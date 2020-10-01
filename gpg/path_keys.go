package gpg

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/hashicorp/vault/sdk/helper/locksutil"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func pathListKeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathKeyList,
			},
		},
		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func pathKeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key.",
			},
			"real_name": {
				Type:        framework.TypeString,
				Description: "The real name of the identity associated with the generated GPG key. Must not contain any of \"()<>\x00\". Only used if generate is false.",
			},
			"email": {
				Type:        framework.TypeString,
				Description: "The email of the identity associated with the generated GPG key. Must not contain any of \"()<>\x00\". Only used if generate is false.",
			},
			"comment": {
				Type:        framework.TypeString,
				Description: "The comment of the identity associated with the generated GPG key. Must not contain any of \"()<>\x00\". Only used if generate is false.",
			},
			"key_bits": {
				Type:        framework.TypeInt,
				Default:     2048,
				Description: "The number of bits to use. Only used if generate is true.",
			},
			"key": {
				Type:        framework.TypeString,
				Description: "The ASCII-armored GPG key to use. Only used if generate is false.",
			},
			"exportable": {
				Type:        framework.TypeBool,
				Description: "Enables the key to be exportable.",
			},
			"generate": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Determines if a key should be generated by Vault or if a key is being passed from another service.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeyRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKeyCreate,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathKeyDelete,
			},
		},
		HelpSynopsis:    pathPolicyHelpSyn,
		HelpDescription: pathPolicyHelpDesc,
	}
}

func (b *backend) key(ctx context.Context, s logical.Storage, name string) (*keyEntry, error) {
	entry, err := s.Get(ctx, "key/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result keyEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) entity(entry *keyEntry) (*openpgp.Entity, error) {
	r := bytes.NewReader(entry.SerializedKey)
	el, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	return el[0], nil
}

func serializePrivateWithoutSigning(w io.Writer, e *openpgp.Entity) (err error) {
	foundPrivateKey := false

	if e.PrivateKey != nil {
		foundPrivateKey = true
		err = e.PrivateKey.Serialize(w)
		if err != nil {
			return
		}
	}
	for _, ident := range e.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return
		}
		err = ident.SelfSignature.Serialize(w)
		if err != nil {
			return
		}
	}
	for _, subkey := range e.Subkeys {
		if subkey.PrivateKey != nil {
			foundPrivateKey = true
			err = subkey.PrivateKey.Serialize(w)
			if err != nil {
				return
			}
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return
		}
	}

	if !foundPrivateKey {
		return fmt.Errorf("no private key has been found")
	}

	return nil
}

func (b *backend) readKey(ctx context.Context, storage logical.Storage, name string) (entity *openpgp.Entity, exportable bool, err error) {
	entry, err := b.key(ctx, storage, name)
	if err != nil {
		return
	}
	if entry == nil {
		return
	}
	exportable = entry.Exportable
	entity, err = b.entity(entry)
	if err != nil {
		return
	}
	return
}

func (b *backend) pathKeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entity, exportable, err := b.readKey(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("master key does not exist"), nil
	}

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	err = entity.Serialize(w)
	if err != nil || w.Close() != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"fingerprint": hex.EncodeToString(entity.PrimaryKey.Fingerprint[:]),
			"public_key":  buf.String(),
			"exportable":  exportable,
		},
	}, nil
}

func (b *backend) pathKeyCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	realName := data.Get("real_name").(string)
	email := data.Get("email").(string)
	comment := data.Get("comment").(string)
	keyBits := data.Get("key_bits").(int)
	exportable := data.Get("exportable").(bool)
	generate := data.Get("generate").(bool)
	key := data.Get("key").(string)

	lock := locksutil.LockForKey(b.keyLocks, name)
	lock.Lock()
	defer lock.Unlock()

	resp, err := b.pathKeyRead(ctx, req, data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if resp != nil {
		return logical.ErrorResponse("key already exists"), nil
	}

	var buf bytes.Buffer
	switch generate {
	case true:
		if keyBits < 2048 {
			return logical.ErrorResponse("Keys < 2048 bits are unsafe and not supported"), nil
		}
		config := packet.Config{
			RSABits: keyBits,
		}
		entity, err := openpgp.NewEntity(realName, comment, email, &config)
		if err != nil {
			return nil, err
		}
		err = entity.SerializePrivate(&buf, nil)
		if err != nil {
			return nil, err
		}
	default:
		if key == "" {
			return logical.ErrorResponse("the key value is required for generated keys"), nil
		}
		el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(key))
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		err = serializePrivateWithoutSigning(&buf, el[0])
		if err != nil {
			return logical.ErrorResponse("the key could not be serialized, is a private key present?"), nil
		}
	}

	entry, err := logical.StorageEntryJSON("key/"+name, &keyEntry{
		SerializedKey: buf.Bytes(),
		Exportable:    exportable,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathKeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	lock := locksutil.LockForKey(b.keyLocks, name)
	lock.Lock()
	defer lock.Unlock()

	err := req.Storage.Delete(ctx, "key/"+name)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathKeyList(
	ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "key/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

type keyEntry struct {
	SerializedKey []byte
	Exportable    bool
}

const pathPolicyHelpSyn = "Managed named GPG keys"
const pathPolicyHelpDesc = `
This path is used to manage the named GPG keys that are available.
Doing a write with no value against a new named key will create
it using a randomly generated key.
`
