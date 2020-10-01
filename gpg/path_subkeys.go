package gpg

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	pathSubkeysHelpSynopsis    = "Manage subkeys under master keys"
	pathSubkeysHelpDescription = `
This path is used to manage subkeys under existing master keys.
Doing a write with no value against an existing master key will create
by default a new, randomly-generated signing subkey.
`
)

func pathSubkeys(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/subkeys" + framework.OptionalParamRegex("key_id"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the master key with which to associate the new subkey.",
			},
			"key_id": {
				Type:        framework.TypeString,
				Description: "The Key ID of the subkey.",
			},
			"key_type": {
				Type:        framework.TypeLowerCaseString,
				Default:     "rsa",
				Description: "The subkey type.",
			},
			"capabilities": {
				Type:        framework.TypeCommaStringSlice,
				Default:     [...]string{"sign"},
				Description: "The capabilities of the subkey.",
			},
			"key_bits": {
				Type:        framework.TypeInt,
				Default:     4096,
				Description: "The number of bits of the generated subkey.",
			},
			"expires": {
				Type:        framework.TypeInt,
				Default:     365 * 24 * 60 * 60,
				Description: "The number of seconds from the creation time (now) after which the subkey expires. If the number is zero, then the subkey never expires.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathSubkeyDelete,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathSubkeyList,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSubkeyRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSubkeyCreate,
			},
		},
		HelpSynopsis:    pathSubkeysHelpSynopsis,
		HelpDescription: pathSubkeysHelpDescription,
	}
}

func (b *backend) pathSubkeyCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	keyBits := data.Get("key_bits").(int)
	keyType := data.Get("key_type").(string)
	capabilities := data.Get("capabilities").([]string)
	expires := uint32(data.Get("expires").(int))

	if keyBits < 2048 {
		return logical.ErrorResponse("asymmetric subkeys < 2048 bits are unsafe"), nil
	}
	if keyType != "rsa" {
		return logical.ErrorResponse("non-RSA subkeys are not yet supported"), nil
	}
	if !reflect.DeepEqual(capabilities, []string{"sign"}) {
		return logical.ErrorResponse("capabilities other than signing are not yet supported: " + fmt.Sprintf("%v", capabilities)), nil
	}

	prevKeyEntry, err := b.key(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("master key could not be read"), err
	}
	if prevKeyEntry == nil {
		return logical.ErrorResponse("master key does not exist"), nil
	}
	entity, err := b.entity(prevKeyEntry)
	if err != nil {
		return logical.ErrorResponse("master key could not be parsed"), err
	}

	config := packet.Config{
		RSABits: keyBits,
	}
	creationTime := config.Now()

	subkeyPriv, err := rsa.GenerateKey(config.Random(), config.RSABits)
	if err != nil {
		return nil, err
	}

	subkey := openpgp.Subkey{
		PublicKey:  packet.NewRSAPublicKey(creationTime, &subkeyPriv.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(creationTime, subkeyPriv),
		Sig: &packet.Signature{
			CreationTime:    creationTime,
			KeyLifetimeSecs: &expires,
			SigType:         packet.SigTypeSubkeyBinding,
			PubKeyAlgo:      packet.PubKeyAlgoRSA,
			Hash:            config.Hash(),
			FlagsValid:      true,
			FlagSign:        true,
			IssuerKeyId:     &entity.PrimaryKey.KeyId,
		},
	}
	subkey.PublicKey.IsSubkey = true
	subkey.PrivateKey.IsSubkey = true
	subkey.Sig.EmbeddedSignature = &packet.Signature{
		CreationTime:    creationTime,
		KeyLifetimeSecs: &expires,
		SigType:         packet.SigTypePrimaryKeyBinding,
		PubKeyAlgo:      packet.PubKeyAlgoRSA,
		Hash:            config.Hash(),
		IssuerKeyId:     &entity.PrimaryKey.KeyId,
	}
	err = subkey.Sig.EmbeddedSignature.SignMasterKey(entity.PrimaryKey, subkey.PrivateKey, &config)
	if err != nil {
		return nil, err
	}
	err = subkey.Sig.SignSubKey(subkey.PublicKey, entity.PrivateKey, &config)
	if err != nil {
		return nil, err
	}
	entity.Subkeys = append(entity.Subkeys, subkey)

	var buf bytes.Buffer
	err = entity.SerializePrivate(&buf, nil)
	if err != nil {
		return nil, err
	}
	currStorageEntry, err := logical.StorageEntryJSON("key/"+name, &keyEntry{
		SerializedKey: buf.Bytes(),
		Exportable:    prevKeyEntry.Exportable,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, currStorageEntry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"key_id": hex.EncodeToString(subkey.PublicKey.Fingerprint[:]),
		},
	}, nil
}

func (b *backend) pathSubkeyDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse("not implemented"), nil
}

func (b *backend) pathSubkeyList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse("not implemented"), nil
}

func (b *backend) pathSubkeyRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse("not implemented"), nil
}
