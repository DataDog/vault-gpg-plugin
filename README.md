# Vault Plugin: GPG Secret Backend [![Build Status](https://travis-ci.org/LeSuisse/vault-gpg-plugin.svg?branch=master)](https://travis-ci.org/LeSuisse/vault-gpg-plugin) [![Code coverage](https://codecov.io/gh/LeSuisse/vault-gpg-plugin/branch/master/graph/badge.svg)](https://codecov.io/gh/LeSuisse/vault-gpg-plugin)

This is a standalone plugin for [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin handles GPG operations on data-in-transit in a similar fashion to what the
[transit secret backend](https://www.vaultproject.io/docs/secrets/transit/index.html) proposes.
Data sent to the backend are not stored.

As of today, the backend does not support encrypting data.

This backend has similar use cases with the [transit secret backend](https://www.vaultproject.io/docs/secrets/transit/index.html)
and the latter should be preferred if you do not need to interact with existing tools that are only GPG-aware.

## Usage & setup

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html), you need to have a working installation
of Vault to use it.

To learn how to use plugins with Vault, see the [documentation on plugin backends](https://www.vaultproject.io/docs/plugin/index.html)
on the official Vault website. You can download and decompress the pre-compiled plugin binary for your architecture
from the [latest release on GitHub](https://github.com/LeSuisse/vault-gpg-plugin/releases). SHA256 checksum for the
pre-compiled plugin binary is also provided in the archive so it can be registered to your Vault plugin catalog.

All archives available from the [release tab on GitHub](https://github.com/LeSuisse/vault-gpg-plugin/releases) come with
a GPG signature made with the GPG key [`FFCB D29F 3AFE D453 AE4B 9E32 1D40 FBA2 9EB3 9616`](https://sks-keyservers.net/pks/lookup?op=get&search=0xFFCBD29F3AFED453AE4B9E321D40FBA29EB39616).

Once mounted in Vault, this plugin exposes the HTTP API described below.

## HTTP API

It is assumed the GPG backend is mounted at the `/gpg` path in Vault.
Since it is possible to mount secret backends at any location, please update your API calls accordingly.

### Create key

This endpoint creates a new named GPG key.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `POST`   | `/gpg/keys/:name`            | `204 (empty body)`     |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to create. This is specified as part of the URL.

- `generate` `(bool: true)` – Specifies if a key should be generated by Vault or if a key is being passed from another service.

- `real_name` `(string:"")` – Specifies the real name of the identity associated with the GPG key to create. Must not contain any of "()<>\x00". Only used if generate is true.

- `email` `(string:"")` – Specifies the email of the identity associated with the GPG key to create. Must not contain any of "()<>\x00". Only used if generate is true.

- `comment` `(string:"")` – Specifies the comment of the identity associated with the GPG key to create. Must not contain any of "()<>\x00". Only used if generate is true.

- `key` `(string: <required - if generate is false>)` – Specifies the ASCII-armored GPG private key to use. Only used if generate is false.

- `key_bits` `(int: 2048)` – Specifies the number of bits of the generated GPG key to use. Only used if generate is true.

- `exportable` `(bool: false)` – Specifies if the raw key is exportable.

#### Sample Payload

```json
{
  "real_name": "John Doe",
  "email": "john.doe@example.com",
  "key_bits": 4096
}
```

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://vault.example.com/v1/gpg/keys/my-key
```

#### Sample Payload

```json
{
  "key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBFmZe5wBCACx8caRJ+M8mKCrS7FdJ5kTdjApbvsx3ccPwvAQhtT2pIYkU\/ec\n...\naUNPVQgd7AF+MIuana8p6KeAXGS3fpiF4vIM0VoeWfEiO9rzdG0ilm16E61r9A==\n=+776\n-----END PGP PRIVATE KEY BLOCK-----\n"
}
```

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://vault.example.com/v1/gpg/keys/my-imported-key
```

### Read key

This endpoint returns information about a named GPG key.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `GET`    | `/gpg/keys/:name`            | `200 application/json` |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to read. This is specified as part of the URL.

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    https://vault.example.com/v1/gpg/keys/my-key
```

#### Sample response


```json
{
  "data": {
    "exportable": false,
    "fingerprint": "b0b7e7ca0e4ba1a631d15196ef3331150a45bc4d",
    "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsBNBFmZ6QQBCAC5QSHMKe6M9S2G9REo3sJuDPX2lm4ZMULXCvwcVekPYyUFWYI8\n...\nnTruSryJ4xYCydiJ1xkTedrkVxhh7hJKHA==\n=4fdy\n-----END PGP PUBLIC KEY BLOCK-----"
  }
}
```

### List keys

This endpoint returns a list of keys. Only the key names are returned.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `LIST`   | `/gpg/keys`                  | `200 application/json` |

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request LIST \
    https://vault.example.com/v1/gpg/keys
```

#### Sample response

```json
{
  "data": {
    "keys": ["foo", "bar"]
  }
}
```

### Delete key

This endpoint deletes a named GPG key.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `DELETE` | `/gpg/keys/:name`            | `204 (empty body)`     |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to delete. This is specified as part of the URL.

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request DELETE \
    https://vault.example.com/v1/gpg/keys/my-key
```

### Export key

This endpoint returns the named GPG key ASCII-armored.
The key must be exportable to support this operation.


| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `GET`    | `/gpg/export/:name`          | `200 application/json` |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to export. This is specified as part of the URL.

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    https://vault.example.com/v1/gpg/export/my-key
```

#### Sample response

```json
{
  "data": {
    "name": "my-key",
    "key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxcLYBFmZ7JwBCACxsatS8MKxvKpMspkl7ck4vvgZvijBu0sx7Z0+0QDAj8ej5gfK\n...\nYsnjj4QHSRbwJVs/WSIiAj39EyD+bQZDDDFqg62pUA==\n=j7B6\n-----END PGP PRIVATE KEY BLOCK-----"
  }
}
```

### Sign data

This endpoint returns the signature of the given data using the
named GPG key and the specified hash algorithm.

| Method   | Path                           | Produces               |
| :------- | :----------------------------- | :--------------------- |
| `POST`   | `/gpg/sign/:name(/:algorithm)` | `200 application/json` |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to use for signing. This is specified as part of the URL.

- `algorithm` `(string: "sha2-256")` – Specifies the hash algorithm to use. This can also be specified as part of the URL.
  Valid algorithms are:

    - `sha2-224`
    - `sha2-256`
    - `sha2-384`
    - `sha2-512`

- `format` `(string: "base64")` – Specifies the encoding format for the returned signature. Valid encoding format are:

    - `base64`
    - `ascii-armor`

- `input` `(string: <required>)` – Specifies the **base64 encoded** input data.

#### Sample payload

```json
{
  "input": "QWxwYWNhCg=="
}
```

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://vault.example.com/v1/gpg/sign/my-key/sha2-512
```

#### Sample response


```json
{
  "data": {
    "signature": "wsBcBAABCgAQBQJZme+7CRBr/Ej4JtFtLAAA8QcIACLtMWlH5860njpQsJZDIzH3T4mz2397lsd9/hsFDAQXEimuLKWmNdJsTEWXKGx1fvW+r6LEPs8HOLdzOMz2tq6M0WvgzHeWOFdEYmCapUlS68m0GnSFHIAFkq2fMVFHdTTmiLNuZwd+meEPL48hUO8QoGZLhS9IO+xOIisJWP+YIfiZBhmqhz0nVX3CnIzDZWAeJCE9TFGPHjFVNHXKN/IA+pdY4ntU1VOxmKCDqtu6qOrFR3ZghJBrDpDqiMHYmnJZ2AGPDVPKoAorvrLkR7eXNX71yRcutqohqS+xt6nGak2OF7UKwgj5bjk1y44lROFi8aVW4LEX7Jmt+2qwWBg="
  }
}
```

### Verify signed data


This endpoint returns whether the provided signature is valid for the given data.


| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `POST`   | `/gpg/verify/:name`          | `200 application/json` |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to use for signing. This is specified as part of the URL.

- `format` `(string: "base64")` – Specifies the encoding format the signature uses. Valid encoding format are:

    - `base64`
    - `ascii-armor`

- `input` `(string: <required>)` – Specifies the **base64 encoded** input data.

- `signature` `(string: "")` – Specifies the signature output from the
  `/gpg/sign` function.


#### Sample payload

```json
{
  "input": "QWxwYWNhCg==",
  "signature": "wsBcBAABCgAQBQJZme+7CRBr/Ej4JtFtLAAA8QcIACLtMWlH5860njpQsJZDIzH3T4mz2397lsd9/hsFDAQXEimuLKWmNdJsTEWXKGx1fvW+r6LEPs8HOLdzOMz2tq6M0WvgzHeWOFdEYmCapUlS68m0GnSFHIAFkq2fMVFHdTTmiLNuZwd+meEPL48hUO8QoGZLhS9IO+xOIisJWP+YIfiZBhmqhz0nVX3CnIzDZWAeJCE9TFGPHjFVNHXKN/IA+pdY4ntU1VOxmKCDqtu6qOrFR3ZghJBrDpDqiMHYmnJZ2AGPDVPKoAorvrLkR7eXNX71yRcutqohqS+xt6nGak2OF7UKwgj5bjk1y44lROFi8aVW4LEX7Jmt+2qwWBg="
}
```

#### Sample request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://vault.example.com/v1/gpg/verify/my-key
```

#### Sample response

```json
{
  "data": {
    "valid": true
  }
}
```

### Decrypt data

This endpoint decrypts the provided ciphertext using the named GPG key.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `POST`   | `/gpg/decrypt/:name`         | `200 application/json` |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to decrypt against. This is specified as part of the URL.

- `format` `(string: "base64")` – Specifies the encoding format the ciphertext uses. Valid encoding format are:

    - `base64`
    - `ascii-armor`

- `ciphertext` `(string: <required>)` – Specifies the ciphertext to decrypt.

- `signer_key` `(string: "")` – Specifies the GPG key ASCII-armored of the signer. If present, the ciphertext must be signed and the signature valid otherwise the decryption fail.


#### Sample Payload

```json
{
  "format": "ascii-armor",
  "ciphertext": "-----BEGIN PGP MESSAGE-----\n\nhQEMA923ECy\/uCBhAQf8DLagsnoLuM4AyKiTyvZ7uSQTkmOkwXwn1WWsxoKJkzdI\n...\ne8iwFg==\n=+yfj\n-----END PGP MESSAGE-----"
}
```

#### Sample Request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://vault.example.com/v1/gpg/decrypt/my-key
```

#### Sample Response

```json
{
  "data": {
    "plaintext": "QWxwYWNhcwo="
  }
}
```

### Show Session Key

This endpoint decrypts and returns the session key of the provided ciphertext using the named GPG key.

| Method   | Path                         | Produces               |
| :------- | :--------------------------- | :--------------------- |
| `POST`   | `/gpg/show-session-key/:name`| `200 application/json` |

#### Parameters

- `name` `(string: <required>)` – Specifies the name of the key to decrypt against. This is specified as part of the URL.

- `format` `(string: "base64")` – Specifies the encoding format the ciphertext uses. Valid encoding format are:

    - `base64`
    - `ascii-armor`

- `ciphertext` `(string: <required>)` – Specifies the ciphertext to decrypt.

- `signer_key` `(string: "")` – Specifies the GPG key ASCII-armored of the signer. If present, the ciphertext must be signed and the signature valid otherwise the decryption fail.

#### Sample Payload

```json
{
  "format": "ascii-armor",
  "ciphertext": "-----BEGIN PGP MESSAGE-----\n\nhQEMA923ECy\/uCBhAQf8DLagsnoLuM4AyKiTyvZ7uSQTkmOkwXwn1WWsxoKJkzdI\n...\ne8iwFg==\n=+yfj\n-----END PGP MESSAGE-----"
}
```

#### Sample Request

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    https://vault.example.com/v1/gpg/show-session-key/my-key
```

#### Sample Response

```json
{
  "data": {
    "session_key": "9:720D9B92D50D4F7C404C8C412BEB73B47E0A2FA2E822C13201A79D5A2694F9F5"
  }
}
```
