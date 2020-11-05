#!/bin/bash

set -xeuo pipefail

# Environment variables
export VAULT_ADDR='http://127.0.0.1:8200'

# Variables
NAME=master1
MOUNT_POINT=vault-gpg-plugin
INPUT=$(echo 'secret santa' | base64 -)

# Functions
function sign_and_verify {
    # Sign data w/ master key
    SIG=$(vault write -format=json $MOUNT_POINT/sign/$NAME input=$INPUT | jq -rC '.data.signature')
    # Verify signed data w/ master key
    vault write $MOUNT_POINT/verify/$NAME input=$INPUT signature=$SIG
}

function with_root {
    # Create master key
    vault write $MOUNT_POINT/keys/$NAME exportable=true
    # Read master key
    vault read $MOUNT_POINT/keys/$NAME
    # List keys
    vault list $MOUNT_POINT/keys
    # Export master key
    vault read $MOUNT_POINT/export/$NAME
    # Sign and verify data w/ master key
    sign_and_verify

    # Create a signing subkey
    KEYID=$(vault write -f $MOUNT_POINT/keys/$NAME/subkeys -format=json | jq -rC '.data.key_id')
    # Read the subkey
    vault read $MOUNT_POINT/keys/$NAME/subkeys/$KEYID
    # List subkeys
    vault list $MOUNT_POINT/keys/$NAME/subkeys
    # Sign and verify data w/ the subkey
    sign_and_verify
}

function without_root {
    # Allow the following operations to fail.
    set +e

    # Create master key
    vault write $MOUNT_POINT/keys/$NAME exportable=true
    # Read master key
    vault read $MOUNT_POINT/keys/$NAME
    # List keys
    vault list $MOUNT_POINT/keys
    # Export master key
    vault read $MOUNT_POINT/export/$NAME

    # Create a signing subkey
    local keyid=$(vault write -f $MOUNT_POINT/keys/$NAME/subkeys -format=json | jq -rC '.data.key_id')
    # Read the subkey
    vault read $MOUNT_POINT/keys/$NAME/subkeys/$keyid
    # List subkeys
    vault list $MOUNT_POINT/keys/$NAME/subkeys

    # Disallow failures going forward.
    set -e
}

# Login as root and see if we can do everything
vault login root
vault secrets disable $MOUNT_POINT
vault secrets enable $MOUNT_POINT
with_root

# Login as a reader and see what we can do
vault policy write reader scripts/reader.hcl
TOKEN=$(vault token create -policy=reader -field token)
vault login $TOKEN
sign_and_verify
without_root

# Login as root and see if we can delete
vault login root
# Delete subkey
vault delete $MOUNT_POINT/keys/$NAME/subkeys/$KEYID
# Delete master key
vault delete $MOUNT_POINT/keys/$NAME
