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
    # Allow all of the following operations to fail.
    set +e

    # Create master key
    if vault write $MOUNT_POINT/keys/$NAME exportable=true; then
        echo "Created master key!"
        exit 1
    fi

    # Read master key
    if vault read $MOUNT_POINT/keys/$NAME; then
        echo "Read master key!"
        exit 2
    fi

    # List keys
    if vault list $MOUNT_POINT/keys; then
        echo "Listed keys!"
        exit 3
    fi

    # Export master key
    if vault read $MOUNT_POINT/export/$NAME; then
        echo "Exported master key!"
        exit 4
    fi

    # Create a signing subkey
    # https://unix.stackexchange.com/a/73180
    # https://superuser.com/a/1103711
    local keyid;
    keyid=$(vault write -f $MOUNT_POINT/keys/$NAME/subkeys -format=json | jq -rC '.data.key_id')
    if [ $? -eq 0 ]; then
        echo "Created subkey!"
        exit 5
    fi

    # Read the subkey
    if vault read $MOUNT_POINT/keys/$NAME/subkeys/$keyid; then
        echo "Read subkey!"
        exit 6
    fi

    # List subkeys
    if vault list $MOUNT_POINT/keys/$NAME/subkeys; then
        echo "Listed subkeys!"
        exit 7
    fi

    # Disallow failures going forward.
    set -e
}

# Setup vault
go mod vendor
go build -o pkg/vault-gpg-plugin
vault server -dev -dev-root-token-id=root -dev-plugin-dir=pkg &
VAULT_PID=$!

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

# Shutdown vault.
kill -2 $VAULT_PID
