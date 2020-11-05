#!/bin/bash

set -xeuo pipefail

go mod vendor
go build -o pkg/vault-gpg-plugin
vault server -dev -dev-root-token-id=root -dev-plugin-dir=pkg/

