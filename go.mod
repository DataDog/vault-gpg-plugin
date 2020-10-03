module github.com/trishankatdatadog/vault-gpg-plugin

go 1.15

require (
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/securego/gosec v0.0.0-20200401082031-e946c8c39989
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	honnef.co/go/tools v0.0.0-20190523083050-ea95bdfd59fc
)

replace golang.org/x/crypto => github.com/trishankatdatadog/crypto v0.0.0-20201003032211-b00c698fd90d
