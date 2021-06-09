module github.com/DataDog/vault-gpg-plugin

go 1.15

require (
	github.com/hashicorp/vault/api v1.0.5-0.20200519221902-385fac77e20f
	github.com/hashicorp/vault/sdk v0.2.0
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/securego/gosec v0.0.0-20200401082031-e946c8c39989
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	honnef.co/go/tools v0.0.0-20190523083050-ea95bdfd59fc
)

replace golang.org/x/crypto => github.com/DataDog/crypto v0.0.0-20201112115411-41db4ea0dd1c
