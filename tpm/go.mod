module github.com/timelybite/go-fdo/tpm

go 1.23.0

replace github.com/timelybite/go-fdo => ../

require (
	github.com/timelybite/go-fdo v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.9.3
)

require (
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
)
