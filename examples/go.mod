module github.com/timelybite/go-fdo/examples

go 1.23.0

replace github.com/timelybite/go-fdo/sqlite => ../sqlite

replace github.com/timelybite/go-fdo => ..

replace github.com/timelybite/go-fdo/fsim => ../fsim

replace github.com/timelybite/go-fdo/tpm => ../tpm

require (
	github.com/timelybite/go-fdo v0.0.0-00010101000000-000000000000
	github.com/timelybite/go-fdo/fsim v0.0.0-00010101000000-000000000000
	github.com/timelybite/go-fdo/sqlite v0.0.0-00010101000000-000000000000
	github.com/timelybite/go-fdo/tpm v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.9.3
	github.com/google/go-tpm-tools v0.4.5
	github.com/syumai/workers v0.27.0
	hermannm.dev/devlog v0.5.0
)

require (
	github.com/ncruces/go-sqlite3 v0.25.0 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/neilotoole/jsoncolor v0.7.1 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/term v0.31.0 // indirect
)
