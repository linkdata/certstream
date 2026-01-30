module github.com/linkdata/certstream

go 1.24.3

require (
	github.com/google/certificate-transparency-go v1.3.2
	github.com/jackc/pgx/v5 v5.8.0
	github.com/linkdata/bwlimit v0.12.1
	github.com/transparency-dev/formats v0.0.0-20251017110053-404c0d5b696c
	github.com/transparency-dev/merkle v0.0.2
	github.com/transparency-dev/tessera v1.0.1
	golang.org/x/crypto v0.47.0
	golang.org/x/mod v0.32.0
	golang.org/x/net v0.49.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
