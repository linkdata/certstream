module github.com/linkdata/certstream

go 1.25

require (
	filippo.io/sunlight v0.7.0
	filippo.io/torchwood v0.9.0
	github.com/google/certificate-transparency-go v1.3.2
	github.com/jackc/pgx/v5 v5.8.0
	github.com/linkdata/bwlimit v1.0.0
	golang.org/x/crypto v0.48.0
	golang.org/x/mod v0.33.0
	golang.org/x/net v0.50.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
