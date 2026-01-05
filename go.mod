module github.com/linkdata/certstream

go 1.24.4

require (
	filippo.io/sunlight v0.6.3
	github.com/google/certificate-transparency-go v1.3.2
	github.com/google/trillian v1.7.2
	github.com/jackc/pgx/v5 v5.8.0
	github.com/linkdata/bwlimit v0.12.1
	golang.org/x/net v0.48.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	filippo.io/torchwood v0.5.1-0.20250713221105-b067ac9d4cf6 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/grpc v1.72.2 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)
