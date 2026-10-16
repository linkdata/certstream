module github.com/linkdata/certstream

go 1.27.0

require (
	filippo.io/sunlight v0.10.0
	filippo.io/torchwood v0.10.0
	github.com/google/certificate-transparency-go v1.3.3
	github.com/jackc/pgx/v5 v5.11.0
	github.com/linkdata/bwlimit v1.0.1
	golang.org/x/crypto v0.58.0
	golang.org/x/mod v0.42.0
	golang.org/x/net v0.61.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
)
