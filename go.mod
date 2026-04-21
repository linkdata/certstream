module github.com/linkdata/certstream

go 1.25.0

require (
	filippo.io/sunlight v0.8.0
	filippo.io/torchwood v0.9.0
	github.com/google/certificate-transparency-go v1.3.3
	github.com/jackc/pgx/v5 v5.9.2
	github.com/linkdata/bwlimit v1.0.0
	golang.org/x/crypto v0.50.0
	golang.org/x/mod v0.35.0
	golang.org/x/net v0.53.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)
