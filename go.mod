module github.com/linkdata/certstream

go 1.23

require (
	github.com/google/certificate-transparency-go v1.2.2
	github.com/google/trillian v1.6.1
	github.com/jackc/pgx/v5 v5.7.2
	golang.org/x/net v0.31.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/grpc v1.68.0 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)
