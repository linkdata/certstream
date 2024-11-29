module github.com/linkdata/certstream

go 1.23

require (
	github.com/google/certificate-transparency-go v1.2.2
	github.com/google/trillian v1.6.1
	github.com/linkdata/bwlimit v0.12.0
	golang.org/x/net v0.31.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	github.com/go-logr/logr v1.4.2 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241118233622-e639e219e697 // indirect
	google.golang.org/grpc v1.68.0 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)
