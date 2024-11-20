module github.com/linkdata/certstream

go 1.23.2

require (
	github.com/google/certificate-transparency-go v1.2.1
	github.com/google/trillian v1.6.0
	github.com/linkdata/bwlimit v0.10.0
	golang.org/x/net v0.25.0
)

// replace github.com/linkdata/bwlimit => ../bwlimit

require (
	github.com/go-logr/logr v1.4.1 // indirect
	golang.org/x/crypto v0.27.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240318140521-94a12d6c2237 // indirect
	google.golang.org/grpc v1.64.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)
