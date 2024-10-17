package main

import (
	"context"
	"fmt"
	"time"

	"github.com/linkdata/certstream"
	"k8s.io/klog/v2"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ch, err := certstream.New().Start(ctx, nil)
	if err != nil {
		klog.Fatal(err)
	}
	for le := range ch {
		fmt.Printf("%s %v\n", le, le.DNSNames())
	}
}
