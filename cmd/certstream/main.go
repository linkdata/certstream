package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/linkdata/certstream"
	"k8s.io/klog/v2"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cs := certstream.New()
	logList, err := certstream.GetLogList(ctx, nil, loglist3.AllLogListURL)
	if err == nil {
		ch, err := cs.Start(ctx, logList)
		if err != nil {
			klog.Error(err)
		}
		for le := range ch {
			fmt.Printf("%s %v\n", le, le.DNSNames())
		}
		return
	}
	klog.Fatal(err)
}
