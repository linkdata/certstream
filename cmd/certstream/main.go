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
	logList, err := certstream.GetLogList(ctx, cs, loglist3.AllLogListURL)
	if err == nil {
		if ch, err := cs.Start(ctx, logList); err == nil {
			for b := range ch {
				for _, l := range b.Logs {
					fmt.Printf("%v\n", l.Body.Cert.Domains)
				}
			}
			return
		}
	}
	klog.Fatal(err)
}
