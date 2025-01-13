package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/linkdata/certstream"
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cs, err := certstream.Start(ctx, certstream.NewConfig())
	if err != nil {
		fmt.Println(err)
	} else {
		for le := range cs.C {
			fmt.Printf("%q %v\n", le.Domain, le.Cert().DNSNames)
		}
	}
}
