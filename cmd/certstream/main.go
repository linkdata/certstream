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

	ch, err := certstream.New().Start(ctx, nil)
	if err != nil {
		fmt.Println(err)
	} else {
		for le := range ch {
			fmt.Printf("%q %v\n", le.Domain, le.DNSNames())
		}
	}
}
