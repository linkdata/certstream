package main

import (
	"context"
	"fmt"
	"time"

	"github.com/linkdata/certstream"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ch, err := certstream.New().Start(ctx, nil)
	if err != nil {
		fmt.Println(err)
	} else {
		for le := range ch {
			fmt.Printf("%q %v\n", le.OperatorDomain, le.DNSNames())
		}
	}
}
