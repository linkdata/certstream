package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/linkdata/certstream"
	"github.com/linkdata/certstream/certdb"
)

func env(key, dflt string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		val = dflt
	}
	return os.ExpandEnv(val)
}

var (
	flagDbUser = flag.String("dbuser", env("DBUSER", "certstream"), "database user")
	flagDbPass = flag.String("dbpass", env("DBPASS", "certstream"), "database password")
	flagDbName = flag.String("dbname", env("DBNAME", "certstream"), "database name")
	flagDbAddr = flag.String("dbaddr", env("DBADDR", ""), "database address")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if *flagDbAddr != "" {
		dsn := fmt.Sprintf("postgres://%s:%s@%s/%s", *flagDbUser, *flagDbPass, *flagDbAddr, *flagDbName)
		db, err := sql.Open("pgx", dsn)
		if err == nil {
			if err = db.Ping(); err == nil {
				var cdb *certdb.Certdb
				if cdb, err = certdb.New(context.Background(), db); err == nil {
					cdb.Close()
				}
			}
			db.Close()
		}
		if err != nil {
			fmt.Println(err)
		}
	}

	ch, err := certstream.New().Start(ctx, nil)
	if err != nil {
		fmt.Println(err)
	} else {
		for le := range ch {
			fmt.Printf("%q %v\n", le.Domain, le.DNSNames())
		}
	}
}
