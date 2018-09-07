package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/crhntr/generatesomecerts"
)

func main() {
	flag.Parse()

	ca, err := generatesomecerts.CA()
	if err != nil {
		println(err)
		return
	}
	fmt.Printf("\n----> ca-cert\n\n%s\n", ca)

	for _, hosts := range flag.Args() {
		hs := strings.Split(hosts, ",")
		cert, err := ca.SignedCert(hs...)
		if err != nil {
			println(err)
			return
		}
		fmt.Printf("\n----> signed-cert\n      %v\n\n%s\n", hs, cert)
	}
}
