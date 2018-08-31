package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/crhntr/generatesomecerts"
)

func main() {
	flag.Parse()

	caCert, signedCerts := generatesomecerts.Certs(flag.Args()...)

	fmt.Println("ca-cert:")
	pem.Encode(os.Stdout)
	for i, cert := range signedCerts {
		fmt.Printf("\n\ncert signed for %q:\n", flag.Args()[i])
		pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}
}
