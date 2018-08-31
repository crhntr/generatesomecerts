package generatesomecerts

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

func CACert(hosts ...string) (private, public *pem.Block) {
	caPriv, err := rsa.GenerateKey(rand.Reader, 512)

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 10000) // nearly 30 years

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	caTemplate := x509.Certificate{
		IsCA:         true,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	caTemplate.KeyUsage |= x509.KeyUsageCertSign

	ca, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	return &pem.Block{Type: "CERTIFICATE", Bytes: caCert}, 

}

func SignedCert(ca []byte, hosts ...string) (private, public *pem.Block) {
	template := x509.Certificate{
		IsCA:         false,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	priv, err := rsa.GenerateKey(rand.Reader, 512)
	cert, err := x509.CreateCertificate(rand.Reader, &template, &caTemplate, priv.Public(), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	//	return ca, certs
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}
