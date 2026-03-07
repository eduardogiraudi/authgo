package cryptokeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GenKeys(regen bool) error {
	privPath := "private_es512.pem"
	pubPath := "public_es512.pem"

	if _, err := os.Stat(privPath); err == nil && !regen {
		fmt.Println("Crypto keypair already exist. Skipping.")
		return nil
	}

	fmt.Println("Generating ES512 keys...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}

	privBytes, _ := x509.MarshalECPrivateKey(privateKey)
	fPriv, _ := os.Create(privPath)
	defer fPriv.Close()
	pem.Encode(fPriv, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	pubBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	fPub, _ := os.Create(pubPath)
	defer fPub.Close()
	pem.Encode(fPub, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return nil
}