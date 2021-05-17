package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/judwhite/cert"
	"github.com/judwhite/cert/ca"
)

const caKeyFile = "ca.key"
const caCertFile = "ca.crt"

func SetupCA() {
	rootKey, err := ca.RootKey()
	if err != nil {
		fmt.Printf("%s\n", rootKey)
		log.Fatalf("ca.RootKey: %v", err)
	}

	rootCert, err := ca.RootCertificate(rootKey)
	if err != nil {
		fmt.Printf("%s\n", rootCert)
		log.Fatalf("ca.RootCertificate: %v", err)
	}

	// Save CA root key and certificate

	if err := ioutil.WriteFile(caKeyFile, rootKey, 0600); err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile(caCertFile, rootCert, 0644); err != nil {
		log.Fatal(err)
	}
}

func CreatePrivateKeyAndCert(configFileName string) {
	// Create private key and certificate signing request

	privateKey, err := cert.PrivateKey()
	if err != nil {
		fmt.Printf("%s\n", privateKey)
		log.Fatalf("cert.PrivateKey: %v", err)
	}

	csr, err := cert.CSR(privateKey, configFileName)
	if err != nil {
		fmt.Printf("%s\n", csr)
		log.Fatalf("cert.CSR: %v", err)
	}

	// Sign the cert

	signedCert, err := ca.Sign(caKeyFile, caCertFile, csr, "client.conf")
	if err != nil {
		fmt.Printf("%s\n", signedCert)
		log.Fatalf("ca.Sign: %v", err)
	}

	// Save private key signed cert

	baseFileName := filepath.Base(configFileName)
	baseFileName = strings.TrimSuffix(baseFileName, filepath.Ext(baseFileName))

	privateKeyFile := baseFileName + ".key"
	if err := ioutil.WriteFile(privateKeyFile, privateKey, 0600); err != nil {
		log.Fatal(err)
	}

	signedCertFile := baseFileName + ".crt"
	if err := ioutil.WriteFile(signedCertFile, signedCert, 0644); err != nil {
		log.Fatal(err)
	}

	// Verify!

	output, err := cert.Verify(caCertFile, signedCertFile)
	fmt.Print(output)
	if err != nil {
		log.Fatalf("cert.Verify: %v", err)
	}
}

func main() {
	SetupCA()
	CreatePrivateKeyAndCert("client.conf")
	CreatePrivateKeyAndCert("server.conf")
}
