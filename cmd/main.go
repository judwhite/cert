package main

import (
	"flag"
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

func main() {
	var mysql bool

	flag.BoolVar(&mysql, "mysql", false, "Output config suitable for MySQL my.cnf")
	flag.Parse()

	SetupCA("config/ca.conf")
	CreatePrivateKeyAndCert("config/client.conf")
	CreatePrivateKeyAndCert("config/server.conf")

	if err := LiveTest(); err != nil {
		log.Fatal(err)
	}

	if mysql {
		fmt.Println()
		fmt.Printf("[mysqld]\n")
		fmt.Printf("default_time_zone=\"+00:00\"\n")
		fmt.Printf("require_secure_transport=ON\n")
		fmt.Printf("tls_version=TLSv1.3\n")
		fmt.Printf("default_authentication_plugin=caching_sha2_password\n")
		fmt.Printf("ssl-ca=ca.crt\n")
		fmt.Printf("ssl-cert=server.crt\n")
		fmt.Printf("ssl-key=server.key\n")
		fmt.Println()
		fmt.Printf("connection string: <LOGIN>@tcp(<SERVER>:3306)/<DATABASE>?tls=custom&parseTime=true&serverPubKey=%s\n", "MySQL")
	}
}

func SetupCA(caConfigFileName string) {
	rootKey, err := cert.PrivateKey(4096)
	if err != nil {
		log.Fatalf("\n%s\n%v", rootKey, err)
	}

	rootCert, err := ca.RootCertificate(rootKey, caConfigFileName)
	if err != nil {
		log.Fatalf("\n%s\n%v", rootCert, err)
	}

	// Save CA root key and certificate

	if err := ioutil.WriteFile(caKeyFile, rootKey, 0600); err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile(caCertFile, rootCert, 0644); err != nil {
		log.Fatal(err)
	}

	fmt.Println()
}

func CreatePrivateKeyAndCert(configFileName string) {
	// Create private key and certificate signing request

	privateKey, err := cert.PrivateKey(2048)
	if err != nil {
		log.Fatalf("\n%s\n%v", privateKey, err)
	}

	csr, err := cert.CSR(privateKey, configFileName)
	if err != nil {
		log.Fatalf("\n%s\n%v", csr, err)
	}

	// Sign the cert

	signedCert, err := ca.Sign(caKeyFile, caCertFile, "", csr, configFileName)
	if err != nil {
		log.Fatalf("\n%s\n%v", signedCert, err)
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

	// Verify

	output, err := cert.Verify(caCertFile, signedCertFile)
	if err != nil {
		log.Fatalf("\n%s\n%v", output, err)
	}
	fmt.Print(output)

	fmt.Println()
}
