package cert

import (
	"bytes"
	"os/exec"
)

func PrivateKey() ([]byte, error) {
	// openssl genrsa -out mydomain.com.key 2048
	cmd := exec.Command("openssl", "genrsa", "-out", "-", "2048")
	return cmd.CombinedOutput()
}

func CSR(privateKey []byte, configFileName string) ([]byte, error) {
	// openssl req -new -key mydomain.com.key -out mydomain.com.csr -config certificate.conf
	cmd := exec.Command("openssl", "req", "-new", "-key", "-", "-out", "-", "-config", configFileName)
	cmd.Stdin = bytes.NewReader(privateKey)
	return cmd.CombinedOutput()
}

func PublicKey(privateKey []byte) ([]byte, error) {
	// openssl rsa -in private.pem -outform PEM -pubout -out public.pem
	cmd := exec.Command("openssl", "rsa", "-in", "-", "-outform", "PEM", "-pubout", "-out", "-")
	cmd.Stdin = bytes.NewReader(privateKey)
	return cmd.CombinedOutput()
}

func Verify(rootCertFileName, signedCertFileName string) (string, error) {
	// openssl verify -CAfile rootCA.crt mydomain.com.crt
	cmd := exec.Command("openssl", "verify", "-CAfile", rootCertFileName, signedCertFileName)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
