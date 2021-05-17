package ca

import (
	"bytes"
	"os/exec"
	"strconv"
	"time"
)

func days() string {
	y2k38 := time.Date(2038, 1, 19, 0, 0, 0, 0, time.UTC)
	return strconv.Itoa(int(time.Until(y2k38).Hours() / 24))
}

func RootKey() ([]byte, error) {
	// openssl genrsa -out rootCA.key 4096
	cmd := exec.Command("openssl", "genrsa", "4096")
	return cmd.CombinedOutput()
}

func RootCertificate(rootKey []byte) ([]byte, error) {
	// openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt
	cmd := exec.Command("openssl", "req", "-x509", "-new", "-key", "-", "-nodes", "-sha256", "-days", days(), "-config", "ca.conf")
	cmd.Stdin = bytes.NewReader(rootKey)
	return cmd.CombinedOutput()
}

func Sign(rootKeyFileName, rootCertFileName string, csr []byte, configFileName string) ([]byte, error) {
	// openssl x509 -req -in mydomain.com.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out mydomain.com.crt -days 500 -sha256 -extfile certificate.conf -extensions req_ext
	cmd := exec.Command("openssl", "x509", "-req", "-CA", rootCertFileName, "-CAkey", rootKeyFileName, "-CAcreateserial", "-days", days(), "-sha256", "-extfile", configFileName, "-extensions", "req_ext")
	cmd.Stdin = bytes.NewReader(csr)
	return cmd.CombinedOutput()

}
