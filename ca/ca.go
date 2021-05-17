package ca

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/judwhite/cert/internal/openssl"
)

func days() string {
	y2k38 := time.Date(2038, 1, 19, 0, 0, 0, 0, time.UTC)
	return strconv.Itoa(int(time.Until(y2k38).Hours() / 24))
}

func RootCertificate(caPrivateKey []byte, caConfigFileName string) ([]byte, error) {
	// openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt

	args := []string{
		"req",
		"-x509",
		"-new",
		"-nodes", // noDES
		"-sha256",
		"-days", days(),
		"-config", caConfigFileName,
		"-key", "-",
	}

	return openssl.Run(caPrivateKey, args...)
}

func Sign(caPrivateKey, rootCertFileName, caSerialFileName string, csr []byte, extFileName string) ([]byte, error) {
	// openssl x509 -req -in mydomain.com.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out mydomain.com.crt -days 500 -sha256 -extfile certificate.conf -extensions req_ext

	if caSerialFileName == "" {
		caSerialFileName = strings.TrimSuffix(caPrivateKey, filepath.Ext(caPrivateKey)) + ".srl"
	}

	args := []string{
		"x509",
		"-req",
		"-CA", rootCertFileName,
		"-CAkey", caPrivateKey,
		"-CAcreateserial",
		"-CAserial", caSerialFileName,
		"-days", days(),
		"-sha256",
		"-extfile", extFileName,
		"-extensions", "x509_ext",
		"-",
	}

	return openssl.Run(csr, args...)
}
