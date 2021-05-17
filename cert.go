package cert

import (
	"strconv"

	"github.com/judwhite/cert/internal/openssl"
)

func PrivateKey(bits int) ([]byte, error) {
	// openssl genrsa -out mydomain.com.key 2048

	return openssl.Run(nil, "genrsa", strconv.Itoa(bits))
}

func CSR(privateKey []byte, requesterConfigFileName string) ([]byte, error) {
	// openssl req -new -key mydomain.com.key -out mydomain.com.csr -config certificate.conf

	args := []string{
		"req",
		"-new",
		"-key", "-",
		"-config", requesterConfigFileName,
	}

	return openssl.Run(privateKey, args...)
}

func Verify(rootCertFileName, signedCertFileName string) (string, error) {
	// openssl verify -CAfile rootCA.crt mydomain.com.crt
	args := []string{
		"verify",
		"-CAfile", rootCertFileName,
		signedCertFileName,
	}

	b, err := openssl.Run(nil, args...)
	return string(b), err
}
