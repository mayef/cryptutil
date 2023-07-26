package cryptutil

import (
	"crypto"
	"crypto/x509"

	"github.com/mayef/cms"

	"github.com/pkg/errors"
)

// openssl smime -encrypt -des3 -in xyz.txt -out encrypted_message.as2 -outform DER  -des3 ..\certs\6472fb9fc2b807fcdd2c7a75-cert.pem
func Encrypt(data []byte, cert *x509.Certificate, alg cms.EncryptionAlgorithm) ([]byte, error) {
	cms.ContentEncryptionAlgorithm = alg
	encryptedData, err := cms.Encrypt(data, []*x509.Certificate{cert})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return encryptedData, nil
}

func Decrypt(data []byte, cert *x509.Certificate, pri crypto.PrivateKey) ([]byte, error) {
	p7, err := cms.Parse(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return p7.Decrypt(cert, pri)
}
