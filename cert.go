package cryptutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

type Certificate struct {
	X509       []byte
	PrivateKey []byte
	Public     []byte
}

func NewCertificate(companyIdentifier string, url string, test ...bool) ([]byte, []byte, []byte, error) {

	// 生成一个新的 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}
	publicKey := &privateKey.PublicKey

	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}
	pkixPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}

	// 构造证书模板
	randNum, err := rand.Int(rand.Reader, big.NewInt(4294967295))
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}
	template := x509.Certificate{
		SerialNumber: randNum,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			StreetAddress:      []string{"Shanghai"},
			Locality:           []string{"Shanghai"},
			Organization:       []string{companyIdentifier},
			OrganizationalUnit: []string{companyIdentifier},
			CommonName:         url,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	// 使用证书模板和密钥对生成自签名证书
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}

	certificateBlock := pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes}
	privateKeyBlock := pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8PrivateKey}
	publicKeyBlock := pem.Block{Type: "PUBLIC KEY", Bytes: pkixPublicKey}
	certificatePEM := pem.EncodeToMemory(&certificateBlock)
	privateKeyPEM := pem.EncodeToMemory(&privateKeyBlock)
	publicKeyPEM := pem.EncodeToMemory(&publicKeyBlock)

	if len(test) > 0 && test[0] {
		fmt.Println(string(certificatePEM))
		fmt.Println(string(privateKeyPEM))
		fmt.Println(string(publicKeyPEM))
	}

	return certificatePEM, privateKeyPEM, publicKeyPEM, nil
}

func NewCertObj(companyIdentifier string, url string, test ...bool) ([]byte, *rsa.PrivateKey, *rsa.PublicKey, error) {

	// 生成一个新的 RSA 密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}
	publicKey := &privateKey.PublicKey

	// 构造证书模板
	randNum, err := rand.Int(rand.Reader, big.NewInt(4294967295))
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}
	template := x509.Certificate{
		SerialNumber: randNum,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			StreetAddress:      []string{"Shanghai"},
			Locality:           []string{"Shanghai"},
			Organization:       []string{companyIdentifier},
			OrganizationalUnit: []string{companyIdentifier},
			CommonName:         url,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
	}
	// 使用证书模板和密钥对生成自签名证书
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}
	certificateBlock := pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes}

	return pem.EncodeToMemory(&certificateBlock), privateKey, publicKey, nil
}

func LoadCertificate(certPem []byte) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		return nil, errors.New("Failed to load the x509 certificate.")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return cert, nil
}

func LoadPrivateKey(privatePem []byte) (crypto.PrivateKey, error) {
	privateBlock, _ := pem.Decode(privatePem)
	if privateBlock == nil {
		return nil, errors.New("Failed to load the pkcs8 private key.")
	}
	pkey, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		pkey, err = x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return crypto.PrivateKey(pkey), nil
}
