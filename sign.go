package cryptutil

import (
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"

	"github.com/mayef/cms"
	"github.com/pkg/errors"
)

// 签名
// openssl smime -sign -in xxx.txt -out yyy.txt -signer ..\certs\6472f4086ae0b9ea0e0b94df-cert.pem -inkey ..\certs\6472f4086ae0b9ea0e0b94df-private.pem -outform pem
func Sign(content []byte, cert *x509.Certificate, pri crypto.PrivateKey, algorithm DigestAlgorithm, withoutType ...bool) ([]byte, error) {
	signedData, err := cms.NewSignedData(content)
	if err != nil {
		return nil, errors.Errorf("Cannot initialize signed data: %s", err)
	}
	switch algorithm {
	case SHA256:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHA256)
	case SHA384:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHA384)
	case SHA512:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHA512)
	case SHA224:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHA224)
	case SHA3_256:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHAT256)
	case SHA3_384:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHAT384)
	case SHA3_512:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHAT512)
	case SHA3_224:
		signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmSHAT224)
	// case BLAKE2S_256:
	// 	signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmBlake2s256)
	// case BLAKE2B_256:
	// 	signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmBlake2b256)
	// case BLAKE2B_384:
	// 	signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmBlake2b384)
	// case BLAKE2B_512:
	// 	signedData.SetDigestAlgorithm(cms.OIDDigestAlgorithmBlake2b512)
	default:
		return nil, errors.Errorf("Unsupported algorithm: %s", algorithm)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert, pri, cms.SignerInfoConfig{}); err != nil {
		return nil, errors.Errorf("Cannot add signer: %s", err)
	}

	signedData.Detach()

	signature, err := signedData.Finish()
	if err != nil {
		return nil, errors.Errorf("Cannot finish signing data: %s", err)
	}

	var result []byte
	if len(withoutType) > 0 && withoutType[0] {
		result = signature
	} else {
		result = pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: signature})
	}
	return result, nil
}

// 验证签名
// openssl smime -verify -in test/cms.txt -content test/a.txt -inform PEM -noverify
func Verify(signature []byte, content []byte, signerCert *x509.Certificate) error {
	p, _ := pem.Decode(signature)
	p7, err := cms.Parse(p.Bytes)
	if err != nil {
		return errors.New("Invalid cms signature.")
	}

	// // test if signerCert is a fullchain certificate
	// if len(signerCert.IssuingCertificateURL) > 0 {
	// 	return errors.Errorf("The certificate of signer is not a fullchain certificate.")
	// }

	// 检查证书是否一致（由于使用自签名证书，无法验证证书链，只能对比证书指纹）~~TODO 签名证书可能是单证书，而给出的可能是证书链，需要从证书链中找到签名证书~~
	{
		cert, err := GetCertFromPKCS7Signature(signature)
		if err != nil {
			return errors.WithStack(err)
		}

		certFingerprint := GetFingerprintFromCert(cert)
		signerCertFingerprint := GetFingerprintFromCert(signerCert)
		if subtle.ConstantTimeCompare([]byte(certFingerprint), []byte(signerCertFingerprint)) != 1 {
			return errors.Errorf("Certificate fingerprint mismatch\n\tExpected: %s\n\tActual: %s", signerCertFingerprint, certFingerprint)
		}
	}

	p7.Content = content

	return p7.Verify()
}

// 从PKCS#7签名中提取签名证书
// openssl cms -in test/cms.txt -inform PEM -print_certs
func GetCertFromPKCS7Signature(signature []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(signature)
	p7, err := cms.Parse(p.Bytes)
	if err != nil {
		return nil, errors.New("Invalid cms signature.")
	}
	cert := p7.GetOnlySigner()
	if cert == nil {
		return nil, errors.New("Can not obtain certificate from the signature.")
	}
	return cert, nil
}

// 获取X509证书指纹
func GetFingerprintFromCert(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}
