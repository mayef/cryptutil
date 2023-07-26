package cryptutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCertificate(t *testing.T) {
	// read fullchain.cer in current directory
	dir, err := filepath.Abs(filepath.Dir("."))
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(filepath.Join(dir, "fullchain.cer"))
	if err != nil {
		t.Fatal(err)
	}

	// load certificate
	cert, err := LoadCertificate(bytes)
	if err != nil {
		t.Fatal(err)
	}

	// check certificate
	if cert.Subject.CommonName != "zzz.zzz" {
		t.Fatal("invalid certificate")
	}

	// check public key
	if cert.PublicKey == nil {
		t.Fatal("invalid private key")
	}

	figerprint := GetFingerprintFromCert(cert)
	t.Log("figerprint:", figerprint)

}
