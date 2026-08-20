package certutil

import (
	"testing"
	"time"
)

func TestValidatePEMPair_Valid(t *testing.T) {
	certPEM, keyPEM, err := GenerateTestCertificateNow("test.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}
	info, err := ValidatePEMPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if info.CommonName() != "test.example.com" {
		t.Errorf("unexpected common name: %s", info.CommonName())
	}
	if info.DaysRemaining() < 0 {
		t.Errorf("expected positive days remaining")
	}
}

func TestValidatePEMPair_Expired(t *testing.T) {
	certPEM, keyPEM, err := GenerateTestCertificate("expired.example.com", time.Now().Add(-time.Hour*48), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}
	_, err = ValidatePEMPair(certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected error for expired certificate")
	}
}

func TestValidatePEMPair_MismatchedKey(t *testing.T) {
	certPEM, _, err := GenerateTestCertificateNow("a.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}
	_, keyPEM, err := GenerateTestCertificateNow("b.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	_, err = ValidatePEMPair(certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected error for mismatched key")
	}
}

func TestValidatePEMPair_InvalidCert(t *testing.T) {
	_, keyPEM, err := GenerateTestCertificateNow("test.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	_, err = ValidatePEMPair([]byte("not a certificate"), keyPEM)
	if err == nil {
		t.Fatal("expected error for invalid certificate")
	}
}

func TestValidatePEMPair_InvalidKey(t *testing.T) {
	certPEM, _, err := GenerateTestCertificateNow("test.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}
	_, err = ValidatePEMPair(certPEM, []byte("not a key"))
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestFingerprint(t *testing.T) {
	certPEM, keyPEM, err := GenerateTestCertificateNow("fp.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}
	fp1, err := Fingerprint(certPEM)
	if err != nil {
		t.Fatalf("fingerprint failed: %v", err)
	}
	if fp1 == "" {
		t.Fatal("fingerprint should not be empty")
	}
	info, err := ValidatePEMPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if info.Fingerprint != fp1 {
		t.Errorf("fingerprint mismatch: %s vs %s", info.Fingerprint, fp1)
	}
}
