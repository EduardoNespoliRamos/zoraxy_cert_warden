package certutil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

type generatedChain struct {
	certPEM []byte
	keyPEM  []byte
	certs   []*x509.Certificate
	leafKey *rsa.PrivateKey
}

func generateChain(t *testing.T, mutate func(leaf, intermediate, root *x509.Certificate)) generatedChain {
	t.Helper()
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(72 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	intermediate := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(102),
		Subject:               pkix.Name{CommonName: "server.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"server.example.com"},
	}
	if mutate != nil {
		mutate(leaf, intermediate, root)
	}

	rootKey := generateRSAKey(t)
	intermediateKey := generateRSAKey(t)
	leafKey := generateRSAKey(t)
	rootDER := createCertificate(t, root, root, &rootKey.PublicKey, rootKey)
	intermediateDER := createCertificate(t, intermediate, root, &intermediateKey.PublicKey, rootKey)
	leafDER := createCertificate(t, leaf, intermediate, &leafKey.PublicKey, intermediateKey)

	certs := []*x509.Certificate{
		parseCertificate(t, leafDER),
		parseCertificate(t, intermediateDER),
		parseCertificate(t, rootDER),
	}
	var certPEM []byte
	for _, der := range [][]byte{leafDER, intermediateDER, rootDER} {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	return generatedChain{
		certPEM: certPEM,
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		certs:   certs,
		leafKey: leafKey,
	}
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, publicKey any, signer *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatalf("create certificate %q: %v", template.Subject.CommonName, err)
	}
	return der
}

func parseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	return cert
}

func TestValidatePEMPair_StrictCertificateBundle(t *testing.T) {
	chain := generateChain(t, nil)
	tests := []struct {
		name    string
		certPEM []byte
		wantErr string
	}{
		{name: "trailing garbage", certPEM: append(append([]byte(nil), chain.certPEM...), []byte("garbage")...), wantErr: "unexpected non-PEM data"},
		{name: "leading garbage", certPEM: append([]byte("garbage\n"), chain.certPEM...), wantErr: "unexpected non-PEM data"},
		{name: "non-certificate block", certPEM: append(append([]byte(nil), chain.certPEM...), pem.EncodeToMemory(&pem.Block{Type: "COMMENT", Bytes: []byte("x")})...), wantErr: `unexpected PEM block "COMMENT"`},
		{name: "malformed trailing PEM", certPEM: append(append([]byte(nil), chain.certPEM...), []byte("-----BEGIN CERTIFICATE-----\nbroken\n")...), wantErr: "malformed PEM data"},
		{name: "invalid trailing certificate", certPEM: append(append([]byte(nil), chain.certPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})...), wantErr: "certificate 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePEMPair(tt.certPEM, chain.keyPEM)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePEMPair_CertificatePolicies(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(leaf, intermediate, root *x509.Certificate)
		wantErr string
	}{
		{name: "expired intermediate", mutate: func(_, intermediate, _ *x509.Certificate) { intermediate.NotAfter = time.Now().Add(-time.Minute) }, wantErr: "certificate 1 has expired"},
		{name: "future root", mutate: func(_, _, root *x509.Certificate) { root.NotBefore = time.Now().Add(time.Hour) }, wantErr: "certificate 2 is not yet valid"},
		{name: "leaf is CA", mutate: func(leaf, _, _ *x509.Certificate) { leaf.IsCA = true; leaf.KeyUsage |= x509.KeyUsageCertSign }, wantErr: "leaf certificate must not be a CA"},
		{name: "client EKU only", mutate: func(leaf, _, _ *x509.Certificate) { leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, wantErr: "does not permit server authentication"},
		{name: "intermediate is not CA", mutate: func(_, intermediate, _ *x509.Certificate) {
			intermediate.IsCA = false
			intermediate.KeyUsage = x509.KeyUsageDigitalSignature
			intermediate.MaxPathLen = -1
			intermediate.MaxPathLenZero = false
		}, wantErr: "is not validly signed"},
		{name: "root path length exceeded", mutate: func(_, _, root *x509.Certificate) { root.MaxPathLen = 0; root.MaxPathLenZero = true }, wantErr: "path length constraint exceeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := generateChain(t, tt.mutate)
			_, err := ValidatePEMPair(chain.certPEM, chain.keyPEM)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePEMPair_ServerUsageAccepted(t *testing.T) {
	tests := []struct {
		name string
		eku  []x509.ExtKeyUsage
	}{
		{name: "server auth", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "any", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{name: "EKU absent", eku: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := generateChain(t, func(leaf, _, _ *x509.Certificate) { leaf.ExtKeyUsage = tt.eku })
			if _, err := ValidatePEMPair(chain.certPEM, chain.keyPEM); err != nil {
				t.Fatalf("validation failed: %v", err)
			}
		})
	}
}

func TestValidatePEMPair_AcceptsPartialPresentedChain(t *testing.T) {
	chain := generateChain(t, nil)
	partial := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.certs[0].Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.certs[1].Raw}),
	}, nil)
	if _, err := ValidatePEMPair(partial, chain.keyPEM); err != nil {
		t.Fatalf("validation required a root or public trust: %v", err)
	}
}

func TestValidatePEMPair_RejectsIncoherentOrder(t *testing.T) {
	chain := generateChain(t, nil)
	blocks := make([][]byte, len(chain.certs))
	for i, cert := range chain.certs {
		blocks[i] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	badOrder := bytes.Join([][]byte{blocks[0], blocks[2], blocks[1]}, nil)
	_, err := ValidatePEMPair(badOrder, chain.keyPEM)
	if err == nil || !strings.Contains(err.Error(), "issuer does not match") {
		t.Fatalf("error = %v, want issuer order error", err)
	}
}

func TestValidatePEMPair_RejectsInvalidPresentedSignature(t *testing.T) {
	chain := generateChain(t, nil)
	unrelated := generateChain(t, nil)
	certPEM := bytes.Join([][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.certs[0].Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unrelated.certs[1].Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unrelated.certs[2].Raw}),
	}, nil)
	_, err := ValidatePEMPair(certPEM, chain.keyPEM)
	if err == nil || !strings.Contains(err.Error(), "is not validly signed") {
		t.Fatalf("error = %v, want signature error", err)
	}
}

func TestValidatePEMPair_EncryptedPrivateKeyMessage(t *testing.T) {
	chain := generateChain(t, nil)
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("not relevant")})
	_, err := ValidatePEMPair(chain.certPEM, encrypted)
	if err == nil || !strings.Contains(err.Error(), "encrypted private keys are not supported") {
		t.Fatalf("error = %v, want clear encrypted key error", err)
	}
}

func TestCertInfoFingerprintsAndBundleDigest(t *testing.T) {
	chain := generateChain(t, nil)
	info, err := ValidatePEMPair(chain.certPEM, chain.keyPEM)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if info.LeafFingerprint == "" || info.LeafFingerprint != info.Fingerprint {
		t.Fatalf("leaf fingerprints differ: explicit=%q compatibility=%q", info.LeafFingerprint, info.Fingerprint)
	}
	if info.BundleDigest == "" || info.BundleDigest == info.LeafFingerprint {
		t.Fatalf("unexpected bundle digest %q", info.BundleDigest)
	}

	pkcs1Key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(chain.leafKey)})
	withOtherEncoding, err := ValidatePEMPair(chain.certPEM, pkcs1Key)
	if err != nil {
		t.Fatalf("validation with PKCS#1 key failed: %v", err)
	}
	if withOtherEncoding.BundleDigest != info.BundleDigest {
		t.Fatal("bundle digest depends on private key encoding")
	}

	same, err := bundleDigest(chain.certs, &chain.leafKey.PublicKey)
	if err != nil || same != info.BundleDigest {
		t.Fatalf("deterministic digest = %q, %v; want %q", same, err, info.BundleDigest)
	}
	fewerCerts, err := bundleDigest(chain.certs[:2], &chain.leafKey.PublicKey)
	if err != nil || fewerCerts == info.BundleDigest {
		t.Fatal("bundle digest does not account for every certificate")
	}
	reversed, err := bundleDigest([]*x509.Certificate{chain.certs[1], chain.certs[0], chain.certs[2]}, &chain.leafKey.PublicKey)
	if err != nil || reversed == info.BundleDigest {
		t.Fatal("bundle digest does not account for certificate order")
	}
	otherKey := generateRSAKey(t)
	otherIdentity, err := bundleDigest(chain.certs, &otherKey.PublicKey)
	if err != nil || otherIdentity == info.BundleDigest {
		t.Fatal("bundle digest does not account for the corresponding public-key identity")
	}
}
