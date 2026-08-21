package certutil

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
	"time"
)

// CertInfo holds parsed certificate data.
type CertInfo struct {
	Certificate     *x509.Certificate
	Chain           []*x509.Certificate
	Fingerprint     string
	LeafFingerprint string
	BundleDigest    string
}

// LoadAndValidate reads source certificate and key files and validates them.
func LoadAndValidate(certPath, keyPath string) (*CertInfo, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	return ValidatePEMPair(certPEM, keyPEM)
}

// ValidatePEMPair validates a certificate/key PEM pair.
func ValidatePEMPair(certPEM, keyPEM []byte) (*CertInfo, error) {
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("certificate PEM is empty")
	}
	if len(keyPEM) == 0 {
		return nil, fmt.Errorf("private key PEM is empty")
	}

	if containsEncryptedPrivateKey(keyPEM) {
		return nil, fmt.Errorf("encrypted private keys are not supported (ENCRYPTED PRIVATE KEY)")
	}

	// Keep the standard library's key parsing and public/private match check.
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate and private key do not match: %w", err)
	}

	chain, err := parseCertificateChain(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM")
	}

	now := time.Now()
	for i, cert := range chain {
		if now.Before(cert.NotBefore) {
			return nil, fmt.Errorf("certificate %d is not yet valid", i)
		}
		if now.After(cert.NotAfter) {
			return nil, fmt.Errorf("certificate %d has expired", i)
		}
	}

	leaf := chain[0]
	if leaf.IsCA {
		return nil, fmt.Errorf("leaf certificate must not be a CA")
	}
	if !allowsServerUse(leaf) {
		return nil, fmt.Errorf("leaf certificate extended key usage does not permit server authentication")
	}
	if err := validatePresentedChain(chain); err != nil {
		return nil, err
	}

	if _, err := parsePrivateKey(keyPEM); err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	fp := fingerprintDER(leaf.Raw)
	publicKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not expose a public key")
	}
	digest, err := bundleDigest(chain, publicKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to calculate bundle digest: %w", err)
	}

	return &CertInfo{
		Certificate:     leaf,
		Chain:           chain,
		Fingerprint:     fp,
		LeafFingerprint: fp,
		BundleDigest:    digest,
	}, nil
}

func parseCertificateChain(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for len(bytes.TrimSpace(rest)) > 0 {
		begin := bytes.Index(rest, []byte("-----BEGIN "))
		if begin < 0 || len(bytes.TrimSpace(rest[:begin])) != 0 {
			return nil, fmt.Errorf("unexpected non-PEM data in certificate bundle")
		}
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("malformed PEM data in certificate bundle")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q in certificate bundle", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(certs), err)
		}
		certs = append(certs, cert)
		rest = remaining
	}
	return certs, nil
}

func containsEncryptedPrivateKey(pemData []byte) bool {
	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			return true
		}
		rest = remaining
	}
}

func allowsServerUse(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func validatePresentedChain(chain []*x509.Certificate) error {
	for i := 0; i+1 < len(chain); i++ {
		child, issuer := chain[i], chain[i+1]
		if !bytes.Equal(child.RawIssuer, issuer.RawSubject) {
			return fmt.Errorf("certificate %d issuer does not match certificate %d subject", i, i+1)
		}
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("certificate %d is not validly signed by certificate %d: %w", i, i+1, err)
		}

		caCertificatesBelow := 0
		for j := 1; j <= i; j++ {
			if !bytes.Equal(chain[j].RawSubject, chain[j].RawIssuer) {
				caCertificatesBelow++
			}
		}
		if issuer.MaxPathLen >= 0 && caCertificatesBelow > issuer.MaxPathLen {
			return fmt.Errorf("certificate %d CA path length constraint exceeded", i+1)
		}
	}
	return nil
}

func fingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func bundleDigest(chain []*x509.Certificate, publicKey any) (string, error) {
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write([]byte("cert-bundle-v1\x00"))
	for _, cert := range chain {
		writeDigestPart(hash, cert.Raw)
	}
	writeDigestPart(hash, publicDER)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeDigestPart(digest hash.Hash, data []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	digest.Write(size[:])
	digest.Write(data)
}

func parsePrivateKey(pemData []byte) (interface{}, error) {
	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("no private key PEM block found")
		}
		if stringsContainsPrivateKey(block.Type) {
			switch block.Type {
			case "RSA PRIVATE KEY":
				return x509.ParsePKCS1PrivateKey(block.Bytes)
			case "EC PRIVATE KEY":
				return x509.ParseECPrivateKey(block.Bytes)
			default:
				return x509.ParsePKCS8PrivateKey(block.Bytes)
			}
		}
		rest = remaining
	}
}

func stringsContainsPrivateKey(t string) bool {
	return t == "RSA PRIVATE KEY" || t == "EC PRIVATE KEY" || t == "PRIVATE KEY" || t == "ENCRYPTED PRIVATE KEY"
}

// Fingerprint returns the SHA-256 fingerprint of the first certificate in the PEM data.
func Fingerprint(pemData []byte) (string, error) {
	chain, err := parseCertificateChain(pemData)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate chain: %w", err)
	}
	if len(chain) == 0 {
		return "", fmt.Errorf("no certificate PEM block found")
	}
	return fingerprintDER(chain[0].Raw), nil
}

// IsSameFingerprint compares two fingerprints safely.
func IsSameFingerprint(a, b string) bool {
	return a != "" && a == b
}

// CommonName returns the leaf certificate's primary DNS name or common name.
func (ci *CertInfo) CommonName() string {
	if ci == nil || ci.Certificate == nil {
		return ""
	}
	if len(ci.Certificate.DNSNames) > 0 {
		return ci.Certificate.DNSNames[0]
	}
	return ci.Certificate.Subject.CommonName
}

// Issuer returns the certificate issuer name.
func (ci *CertInfo) Issuer() string {
	if ci == nil || ci.Certificate == nil {
		return ""
	}
	return ci.Certificate.Issuer.CommonName
}

// Serial returns the certificate serial number as a string.
func (ci *CertInfo) Serial() string {
	if ci == nil || ci.Certificate == nil {
		return ""
	}
	return ci.Certificate.SerialNumber.String()
}

// NotBefore returns the certificate validity start.
func (ci *CertInfo) NotBefore() time.Time {
	if ci == nil || ci.Certificate == nil {
		return time.Time{}
	}
	return ci.Certificate.NotBefore
}

// NotAfter returns the certificate validity end.
func (ci *CertInfo) NotAfter() time.Time {
	if ci == nil || ci.Certificate == nil {
		return time.Time{}
	}
	return ci.Certificate.NotAfter
}

// DaysRemaining returns the number of days until expiry.
func (ci *CertInfo) DaysRemaining() int {
	if ci == nil || ci.Certificate == nil {
		return 0
	}
	return int(time.Until(ci.Certificate.NotAfter).Hours() / 24)
}
