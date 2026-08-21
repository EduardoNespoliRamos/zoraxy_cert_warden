package certutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertInfo holds parsed certificate data.
type CertInfo struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Fingerprint string
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

	// Ensure the key pair loads together.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("certificate and private key do not match: %w", err)
	}

	chain, err := parseCertificateChain(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM")
	}

	leaf := chain[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("certificate is not yet valid")
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("certificate has expired")
	}

	if _, err := parsePrivateKey(keyPEM); err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	fp, err := Fingerprint(certPEM)
	if err != nil {
		return nil, err
	}

	return &CertInfo{
		Certificate: leaf,
		Chain:       chain,
		Fingerprint: fp,
	}, nil
}

func parseCertificateChain(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			rest = remaining
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		rest = remaining
	}
	return certs, nil
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
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate PEM block found")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
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
