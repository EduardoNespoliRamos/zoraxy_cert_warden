package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	dataPath         = "/certwarden/api/v1/download/privatecertchains/remote.example.com"
	expectedAPIKey   = "cert-api-key.key-api-key"
	defaultCAPath    = "/test-ca/ca.pem"
	defaultSlowDelay = 35 * time.Second
	maximumBodyBytes = 1 << 20
)

type scenario string

const (
	scenarioValidA         scenario = "valid-a"
	scenarioValidB         scenario = "valid-b"
	scenarioUnauthorized   scenario = "unauthorized"
	scenarioNotFound       scenario = "not-found"
	scenarioServerError    scenario = "server-error"
	scenarioMismatchedPair scenario = "mismatched-pair"
	scenarioMalformedPEM   scenario = "malformed-pem"
	scenarioSlowResponse   scenario = "slow-response"
	scenarioOversized      scenario = "oversized-response"
)

var scenarios = map[scenario]struct{}{
	scenarioValidA: {}, scenarioValidB: {}, scenarioUnauthorized: {},
	scenarioNotFound: {}, scenarioServerError: {}, scenarioMismatchedPair: {},
	scenarioMalformedPEM: {}, scenarioSlowResponse: {}, scenarioOversized: {},
}

type material struct {
	validA     []byte
	validB     []byte
	mismatched []byte
	malformed  []byte
	oversized  []byte
}

type mock struct {
	mu        sync.RWMutex
	scenario  scenario
	material  material
	slowDelay time.Duration
}

func main() {
	caPEM, ca, caKey, err := generateCA()
	if err != nil {
		log.Fatal("generate transport CA: ", err)
	}
	serverCertificate, err := generateTransportCertificate(ca, caKey)
	if err != nil {
		log.Fatal("generate HTTPS certificate: ", err)
	}
	caPath := envOrDefault("TEST_CA_PATH", defaultCAPath)
	if err := writeFileAtomically(caPath, caPEM, 0o644); err != nil {
		log.Fatal("write transport CA: ", err)
	}

	responseMaterial, err := generateMaterial()
	if err != nil {
		log.Fatal("generate response material: ", err)
	}
	delay, err := slowDelayFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	service := &mock{scenario: scenarioValidA, material: responseMaterial, slowDelay: delay}

	httpsServer := &http.Server{Addr: ":8443", Handler: service.dataHandler(), ReadHeaderTimeout: 5 * time.Second}
	controlServer := &http.Server{Addr: ":8080", Handler: service.controlHandler(), ReadHeaderTimeout: 5 * time.Second}
	errorsChannel := make(chan error, 2)

	go func() {
		listener, listenErr := net.Listen("tcp", httpsServer.Addr)
		if listenErr != nil {
			errorsChannel <- listenErr
			return
		}
		tlsListener := tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			MinVersion:   tls.VersionTLS12,
		})
		log.Printf("HTTPS data endpoint listening on %s", httpsServer.Addr)
		errorsChannel <- httpsServer.Serve(tlsListener)
	}()
	go func() {
		log.Printf("HTTP control endpoint listening on %s", controlServer.Addr)
		errorsChannel <- controlServer.ListenAndServe()
	}()

	if err := <-errorsChannel; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (m *mock) dataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != dataPath {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-API-Key") != expectedAPIKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		current := m.currentScenario()
		switch current {
		case scenarioUnauthorized:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case scenarioNotFound:
			http.Error(w, "not found", http.StatusNotFound)
		case scenarioServerError:
			http.Error(w, "server error", http.StatusInternalServerError)
		case scenarioSlowResponse:
			select {
			case <-time.After(m.slowDelay):
			case <-r.Context().Done():
				return
			}
			m.writeMaterial(w, m.material.validA)
		case scenarioValidB:
			m.writeMaterial(w, m.material.validB)
		case scenarioMismatchedPair:
			m.writeMaterial(w, m.material.mismatched)
		case scenarioMalformedPEM:
			m.writeMaterial(w, m.material.malformed)
		case scenarioOversized:
			m.writeMaterial(w, m.material.oversized)
		default:
			m.writeMaterial(w, m.material.validA)
		}
	})
}

func (m *mock) controlHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			if r.Method != http.MethodGet {
				methodNotAllowed(w, http.MethodGet)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "scenario": string(m.currentScenario())})
		case r.URL.Path == "/test/reset":
			if r.Method != http.MethodPost {
				methodNotAllowed(w, http.MethodPost)
				return
			}
			m.setScenario(scenarioValidA)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/test/scenario/"):
			if r.Method != http.MethodPost {
				methodNotAllowed(w, http.MethodPost)
				return
			}
			requested := scenario(strings.TrimPrefix(r.URL.Path, "/test/scenario/"))
			if _, ok := scenarios[requested]; !ok {
				http.NotFound(w, r)
				return
			}
			m.setScenario(requested)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
}

func (m *mock) currentScenario() scenario {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scenario
}

func (m *mock) setScenario(value scenario) {
	m.mu.Lock()
	m.scenario = value
	m.mu.Unlock()
}

func (m *mock) writeMaterial(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func generateMaterial() (material, error) {
	certA, keyA, err := generateBundle(101, "A")
	if err != nil {
		return material{}, err
	}
	certB, keyB, err := generateBundle(102, "B")
	if err != nil {
		return material{}, err
	}
	return material{
		validA:     joinPEM(certA, keyA),
		validB:     joinPEM(certB, keyB),
		mismatched: joinPEM(certA, keyB),
		malformed:  []byte("-----BEGIN CERTIFICATE-----\nnot-valid-base64\n-----END CERTIFICATE-----\n"),
		oversized:  bytes.Repeat([]byte("x"), maximumBodyBytes+1),
	}, nil
}

func generateBundle(serial int64, label string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "remote.example.com " + label},
		DNSNames:     []string{"remote.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certificatePEM, keyPEM, nil
}

func generateCA() ([]byte, *x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Cert Warden Mock Transport CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed, key, nil
}

func generateTransportCertificate(ca *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cert-warden-mock"},
		DNSNames:     []string{"cert-warden-mock"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certificatePEM, keyPEM)
}

func writeFileAtomically(path string, contents []byte, mode os.FileMode) (err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".ca-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err = temporary.Write(contents); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func slowDelayFromEnvironment() (time.Duration, error) {
	raw := os.Getenv("TEST_SLOW_DELAY")
	if raw == "" {
		return defaultSlowDelay, nil
	}
	delay, err := time.ParseDuration(raw)
	if err != nil || delay < 0 {
		return 0, fmt.Errorf("invalid TEST_SLOW_DELAY %q", raw)
	}
	return delay, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func joinPEM(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}
