package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestDataHandlerScenarios(t *testing.T) {
	m := &mock{
		scenario: scenarioValidA,
		material: material{
			validA:     []byte("valid-a"),
			validB:     []byte("valid-b"),
			mismatched: []byte("mismatched"),
			malformed:  []byte("malformed"),
			oversized:  make([]byte, maximumBodyBytes+1),
		},
		slowDelay: time.Millisecond,
	}
	tests := []struct {
		scenario scenario
		status   int
		bodySize int
	}{
		{scenarioValidA, http.StatusOK, len(m.material.validA)},
		{scenarioValidB, http.StatusOK, len(m.material.validB)},
		{scenarioUnauthorized, http.StatusUnauthorized, 0},
		{scenarioNotFound, http.StatusNotFound, 0},
		{scenarioServerError, http.StatusInternalServerError, 0},
		{scenarioMismatchedPair, http.StatusOK, len(m.material.mismatched)},
		{scenarioMalformedPEM, http.StatusOK, len(m.material.malformed)},
		{scenarioSlowResponse, http.StatusOK, len(m.material.validA)},
		{scenarioOversized, http.StatusOK, len(m.material.oversized)},
	}
	for _, tt := range tests {
		t.Run(string(tt.scenario), func(t *testing.T) {
			m.setScenario(tt.scenario)
			request := httptest.NewRequest(http.MethodGet, dataPath, nil)
			request.Header.Set("X-API-Key", expectedAPIKey)
			response := httptest.NewRecorder()
			m.dataHandler().ServeHTTP(response, request)
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d", response.Code, tt.status)
			}
			if tt.bodySize != 0 && response.Body.Len() != tt.bodySize {
				t.Fatalf("body size = %d, want %d", response.Body.Len(), tt.bodySize)
			}
		})
	}
}

func TestDataHandlerRequiresExactRequest(t *testing.T) {
	m := &mock{scenario: scenarioValidA, material: material{validA: []byte("ok")}}
	tests := []struct {
		name   string
		method string
		path   string
		key    string
		status int
	}{
		{name: "valid", method: http.MethodGet, path: dataPath, key: expectedAPIKey, status: http.StatusOK},
		{name: "wrong key", method: http.MethodGet, path: dataPath, key: "wrong", status: http.StatusUnauthorized},
		{name: "wrong path", method: http.MethodGet, path: dataPath + "/", key: expectedAPIKey, status: http.StatusNotFound},
		{name: "wrong method", method: http.MethodPost, path: dataPath, key: expectedAPIKey, status: http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, tt.path, nil)
			request.Header.Set("X-API-Key", tt.key)
			response := httptest.NewRecorder()
			m.dataHandler().ServeHTTP(response, request)
			if response.Code != tt.status {
				t.Fatalf("status = %d, want %d", response.Code, tt.status)
			}
		})
	}
}

func TestControlHandlerChangesAndResetsScenario(t *testing.T) {
	m := &mock{scenario: scenarioValidA}
	postControl(t, m, "/test/scenario/valid-b", http.StatusNoContent)
	if m.currentScenario() != scenarioValidB {
		t.Fatalf("scenario = %q, want %q", m.currentScenario(), scenarioValidB)
	}
	postControl(t, m, "/test/scenario/unknown", http.StatusNotFound)
	postControl(t, m, "/test/reset", http.StatusNoContent)
	if m.currentScenario() != scenarioValidA {
		t.Fatalf("scenario = %q, want %q", m.currentScenario(), scenarioValidA)
	}

	response := httptest.NewRecorder()
	m.controlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d", response.Code)
	}
}

func TestGeneratedBundlesAreValidAndDistinct(t *testing.T) {
	generated, err := generateMaterial()
	if err != nil {
		t.Fatal(err)
	}
	certA, keyA := parseBundle(t, generated.validA)
	certB, keyB := parseBundle(t, generated.validB)
	if certA.PublicKey.(*rsa.PublicKey).N.Cmp(keyA.N) != 0 || certB.PublicKey.(*rsa.PublicKey).N.Cmp(keyB.N) != 0 {
		t.Fatal("valid certificate and key pair do not match")
	}
	if certA.SerialNumber.Cmp(certB.SerialNumber) == 0 || keyA.N.Cmp(keyB.N) == 0 {
		t.Fatal("bundles A and B are not distinct")
	}
	mismatchCert, mismatchKey := parseBundle(t, generated.mismatched)
	if mismatchCert.PublicKey.(*rsa.PublicKey).N.Cmp(mismatchKey.N) == 0 {
		t.Fatal("mismatched scenario contains a matching pair")
	}
}

func TestTransportCertificateUsesGeneratedCAAndDNSName(t *testing.T) {
	_, ca, caKey, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	transportCertificate, err := generateTransportCertificate(ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(transportCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "cert-warden-mock", Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("verify transport certificate: %v", err)
	}
	if _, ok := transportCertificate.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("transport key type = %T, want RSA", transportCertificate.PrivateKey)
	}
}

func TestWriteFileAtomically(t *testing.T) {
	path := t.TempDir() + "/nested/ca.pem"
	if err := writeFileAtomically(path, []byte("ca"), 0o644); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "ca" {
		t.Fatalf("contents = %q", contents)
	}
}

func postControl(t *testing.T, m *mock, path string, wantStatus int) {
	t.Helper()
	response := httptest.NewRecorder()
	m.controlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
	if response.Code != wantStatus {
		t.Fatalf("POST %s status = %d, want %d", path, response.Code, wantStatus)
	}
}

func parseBundle(t *testing.T, bundle []byte) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	certificateBlock, rest := pem.Decode(bundle)
	keyBlock, trailing := pem.Decode(rest)
	if certificateBlock == nil || keyBlock == nil || len(trailing) != 0 {
		t.Fatal("bundle is not exactly one certificate and one key")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}
