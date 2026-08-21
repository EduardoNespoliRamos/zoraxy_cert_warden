package certwarden

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

const (
	testCertificateAPIKey = "certificate-component-secret"
	testPrivateKeyAPIKey  = "private-component-secret"
)

func TestNewClientValidation(t *testing.T) {
	validCredentials := testCredentials()
	tests := []struct {
		name        string
		baseURL     string
		credentials Credentials
		wantError   bool
	}{
		{name: "valid", baseURL: "https://certwarden.example", credentials: validCredentials},
		{name: "root slash", baseURL: "https://certwarden.example/", credentials: validCredentials},
		{name: "http", baseURL: "http://certwarden.example", credentials: validCredentials, wantError: true},
		{name: "missing host", baseURL: "https://", credentials: validCredentials, wantError: true},
		{name: "userinfo", baseURL: "https://user@certwarden.example", credentials: validCredentials, wantError: true},
		{name: "query", baseURL: "https://certwarden.example?x=1", credentials: validCredentials, wantError: true},
		{name: "empty query", baseURL: "https://certwarden.example?", credentials: validCredentials, wantError: true},
		{name: "fragment", baseURL: "https://certwarden.example/#x", credentials: validCredentials, wantError: true},
		{name: "empty fragment", baseURL: "https://certwarden.example#", credentials: validCredentials, wantError: true},
		{name: "path", baseURL: "https://certwarden.example/base", credentials: validCredentials, wantError: true},
		{name: "empty credentials", baseURL: "https://certwarden.example", credentials: Credentials{}, wantError: true},
		{name: "empty certificate key", baseURL: "https://certwarden.example", credentials: Credentials{PrivateKeyAPIKey: testPrivateKeyAPIKey}, wantError: true},
		{name: "blank certificate key", baseURL: "https://certwarden.example", credentials: Credentials{CertificateAPIKey: "  ", PrivateKeyAPIKey: testPrivateKeyAPIKey}, wantError: true},
		{name: "empty private key", baseURL: "https://certwarden.example", credentials: Credentials{CertificateAPIKey: testCertificateAPIKey}, wantError: true},
		{name: "blank private key", baseURL: "https://certwarden.example", credentials: Credentials{CertificateAPIKey: testCertificateAPIKey, PrivateKeyAPIKey: "  "}, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(tt.baseURL, tt.credentials, nil)
			if (err != nil) != tt.wantError {
				t.Fatalf("NewClient() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && (strings.Contains(err.Error(), tt.credentials.CertificateAPIKey) && tt.credentials.CertificateAPIKey != "" || strings.Contains(err.Error(), tt.credentials.PrivateKeyAPIKey) && tt.credentials.PrivateKeyAPIKey != "") {
				t.Fatal("NewClient() error exposed a credential component")
			}
		})
	}
}

func TestNewClientCopiesHTTPClientSettings(t *testing.T) {
	originalRedirect := func(_ *http.Request, _ []*http.Request) error { return nil }
	original := &http.Client{Timeout: 7 * time.Second, CheckRedirect: originalRedirect}
	client, err := NewClient("https://certwarden.example", testCredentials(), original)
	if err != nil {
		t.Fatal(err)
	}
	if client.httpClient == original || client.httpClient.Timeout != 7*time.Second {
		t.Fatal("supplied HTTP client was not copied with its timeout")
	}
	if client.httpClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects are not disabled")
	}
	if original.CheckRedirect(nil, nil) != nil {
		t.Fatal("supplied HTTP client was modified")
	}

	defaulted, err := NewClient("https://certwarden.example", testCredentials(), &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if defaulted.httpClient.Timeout != 30*time.Second {
		t.Fatalf("timeout = %v, want 30s", defaulted.httpClient.Timeout)
	}
}

func TestFetchRequestAndMaterial(t *testing.T) {
	certPEM, keyPEM := testMaterial(t)
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet {
			t.Errorf("method = %s", req.Method)
		}
		wantURI := "/certwarden/api/v1/download/privatecertchains/example%2Fname%20one"
		if req.URL.EscapedPath() != wantURI {
			t.Errorf("path = %q, want %q", req.URL.EscapedPath(), wantURI)
		}
		wantAPIKey := testCertificateAPIKey + "." + testPrivateKeyAPIKey
		if got := req.Header.Get("X-API-Key"); got != wantAPIKey {
			t.Errorf("X-API-Key = %q, want exact composed value %q", got, wantAPIKey)
		}
		return response(http.StatusOK, append(append([]byte{}, certPEM...), keyPEM...)), nil
	})
	client := newTestClient(t, transport)

	before := time.Now()
	material, err := client.Fetch(context.Background(), "example/name one")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if string(material.CertificatePEM) != string(certPEM) || string(material.PrivateKeyPEM) != string(keyPEM) {
		t.Fatal("material was not split correctly")
	}
	if material.HTTPStatus != http.StatusOK || material.RetrievedAt.Before(before) || material.Latency < 0 {
		t.Fatalf("invalid metadata: %+v", material)
	}
}

func TestFetchHTTPErrorKinds(t *testing.T) {
	tests := []struct {
		status int
		kind   ErrorKind
	}{
		{http.StatusUnauthorized, ErrorKindAuthentication},
		{http.StatusForbidden, ErrorKindAuthentication},
		{http.StatusNotFound, ErrorKindNotFound},
		{http.StatusInternalServerError, ErrorKindServer},
		{http.StatusBadGateway, ErrorKindServer},
		{http.StatusBadRequest, ErrorKindInvalidResponse},
		{http.StatusFound, ErrorKindInvalidResponse},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(tt.status, []byte(testCertificateAPIKey+" "+testPrivateKeyAPIKey)), nil
			}))
			_, err := client.Fetch(context.Background(), "name")
			assertFetchError(t, err, tt.kind, tt.status)
		})
	}
}

func TestFetchInvalidMaterial(t *testing.T) {
	certPEM, keyPEM := testMaterial(t)
	secondKey := append([]byte{}, keyPEM...)
	tests := []struct {
		name string
		body []byte
	}{
		{name: "empty"},
		{name: "missing certificate", body: keyPEM},
		{name: "missing key", body: certPEM},
		{name: "duplicate key", body: append(append(append([]byte{}, certPEM...), keyPEM...), secondKey...)},
		{name: "unknown block", body: append(append([]byte{}, certPEM...), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("x")})...)},
		{name: "encrypted key type", body: append(append([]byte{}, certPEM...), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})...)},
		{name: "non PEM", body: append([]byte("unexpected\n"), append(certPEM, keyPEM...)...)},
		{name: "invalid certificate", body: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), keyPEM...)},
		{name: "invalid key", body: append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, tt.body), nil
			}))
			_, err := client.Fetch(context.Background(), "name")
			assertFetchError(t, err, ErrorKindInvalidResponse, http.StatusOK)
			if strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Fatal("error exposed PEM data")
			}
		})
	}
}

func TestSplitMaterialSupportedKeysAndCertificateOrder(t *testing.T) {
	certPEM, rsaPEM := testMaterial(t)
	rsaBlock, _ := pem.Decode(rsaPEM)
	rsaKey, err := x509.ParsePKCS1PrivateKey(rsaBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  []byte
	}{
		{name: "PKCS1 RSA", key: rsaPEM},
		{name: "SEC1 EC", key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})},
		{name: "PKCS8", key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := append(append([]byte{}, certPEM...), certPEM...)
			body := append(append([]byte{}, tt.key...), chain...)
			certificates, privateKey, err := splitMaterial(body)
			if err != nil {
				t.Fatalf("splitMaterial() error = %v", err)
			}
			if string(certificates) != string(chain) {
				t.Fatal("certificate blocks were not retained in response order")
			}
			if string(privateKey) != string(tt.key) {
				t.Fatal("private key block was not retained")
			}
		})
	}
}

func TestFetchDoesNotFollowRedirects(t *testing.T) {
	redirectTargetCalled := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectTargetCalled = true
	}))
	defer target.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer redirector.Close()

	client, err := NewClient(redirector.URL, testCredentials(), redirector.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Fetch(context.Background(), "name")
	assertFetchError(t, err, ErrorKindInvalidResponse, http.StatusFound)
	if redirectTargetCalled {
		t.Fatal("redirect was followed")
	}
}

func TestFetchResponseLimit(t *testing.T) {
	client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, make([]byte, maximumBodyBytes+1)), nil
	}))
	_, err := client.Fetch(context.Background(), "name")
	assertFetchError(t, err, ErrorKindResponseTooLarge, http.StatusOK)
}

func TestFetchContextAndNetworkErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		kind ErrorKind
	}{
		{name: "network", err: errors.New("network failure containing " + testCertificateAPIKey + " and " + testPrivateKeyAPIKey), kind: ErrorKindNetwork},
		{name: "timeout", err: context.DeadlineExceeded, kind: ErrorKindTimeout},
		{name: "TLS", err: x509.UnknownAuthorityError{}, kind: ErrorKindTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, tt.err }))
			_, err := client.Fetch(context.Background(), "name")
			assertFetchError(t, err, tt.kind, 0)
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := newTestClient(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, req.Context().Err()
	}))
	_, err := client.Fetch(ctx, "name")
	assertFetchError(t, err, ErrorKindNetwork, 0)
}

func TestFetchTLSFailureWithInjectedClient(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client, err := NewClient(server.URL, testCredentials(), &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Fetch(context.Background(), "name")
	assertFetchError(t, err, ErrorKindTLS, 0)
}

func TestFetchRejectsEmptyName(t *testing.T) {
	client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport should not be called")
		return nil, nil
	}))
	for _, name := range []string{"", "  "} {
		_, err := client.Fetch(context.Background(), name)
		assertFetchError(t, err, ErrorKindInvalidResponse, 0)
	}
}

func newTestClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := NewClient("https://certwarden.example", testCredentials(), &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func response(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}

func assertFetchError(t *testing.T, err error, kind ErrorKind, status int) {
	t.Helper()
	var fetchErr *FetchError
	if !errors.As(err, &fetchErr) {
		t.Fatalf("error = %T %v, want *FetchError", err, err)
	}
	if fetchErr.Kind != kind || fetchErr.HTTPStatus != status {
		t.Fatalf("error = %+v, want kind %q status %d", fetchErr, kind, status)
	}
	if strings.Contains(err.Error(), testCertificateAPIKey) || strings.Contains(err.Error(), testPrivateKeyAPIKey) {
		t.Fatal("error exposed a credential component")
	}
}

func testCredentials() Credentials {
	return Credentials{
		CertificateAPIKey: testCertificateAPIKey,
		PrivateKeyAPIKey:  testPrivateKeyAPIKey,
	}
}

func testMaterial(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
