package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
)

type testManager struct {
	mu                                                        sync.Mutex
	cfg                                                       *config.Config
	pending                                                   bool
	configured                                                map[string]credentialState
	credentialMutations                                       []CredentialMutation
	certWardenTestCalls                                       []certWardenTestCall
	applyErr, mutateErr, syncErr, validateErr, acknowledgeErr error
}

type certWardenTestCall struct {
	serverURL, certificateName, certificateAPIKey, privateKeyAPIKey string
}

func (m *testManager) SnapshotConfig() *config.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Clone()
}
func (m *testManager) SnapshotStatus() []status.CertificateStatus { return nil }
func (m *testManager) ApplyConfig(_ context.Context, candidate *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.applyErr != nil {
		return m.applyErr
	}
	m.cfg = candidate.Clone()
	return nil
}
func (m *testManager) MutateConfig(_ context.Context, mutation ConfigMutation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	candidate := m.cfg.Clone()
	if err := mutation(candidate); err != nil {
		return err
	}
	if m.mutateErr != nil {
		return m.mutateErr
	}
	m.cfg = candidate
	return nil
}
func (m *testManager) MutateConfigAndCredentials(_ context.Context, mutation ConfigMutation, credentials *CredentialMutation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	candidate := m.cfg.Clone()
	if err := mutation(candidate); err != nil {
		return err
	}
	if m.mutateErr != nil {
		return m.mutateErr
	}
	m.cfg = candidate
	if credentials != nil {
		m.credentialMutations = append(m.credentialMutations, *credentials)
	}
	return nil
}
func (m *testManager) CredentialsConfigured(name string) (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	configured := m.configured[name]
	return configured.CertificateAPIKey, configured.PrivateKeyAPIKey
}
func (m *testManager) SyncCertificate(string) error     { return m.syncErr }
func (m *testManager) ValidateCertificate(string) error { return m.validateErr }
func (m *testManager) TestCertWardenConnection(_ context.Context, serverURL, certificateName, certificateAPIKey, privateKeyAPIKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certWardenTestCalls = append(m.certWardenTestCalls, certWardenTestCall{
		serverURL: serverURL, certificateName: certificateName,
		certificateAPIKey: certificateAPIKey, privateKeyAPIKey: privateKeyAPIKey,
	})
	return m.validateErr
}
func (m *testManager) FallbackRestartPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending
}
func (m *testManager) AcknowledgeFallbackRestart(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.acknowledgeErr != nil {
		return m.acknowledgeErr
	}
	m.pending = false
	return nil
}

func TestConcurrentCertificateCreatesDoNotLoseUpdates(t *testing.T) {
	manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
	server := NewServer(manager)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, _ := json.Marshal(config.CertificateConfig{Name: fmt.Sprintf("cert-%d", i)})
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			server.handleCertificates(response, request)
			if response.Code != http.StatusOK {
				t.Errorf("create failed: %d: %s", response.Code, response.Body.String())
			}
		}(i)
	}
	wg.Wait()
	if got := len(manager.SnapshotConfig().Certificates); got != 20 {
		t.Fatalf("expected 20 certificates, got %d", got)
	}
}

func testHandler(manager *testManager, logger ...*slog.Logger) http.Handler {
	mux := http.NewServeMux()
	server := NewServer(manager, logger...)
	server.RegisterRoutes(mux, "/ui")
	server.RegisterRoutesUnderPrefix(mux, "/custom/proxy")
	return server.Handler(mux)
}

func request(t *testing.T, handler http.Handler, method, target, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestStrictJSONDecoder(t *testing.T) {
	manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
	handler := testHandler(manager)
	tests := []struct {
		name, body, contentType string
		want                    int
	}{
		{name: "empty", body: "", contentType: "application/json", want: http.StatusBadRequest},
		{name: "unknown field", body: `{"unknown":true}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "second JSON value", body: `{} {}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "trailing garbage", body: `{} trailing`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "wrong content type", body: `{}`, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "missing content type", body: `{}`, want: http.StatusUnsupportedMediaType},
		{name: "parameters allowed", body: `{}`, contentType: "application/json; charset=utf-8", want: http.StatusOK},
		{name: "oversized", body: `{"log_level":"` + strings.Repeat("a", int(maxRequestBodyBytes)) + `"}`, contentType: "application/json", want: http.StatusRequestEntityTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := request(t, handler, http.MethodPost, "/api/config", test.body, test.contentType)
			if response.Code != test.want {
				t.Fatalf("code=%d body=%s; want %d", response.Code, response.Body.String(), test.want)
			}
			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type=%q", got)
			}
		})
	}
}

func TestCertWardenTestStrictRequestParsing(t *testing.T) {
	tests := []struct {
		name, body, contentType string
		want                    int
	}{
		{name: "empty", contentType: "application/json", want: http.StatusBadRequest},
		{name: "unknown field", body: `{"server_url":"https://warden.example","unknown":true}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "second JSON value", body: `{} {}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "trailing garbage", body: `{} trailing`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "wrong content type", body: `{}`, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "oversized", body: `{"certificate_api_key":"` + strings.Repeat("a", int(maxRequestBodyBytes)) + `"}`, contentType: "application/json", want: http.StatusRequestEntityTooLarge},
	}
	for _, route := range []struct {
		name, path string
	}{
		{name: "direct", path: "/api/certwarden/test"},
		{name: "prefixed", path: "/custom/proxy/api/certwarden/test"},
	} {
		for _, test := range tests {
			t.Run(route.name+"/"+test.name, func(t *testing.T) {
				manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
				response := request(t, testHandler(manager), http.MethodPost, route.path, test.body, test.contentType)
				if response.Code != test.want {
					t.Fatalf("code=%d body=%s; want %d", response.Code, response.Body.String(), test.want)
				}
				if response.Header().Get("Content-Type") != "application/json" {
					t.Fatalf("Content-Type=%q", response.Header().Get("Content-Type"))
				}
				if len(manager.certWardenTestCalls) != 0 {
					t.Fatalf("invalid request reached manager: %+v", manager.certWardenTestCalls)
				}
			})
		}
	}
}

func TestCertWardenTestRoutesPassValuesAndReturnSuccess(t *testing.T) {
	want := certWardenTestCall{
		serverURL: "https://warden.example:8443", certificateName: "example.com",
		certificateAPIKey: "certificate-secret", privateKeyAPIKey: "private-secret",
	}
	body := `{"server_url":"` + want.serverURL + `","certificate_name":"` + want.certificateName + `","certificate_api_key":"` + want.certificateAPIKey + `","private_key_api_key":"` + want.privateKeyAPIKey + `"}`
	for _, route := range []struct {
		name, path string
	}{
		{name: "direct", path: "/api/certwarden/test"},
		{name: "prefixed", path: "/custom/proxy/api/certwarden/test"},
	} {
		t.Run(route.name, func(t *testing.T) {
			manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			response := request(t, testHandler(manager, logger), http.MethodPost, route.path, body, "application/json")
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"ok"`) {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			if len(manager.certWardenTestCalls) != 1 || manager.certWardenTestCalls[0] != want {
				t.Fatalf("manager calls=%+v; want %+v", manager.certWardenTestCalls, want)
			}
			for _, secret := range []string{want.certificateAPIKey, want.privateKeyAPIKey} {
				if strings.Contains(response.Body.String(), secret) || strings.Contains(logs.String(), secret) {
					t.Fatalf("credential %q exposed in response or logs", secret)
				}
			}
		})
	}
}

func TestCertWardenTestValidationErrorIsSafe(t *testing.T) {
	const certificateAPIKey = "certificate-secret"
	const privateKeyAPIKey = "private-secret"
	body := `{"server_url":"https://warden.example","certificate_name":"example.com","certificate_api_key":"` + certificateAPIKey + `","private_key_api_key":"` + privateKeyAPIKey + `"}`
	for _, route := range []struct {
		name, path string
	}{
		{name: "direct", path: "/api/certwarden/test"},
		{name: "prefixed", path: "/custom/proxy/api/certwarden/test"},
	} {
		t.Run(route.name, func(t *testing.T) {
			manager := &testManager{
				cfg:         &config.Config{LogLevel: "info"},
				validateErr: testSourceValidationError{errors.New("remote certificate validation failed")},
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			response := request(t, testHandler(manager, logger), http.MethodPost, route.path, body, "application/json")
			if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "certificate validation failed") {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			if len(manager.certWardenTestCalls) != 1 {
				t.Fatalf("manager calls=%d; want 1", len(manager.certWardenTestCalls))
			}
			for _, secret := range []string{certificateAPIKey, privateKeyAPIKey} {
				if strings.Contains(response.Body.String(), secret) || strings.Contains(logs.String(), secret) {
					t.Fatalf("credential %q exposed in response or logs", secret)
				}
			}
		})
	}
}

func TestCertificateRoutesRequireExactPaths(t *testing.T) {
	manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
	handler := testHandler(manager)
	for _, prefix := range []string{"", "/custom/proxy"} {
		for _, path := range []string{
			"/api/certificates/name/sync",
			"/api/certificates/name/validate",
			"/api/fallback/restart/acknowledge",
		} {
			response := request(t, handler, http.MethodPost, prefix+path, "", "")
			if response.Code != http.StatusOK {
				t.Fatalf("valid path %s: code=%d body=%s", prefix+path, response.Code, response.Body.String())
			}
		}
		for _, path := range []string{
			"/api/certificates/", "/api/certificates//sync", "/api/certificates/name/",
			"/api/certificates/name/sync/extra", "/api/certificates/name/unknown",
			"/api/fallback/restart/acknowledge/extra", "/api/config/extra",
		} {
			response := request(t, handler, http.MethodPost, prefix+path, "", "")
			if response.Code != http.StatusNotFound {
				t.Fatalf("invalid path %s: code=%d body=%s", prefix+path, response.Code, response.Body.String())
			}
		}
	}
}

func TestCanonicalPathHandlerPreservesUIProxyRoot(t *testing.T) {
	manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
	server := NewServer(manager)
	mux := http.NewServeMux()
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	response := request(t, server.Handler(mux), http.MethodGet, "/ui/", "", "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("UI proxy root returned %d: %s", response.Code, response.Body.String())
	}
}

func TestMethodNotAllowedIsJSONAndSetsAllow(t *testing.T) {
	manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
	handler := testHandler(manager)
	tests := []struct{ path, allow string }{
		{path: "/health", allow: "GET"},
		{path: "/api/config", allow: "GET, POST"},
		{path: "/api/certificates/name", allow: "PUT, DELETE"},
		{path: "/api/certificates/name/sync", allow: "POST"},
		{path: "/api/fallback/restart/acknowledge", allow: "POST"},
	}
	for _, test := range tests {
		response := request(t, handler, http.MethodPatch, test.path, "", "")
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != test.allow {
			t.Fatalf("%s: code=%d Allow=%q body=%s", test.path, response.Code, response.Header().Get("Allow"), response.Body.String())
		}
		if response.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s returned non-JSON 405", test.path)
		}
	}
}

type testInvalidConfigError struct{ error }

func (testInvalidConfigError) InvalidConfig() bool { return true }

type testConfigConflictError struct{ error }

func (testConfigConflictError) ConfigConflict() bool { return true }

type testNotFoundError struct{ error }

func (testNotFoundError) NotFound() bool { return true }

type testSourceValidationError struct{ error }

func (testSourceValidationError) SourceValidation() bool { return true }

func TestErrorStatusMappingsAndSafeMessages(t *testing.T) {
	secretPath := "/private/source/certificate.pem"
	tests := []struct {
		name, path string
		configure  func(*testManager)
		want       int
		message    string
	}{
		{name: "not found", path: "/api/certificates/missing/sync", configure: func(m *testManager) { m.syncErr = testNotFoundError{errors.New(secretPath)} }, want: http.StatusNotFound, message: "certificate not found"},
		{name: "invalid source", path: "/api/certificates/bad/validate", configure: func(m *testManager) { m.validateErr = testSourceValidationError{errors.New(secretPath)} }, want: http.StatusUnprocessableEntity, message: "certificate validation failed"},
		{name: "invalid request field", path: "/api/config", configure: func(m *testManager) { m.applyErr = testInvalidConfigError{errors.New(secretPath)} }, want: http.StatusBadRequest, message: "invalid request"},
		{name: "config conflict", path: "/api/config", configure: func(m *testManager) { m.applyErr = testConfigConflictError{errors.New(secretPath)} }, want: http.StatusConflict, message: "configuration conflict"},
		{name: "filesystem", path: "/api/certificates/bad/sync", configure: func(m *testManager) { m.syncErr = errors.New("open " + secretPath + ": permission denied") }, want: http.StatusInternalServerError, message: "internal server error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
			test.configure(manager)
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			contentType, body := "", ""
			if test.path == "/api/config" {
				contentType, body = "application/json", `{}`
			}
			response := request(t, testHandler(manager, logger), http.MethodPost, test.path, body, contentType)
			if response.Code != test.want || !strings.Contains(response.Body.String(), test.message) {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), secretPath) {
				t.Fatalf("response exposed path: %s", response.Body.String())
			}
			if !strings.Contains(logs.String(), secretPath) {
				t.Fatalf("full error was not logged: %s", logs.String())
			}
		})
	}
}

func TestCertificateCreateConflict(t *testing.T) {
	manager := &testManager{cfg: &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{{Name: "duplicate"}}}}
	response := request(t, testHandler(manager), http.MethodPost, "/api/certificates", `{"name":"duplicate"}`, "application/json")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "configuration conflict") {
		t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
	}
}

func TestFallbackRestartAcknowledgeRoutes(t *testing.T) {
	for _, path := range []string{"/api/fallback/restart/acknowledge", "/ui/api/fallback/restart/acknowledge"} {
		manager := &testManager{cfg: &config.Config{LogLevel: "info"}, pending: true}
		mux := http.NewServeMux()
		server := NewServer(manager)
		server.RegisterRoutes(mux, "/ui")
		server.RegisterRoutesUnderPrefix(mux, "/ui")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusOK || manager.FallbackRestartPending() {
			t.Fatalf("acknowledge failed for %s: code=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestRemoteCredentialsAreMaskedInConfigResponses(t *testing.T) {
	manager := &testManager{
		cfg: &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{{
			Name: "remote", Source: config.CertificateSource{Type: config.SourceTypeCertWarden},
		}}},
		configured: map[string]credentialState{
			"remote": {CertificateAPIKey: true, PrivateKeyAPIKey: false},
		},
	}
	for _, path := range []string{"/api/config", "/api/certificates"} {
		t.Run(path, func(t *testing.T) {
			response := request(t, testHandler(manager), http.MethodGet, path, "", "")
			if response.Code != http.StatusOK {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			body := response.Body.String()
			if !strings.Contains(body, `"certificate_api_key_configured":true`) || !strings.Contains(body, `"private_key_api_key_configured":false`) {
				t.Fatalf("configured credential state missing: %s", body)
			}
			if strings.Contains(body, `"certificate_api_key":`) || strings.Contains(body, `"private_key_api_key":`) {
				t.Fatalf("response exposed credential values: %s", body)
			}
		})
	}
}

func TestCreateRemoteCertificateRequiresBothCredentials(t *testing.T) {
	tests := []struct {
		name        string
		credentials string
		want        int
	}{
		{name: "omitted", credentials: "", want: http.StatusBadRequest},
		{name: "certificate only", credentials: `,"cert_warden_credentials":{"certificate_api_key":"certificate-value"}`, want: http.StatusBadRequest},
		{name: "private key only", credentials: `,"cert_warden_credentials":{"private_key_api_key":"private-value"}`, want: http.StatusBadRequest},
		{name: "both", credentials: `,"cert_warden_credentials":{"certificate_api_key":"certificate-value","private_key_api_key":"private-value"}`, want: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &testManager{cfg: &config.Config{LogLevel: "info"}}
			body := `{"name":"remote","source":{"type":"cert_warden"}` + test.credentials + `}`
			response := request(t, testHandler(manager), http.MethodPost, "/api/certificates", body, "application/json")
			if response.Code != test.want {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			if test.want != http.StatusOK && (len(manager.credentialMutations) != 0 || len(manager.SnapshotConfig().Certificates) != 0) {
				t.Fatal("invalid create mutated configuration or credentials")
			}
			if test.want == http.StatusOK && (len(manager.credentialMutations) != 1 || manager.credentialMutations[0].CertificateAPIKey == nil || manager.credentialMutations[0].PrivateKeyAPIKey == nil) {
				t.Fatalf("complete credentials were not passed to the manager: %+v", manager.credentialMutations)
			}
		})
	}
}

func TestRemoteCredentialMutations(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		body       string
		wantDelete bool
	}{
		{
			name:   "remote update omitting credentials preserves them",
			method: http.MethodPut,
			body:   `{"name":"remote","source":{"type":"cert_warden"}}`,
		},
		{
			name:       "switching to local deletes credentials",
			method:     http.MethodPut,
			body:       `{"name":"remote","source":{"type":"local"}}`,
			wantDelete: true,
		},
		{
			name:       "deleting certificate deletes credentials",
			method:     http.MethodDelete,
			wantDelete: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &testManager{cfg: &config.Config{Certificates: []config.CertificateConfig{{
				Name: "remote", Source: config.CertificateSource{Type: config.SourceTypeCertWarden},
			}}}}
			contentType := ""
			if test.method == http.MethodPut {
				contentType = "application/json"
			}
			response := request(t, testHandler(manager), test.method, "/api/certificates/remote", test.body, contentType)
			if response.Code != http.StatusOK {
				t.Fatalf("code=%d body=%s", response.Code, response.Body.String())
			}
			if len(manager.credentialMutations) != 1 {
				t.Fatalf("credential mutations=%d; want 1", len(manager.credentialMutations))
			}
			mutation := manager.credentialMutations[0]
			if mutation.Name != "remote" || mutation.Delete != test.wantDelete {
				t.Fatalf("unexpected credential mutation: %+v", mutation)
			}
			if mutation.CertificateAPIKey != nil || mutation.PrivateKeyAPIKey != nil {
				t.Fatalf("omitted credentials unexpectedly supplied values: %+v", mutation)
			}
		})
	}
}
