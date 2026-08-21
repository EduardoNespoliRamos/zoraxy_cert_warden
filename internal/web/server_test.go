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
	applyErr, mutateErr, syncErr, validateErr, acknowledgeErr error
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
func (m *testManager) SyncCertificate(string) error     { return m.syncErr }
func (m *testManager) ValidateCertificate(string) error { return m.validateErr }
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
