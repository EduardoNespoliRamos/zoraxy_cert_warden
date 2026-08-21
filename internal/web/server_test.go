package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
)

type testManager struct {
	mu      sync.Mutex
	cfg     *config.Config
	pending bool
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
	m.cfg = candidate
	return nil
}
func (m *testManager) SyncCertificate(string) error     { return nil }
func (m *testManager) ValidateCertificate(string) error { return nil }
func (m *testManager) FallbackRestartPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending
}
func (m *testManager) AcknowledgeFallbackRestart(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
			server.handleCertificates(response, httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(body)))
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
