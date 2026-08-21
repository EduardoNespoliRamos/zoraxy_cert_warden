package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
)

type testSyncer struct {
	reloads int
}

func (s *testSyncer) SyncCertificate(string) error     { return nil }
func (s *testSyncer) ValidateCertificate(string) error { return nil }
func (s *testSyncer) ReloadConfig(*config.Config) error {
	s.reloads++
	return nil
}

func TestHandleCertificatesRejectsOutOfPolicyPath(t *testing.T) {
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	policy, err := config.NewPathPolicy([]string{sourceRoot}, []string{destinationRoot})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Certificates: []config.CertificateConfig{{
		Name:    "existing",
		Enabled: true,
		Source: config.CertificateSource{
			Certificate: filepath.Join(sourceRoot, "cert.pem"),
			PrivateKey:  filepath.Join(sourceRoot, "key.pem"),
		},
		Destination: config.CertificateDestination{
			TargetDirectory: destinationRoot,
			TargetName:      "existing",
		},
	}}}
	syncer := &testSyncer{}
	server := NewServer(cfg, map[string]*status.State{}, syncer, filepath.Join(t.TempDir(), "config.json"), policy)

	outside := t.TempDir()
	requestConfig := config.CertificateConfig{
		Name:    "outside",
		Enabled: true,
		Source: config.CertificateSource{
			Certificate: filepath.Join(outside, "cert.pem"),
			PrivateKey:  filepath.Join(outside, "key.pem"),
		},
		Destination: config.CertificateDestination{
			TargetDirectory: destinationRoot,
			TargetName:      "outside",
		},
	}
	body, err := json.Marshal(requestConfig)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(body))
	response := httptest.NewRecorder()

	server.handleCertificates(response, req)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", response.Code, response.Body.String())
	}
	if syncer.reloads != 0 {
		t.Fatal("out-of-policy config must not be reloaded")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatal("out-of-policy config must not be persisted in memory")
	}
}
