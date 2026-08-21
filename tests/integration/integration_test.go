package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/sync"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/watcher"
)

func TestSyncFlow_CertificateAThenB(t *testing.T) {
	sourceDir := t.TempDir()
	targetDir := t.TempDir()
	policy := integrationPolicy(t, sourceDir, targetDir)

	// Generate and write certificate A.
	certA, keyA, err := certutil.GenerateTestCertificateNow("a.homealone.com.br", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert A failed: %v", err)
	}
	writeSource(t, sourceDir, certA, keyA)

	cfg := config.CertificateConfig{
		Name:    "homealone-wildcard",
		Enabled: true,
		Source: config.CertificateSource{
			Certificate: filepath.Join(sourceDir, "certchain0.pem"),
			PrivateKey:  filepath.Join(sourceDir, "key0.pem"),
		},
		Destination: config.CertificateDestination{
			TargetDirectory: targetDir,
			TargetName:      "homealone-wildcard",
		},
	}

	_, result, err := sync.Sync(cfg, policy)
	if err != nil {
		t.Fatalf("sync A failed: %v", err)
	}
	if !result.Synced {
		t.Fatal("expected sync A to write files")
	}

	destFP, err := sync.ReadDestinationFingerprint(targetDir, "homealone-wildcard", policy)
	if err != nil {
		t.Fatalf("read dest fingerprint failed: %v", err)
	}
	if destFP != result.SourceFP {
		t.Fatal("destination fingerprint mismatch after sync A")
	}

	// Replace with certificate B and use watcher to detect the change.
	certB, keyB, err := certutil.GenerateTestCertificateNow("b.homealone.com.br", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert B failed: %v", err)
	}

	done := make(chan struct{})
	w, err := watcher.New([]string{
		filepath.Join(sourceDir, "certchain0.pem"),
		filepath.Join(sourceDir, "key0.pem"),
	}, 200*time.Millisecond, 300*time.Millisecond, false, func() {
		_, result, err := sync.Sync(cfg, policy)
		if err != nil {
			t.Logf("sync callback error: %v", err)
			return
		}
		if result.Synced {
			close(done)
		}
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	writeSource(t, sourceDir, certB, keyB)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for watcher to sync certificate B")
	}

	destFP2, err := sync.ReadDestinationFingerprint(targetDir, "homealone-wildcard", policy)
	if err != nil {
		t.Fatalf("read dest fingerprint failed: %v", err)
	}
	if destFP2 == destFP {
		t.Fatal("destination fingerprint should have changed to certificate B")
	}
}

func TestSyncFlow_SplitUpdate(t *testing.T) {
	sourceDir := t.TempDir()
	targetDir := t.TempDir()
	policy := integrationPolicy(t, sourceDir, targetDir)

	certA, keyA, err := certutil.GenerateTestCertificateNow("split.homealone.com.br", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert A failed: %v", err)
	}
	certB, keyB, err := certutil.GenerateTestCertificateNow("split.homealone.com.br", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert B failed: %v", err)
	}

	cfg := config.CertificateConfig{
		Name:    "split",
		Enabled: true,
		Source: config.CertificateSource{
			Certificate: filepath.Join(sourceDir, "certchain0.pem"),
			PrivateKey:  filepath.Join(sourceDir, "key0.pem"),
		},
		Destination: config.CertificateDestination{
			TargetDirectory: targetDir,
			TargetName:      "split",
		},
	}

	writeSource(t, sourceDir, certA, keyA)
	if _, _, err := sync.Sync(cfg, policy); err != nil {
		t.Fatalf("initial sync failed: %v", err)
	}

	destFP, _ := sync.ReadDestinationFingerprint(targetDir, "split", policy)

	// Update only certificate. Sync should fail/abort and target should stay unchanged.
	if err := os.WriteFile(filepath.Join(sourceDir, "certchain0.pem"), certB, 0644); err != nil {
		t.Fatal(err)
	}
	if _, result, err := sync.Sync(cfg, policy); err == nil && result.Synced {
		t.Fatal("expected sync to be skipped or fail when key does not match")
	}

	destFP2, _ := sync.ReadDestinationFingerprint(targetDir, "split", policy)
	if destFP2 != destFP {
		t.Fatal("destination should not have changed after partial update")
	}

	// Now update key to match. Sync should succeed.
	if err := os.WriteFile(filepath.Join(sourceDir, "key0.pem"), keyB, 0600); err != nil {
		t.Fatal(err)
	}
	_, result, err := sync.Sync(cfg, policy)
	if err != nil {
		t.Fatalf("sync after key update failed: %v", err)
	}
	if !result.Synced {
		t.Fatal("expected sync to succeed after both files match")
	}
}

func integrationPolicy(t *testing.T, sourceDir, targetDir string) *config.PathPolicy {
	t.Helper()
	policy, err := config.NewPathPolicy([]string{sourceDir}, []string{targetDir})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func writeSource(t *testing.T, dir string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "certchain0.pem"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key0.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}
