package sync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("sync.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}

	if err := AtomicWrite(dir, "test", certPEM, keyPEM); err != nil {
		t.Fatalf("atomic write failed: %v", err)
	}

	pemPath := filepath.Join(dir, "test.pem")
	keyPath := filepath.Join(dir, "test.key")
	if _, err := os.Stat(pemPath); err != nil {
		t.Fatalf("pem file not written: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file not written: %v", err)
	}

	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected key mode 0600, got %o", info.Mode().Perm())
	}
}

func TestSync_NoChanges(t *testing.T) {
	dir := t.TempDir()
	sourceDir := t.TempDir()
	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("sync.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(sourceDir, "cert.pem"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "key.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := config.CertificateConfig{
		Name:    "test",
		Enabled: true,
		Source: config.CertificateSource{
			Certificate: filepath.Join(sourceDir, "cert.pem"),
			PrivateKey:  filepath.Join(sourceDir, "key.pem"),
		},
		Destination: config.CertificateDestination{
			TargetDirectory: dir,
			TargetName:      "test",
		},
	}

	_, result, err := Sync(cfg)
	if err != nil {
		t.Fatalf("first sync failed: %v", err)
	}
	if !result.Synced {
		t.Fatal("expected first sync to write files")
	}

	_, result, err = Sync(cfg)
	if err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	if !result.NoChanges {
		t.Fatal("expected no changes on second sync")
	}
}

func TestWriteFallback(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFallback(dir, "homealone-wildcard"); err != nil {
		t.Fatalf("write fallback failed: %v", err)
	}
	name, err := ReadFallback(dir)
	if err != nil {
		t.Fatalf("read fallback failed: %v", err)
	}
	if name != "homealone-wildcard" {
		t.Errorf("unexpected fallback name: %s", name)
	}
}
