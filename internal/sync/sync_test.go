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
	policy := syncTestPolicy(t, dir, dir)
	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("sync.example.com", time.Hour*24)
	if err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}

	if err := AtomicWrite(dir, "test", certPEM, keyPEM, policy); err != nil {
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
	policy := syncTestPolicy(t, sourceDir, dir)
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

	_, result, err := Sync(cfg, policy)
	if err != nil {
		t.Fatalf("first sync failed: %v", err)
	}
	if !result.Synced {
		t.Fatal("expected first sync to write files")
	}

	_, result, err = Sync(cfg, policy)
	if err != nil {
		t.Fatalf("second sync failed: %v", err)
	}
	if !result.NoChanges {
		t.Fatal("expected no changes on second sync")
	}
}

func TestWriteFallback(t *testing.T) {
	dir := t.TempDir()
	policy := syncTestPolicy(t, dir, dir)
	if err := WriteFallback(dir, "homealone-wildcard", policy); err != nil {
		t.Fatalf("write fallback failed: %v", err)
	}
	name, err := ReadFallback(dir, policy)
	if err != nil {
		t.Fatalf("read fallback failed: %v", err)
	}
	if name != "homealone-wildcard" {
		t.Errorf("unexpected fallback name: %s", name)
	}
}

func TestAtomicWriteRejectsDestinationOutsidePolicy(t *testing.T) {
	allowed := t.TempDir()
	outside := t.TempDir()
	policy := syncTestPolicy(t, allowed, allowed)
	if err := AtomicWrite(outside, "test", []byte("cert"), []byte("key"), policy); err == nil {
		t.Fatal("expected destination outside policy to be rejected")
	}
}

func TestAtomicWriteReplacesDestinationSymlinkWithoutFollowingIt(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.pem")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "test.pem")); err != nil {
		t.Fatal(err)
	}
	policy := syncTestPolicy(t, dir, dir)

	if err := AtomicWrite(dir, "test", []byte("certificate"), []byte("key"), policy); err != nil {
		t.Fatal(err)
	}
	outsideData, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(outsideData) != "unchanged" {
		t.Fatal("destination symlink target was modified")
	}
	info, err := os.Lstat(filepath.Join(dir, "test.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("destination symlink was not replaced")
	}
}

func TestReadDestinationFingerprintRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.pem")
	if err := os.WriteFile(outside, []byte("certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "test.pem")); err != nil {
		t.Fatal(err)
	}
	policy := syncTestPolicy(t, dir, dir)
	if _, err := ReadDestinationFingerprint(dir, "test", policy); err == nil {
		t.Fatal("expected destination symlink to be rejected")
	}
}

func syncTestPolicy(t *testing.T, sourceDir, destinationDir string) *config.PathPolicy {
	t.Helper()
	policy, err := config.NewPathPolicy([]string{sourceDir}, []string{destinationDir})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
