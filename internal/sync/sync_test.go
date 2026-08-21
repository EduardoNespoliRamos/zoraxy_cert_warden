package sync

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

func TestSyncNoChangesRequiresCompleteValidDestination(t *testing.T) {
	sourceCert, sourceKey, alternateChain := generatePairWithAlternateChain(t)
	_, wrongKey, err := certutil.GenerateTestCertificateNow("wrong.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(t *testing.T, certPath, keyPath string)
	}{
		{name: "missing key", mutate: func(t *testing.T, _, keyPath string) { mustRemove(t, keyPath) }},
		{name: "corrupt key", mutate: func(t *testing.T, _, keyPath string) { mustWrite(t, keyPath, []byte("corrupt"), 0600) }},
		{name: "mismatched key", mutate: func(t *testing.T, _, keyPath string) { mustWrite(t, keyPath, wrongKey, 0600) }},
		{name: "changed chain with same leaf", mutate: func(t *testing.T, certPath, _ string) { mustWrite(t, certPath, alternateChain, 0644) }},
		{name: "truncated certificate", mutate: func(t *testing.T, certPath, _ string) { mustWrite(t, certPath, sourceCert[:len(sourceCert)/2], 0644) }},
		{name: "wrong certificate permissions", mutate: func(t *testing.T, certPath, _ string) { mustChmod(t, certPath, 0600) }},
		{name: "wrong key permissions", mutate: func(t *testing.T, _, keyPath string) { mustChmod(t, keyPath, 0644) }},
		{name: "certificate symlink", mutate: func(t *testing.T, certPath, _ string) {
			target := filepath.Join(t.TempDir(), "outside.pem")
			mustWrite(t, target, sourceCert, 0644)
			mustRemove(t, certPath)
			if err := os.Symlink(target, certPath); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "key symlink", mutate: func(t *testing.T, _, keyPath string) {
			target := filepath.Join(t.TempDir(), "outside.key")
			mustWrite(t, target, sourceKey, 0600)
			mustRemove(t, keyPath)
			if err := os.Symlink(target, keyPath); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, policy, certPath, keyPath := syncFixture(t, sourceCert, sourceKey)
			tt.mutate(t, certPath, keyPath)
			_, result, err := Sync(cfg, policy)
			if err != nil {
				t.Fatalf("sync failed: %v", err)
			}
			if !result.Synced || result.NoChanges {
				t.Fatalf("invalid destination must be reinstalled: %+v", result)
			}
			assertPair(t, certPath, keyPath, sourceCert, sourceKey)
		})
	}
}

func TestSyncIdenticalValidDestinationReturnsNoChanges(t *testing.T) {
	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("sync.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg, policy, certPath, keyPath := syncFixture(t, certPEM, keyPEM)
	beforeCert, beforeKey := mustRead(t, certPath), mustRead(t, keyPath)

	_, result, err := Sync(cfg, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !result.NoChanges || result.Synced {
		t.Fatalf("expected NoChanges, got %+v", result)
	}
	if !bytes.Equal(beforeCert, mustRead(t, certPath)) || !bytes.Equal(beforeKey, mustRead(t, keyPath)) {
		t.Fatal("NoChanges modified destination files")
	}
}

func TestReplacePairNormalAndPartialOldStates(t *testing.T) {
	newCert, newKey, err := certutil.GenerateTestCertificateNow("new.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldCert, oldKey, err := certutil.GenerateTestCertificateNow("old.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	for _, state := range []string{"absent", "certificate-only", "key-only", "complete"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			policy := syncTestPolicy(t, dir, dir)
			certPath, keyPath := filepath.Join(dir, "test.pem"), filepath.Join(dir, "test.key")
			if state == "certificate-only" || state == "complete" {
				mustWrite(t, certPath, oldCert, 0644)
			}
			if state == "key-only" || state == "complete" {
				mustWrite(t, keyPath, oldKey, 0600)
			}
			if err := AtomicWrite(dir, "test", newCert, newKey, policy); err != nil {
				t.Fatal(err)
			}
			assertPair(t, certPath, keyPath, newCert, newKey)
			assertNoTransactionFiles(t, dir)
		})
	}
}

func TestReplacePairValidatesBeforeStaging(t *testing.T) {
	dir := t.TempDir()
	policy := syncTestPolicy(t, dir, dir)
	fsys := osFilesystem
	created := 0
	fsys.createTemp = func(dir, pattern string) (syncFile, error) {
		created++
		return osFilesystem.createTemp(dir, pattern)
	}
	err := replacePair(dir, "test", []byte("bad cert"), []byte("bad key"), "", policy, fsys)
	if err == nil || created != 0 {
		t.Fatalf("invalid source reached staging: err=%v creates=%d", err, created)
	}
}

func TestReplacePairFailuresRollback(t *testing.T) {
	oldCert, oldKey, err := certutil.GenerateTestCertificateNow("old.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey, err := certutil.GenerateTestCertificateNow("new.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newInfo, err := certutil.ValidatePEMPair(newCert, newKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		fault func(*filesystem, string)
	}{
		{name: "before rename", fault: func(fsys *filesystem, _ string) {
			calls := 0
			base := fsys.createTemp
			fsys.createTemp = func(dir, pattern string) (syncFile, error) {
				calls++
				if calls == 2 {
					return nil, errors.New("injected staging failure")
				}
				return base(dir, pattern)
			}
		}},
		{name: "first publish rename", fault: failRenameCall(3)},
		{name: "second publish rename", fault: failRenameCall(4)},
		{name: "post validation", fault: func(fsys *filesystem, certPath string) {
			base := fsys.readFile
			failed := false
			fsys.readFile = func(path string) ([]byte, error) {
				if path == certPath && !failed {
					failed = true
					return []byte("truncated"), nil
				}
				return base(path)
			}
		}},
		{name: "directory fsync after validation", fault: func(fsys *filesystem, _ string) {
			calls := 0
			base := fsys.syncDir
			fsys.syncDir = func(path string) error {
				calls++
				if calls == 1 {
					return errors.New("injected directory sync failure")
				}
				return base(path)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "test.pem"), filepath.Join(dir, "test.key")
			mustWrite(t, certPath, oldCert, 0644)
			mustWrite(t, keyPath, oldKey, 0600)
			policy := syncTestPolicy(t, dir, dir)
			fsys := osFilesystem
			tt.fault(&fsys, certPath)
			err := replacePair(dir, "test", newCert, newKey, newInfo.BundleDigest, policy, fsys)
			if err == nil {
				t.Fatal("expected injected failure")
			}
			assertPair(t, certPath, keyPath, oldCert, oldKey)
			assertNoTransactionFiles(t, dir)
			if tt.name != "before rename" && !strings.Contains(err.Error(), "certificate=restored") {
				t.Fatalf("missing known rollback states: %v", err)
			}
		})
	}
}

func TestReplacePairReportsPartialRollbackFailureAndRetainsBackup(t *testing.T) {
	oldCert, oldKey, err := certutil.GenerateTestCertificateNow("old.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey, err := certutil.GenerateTestCertificateNow("new.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newInfo, _ := certutil.ValidatePEMPair(newCert, newKey)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "test.pem"), filepath.Join(dir, "test.key")
	mustWrite(t, certPath, oldCert, 0644)
	mustWrite(t, keyPath, oldKey, 0600)
	policy := syncTestPolicy(t, dir, dir)

	fsys := osFilesystem
	baseRename := fsys.rename
	renames := 0
	fsys.rename = func(old, new string) error {
		renames++
		if renames == 4 {
			return errors.New("injected second publish failure")
		}
		if renames == 6 {
			return errors.New("injected key restore failure")
		}
		return baseRename(old, new)
	}
	err = replacePair(dir, "test", newCert, newKey, newInfo.BundleDigest, policy, fsys)
	if err == nil || !strings.Contains(err.Error(), "private key=unknown") || !strings.Contains(err.Error(), "injected key restore failure") {
		t.Fatalf("partial rollback was not fully reported: %v", err)
	}
	if !bytes.Equal(mustRead(t, certPath), oldCert) {
		t.Fatal("recoverable certificate was not restored")
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("key state should be known missing after failed restore: %v", statErr)
	}
	matches, globErr := filepath.Glob(filepath.Join(dir, ".test-key-backup-*.tmp"))
	if globErr != nil || len(matches) != 1 || !bytes.Equal(mustRead(t, matches[0]), oldKey) {
		t.Fatalf("key recovery backup not retained: matches=%v err=%v", matches, globErr)
	}
}

func TestReplacePairCleansStaleStagingAndSetsPermissions(t *testing.T) {
	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("sync.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, ".test-cert-sync-stale.tmp"), []byte("stale"), 0600)
	mustWrite(t, filepath.Join(dir, ".test-key-sync-stale.tmp"), []byte("stale"), 0600)
	policy := syncTestPolicy(t, dir, dir)
	if err := AtomicWrite(dir, "test", certPEM, keyPEM, policy); err != nil {
		t.Fatal(err)
	}
	assertPair(t, filepath.Join(dir, "test.pem"), filepath.Join(dir, "test.key"), certPEM, keyPEM)
	assertNoTransactionFiles(t, dir)
}

func TestAtomicWriteRejectsDestinationOutsidePolicy(t *testing.T) {
	allowed, outside := t.TempDir(), t.TempDir()
	policy := syncTestPolicy(t, allowed, allowed)
	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("sync.example.com", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(outside, "test", certPEM, keyPEM, policy); err == nil {
		t.Fatal("expected destination outside policy to be rejected")
	}
}

func TestEnsureFallback(t *testing.T) {
	dir := t.TempDir()
	policy := syncTestPolicy(t, dir, dir)
	desired := "homealone-wildcard"
	changed, err := EnsureFallback(dir, &desired, policy)
	if err != nil || !changed {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "fallback.json"))
	if err != nil {
		t.Fatal(err)
	}
	changed, err = EnsureFallback(dir, &desired, policy)
	if err != nil || changed {
		t.Fatalf("unchanged fallback was rewritten: changed=%v err=%v", changed, err)
	}
	infoAfter, err := os.Stat(filepath.Join(dir, "fallback.json"))
	if err != nil || !info.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatalf("fallback modification time changed: %v", err)
	}
	name, err := ReadFallback(dir, policy)
	if err != nil {
		t.Fatal(err)
	}
	if name != "homealone-wildcard" {
		t.Fatalf("unexpected fallback name: %s", name)
	}
	changed, err = EnsureFallback(dir, nil, policy)
	if err != nil || !changed {
		t.Fatalf("fallback was not removed: changed=%v err=%v", changed, err)
	}
	changed, err = EnsureFallback(dir, nil, policy)
	if err != nil || changed {
		t.Fatalf("missing fallback removal was not idempotent: changed=%v err=%v", changed, err)
	}
}

func TestEnsureFallbackReplacesInvalidFile(t *testing.T) {
	dir := t.TempDir()
	policy := syncTestPolicy(t, dir, dir)
	mustWrite(t, filepath.Join(dir, "fallback.json"), []byte("not-json"), 0644)
	desired := "replacement"
	changed, err := EnsureFallback(dir, &desired, policy)
	if err != nil || !changed {
		t.Fatalf("invalid fallback was not replaced: changed=%v err=%v", changed, err)
	}
	if got, err := ReadFallback(dir, policy); err != nil || got != desired {
		t.Fatalf("unexpected fallback: %q, %v", got, err)
	}
}

func TestEnsureFallbackRejectsSymlinkAndOutsidePolicy(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	policy := syncTestPolicy(t, dir, dir)
	target := filepath.Join(outside, "target.json")
	mustWrite(t, target, []byte(`{"fallbackCert":"old"}`), 0644)
	if err := os.Symlink(target, filepath.Join(dir, "fallback.json")); err != nil {
		t.Fatal(err)
	}
	desired := "new"
	if _, err := EnsureFallback(dir, &desired, policy); err == nil {
		t.Fatal("expected fallback symlink to be rejected")
	}
	if _, err := EnsureFallback(outside, &desired, policy); err == nil {
		t.Fatal("expected destination outside policy to be rejected")
	}
}

func failRenameCall(want int) func(*filesystem, string) {
	return func(fsys *filesystem, _ string) {
		base := fsys.rename
		calls := 0
		fsys.rename = func(old, new string) error {
			calls++
			if calls == want {
				return fmt.Errorf("injected rename failure %d", want)
			}
			return base(old, new)
		}
	}
}

func syncFixture(t *testing.T, certPEM, keyPEM []byte) (config.CertificateConfig, *config.PathPolicy, string, string) {
	t.Helper()
	sourceDir, destDir := t.TempDir(), t.TempDir()
	mustWrite(t, filepath.Join(sourceDir, "cert.pem"), certPEM, 0644)
	mustWrite(t, filepath.Join(sourceDir, "key.pem"), keyPEM, 0600)
	certPath, keyPath := filepath.Join(destDir, "test.pem"), filepath.Join(destDir, "test.key")
	mustWrite(t, certPath, certPEM, 0644)
	mustWrite(t, keyPath, keyPEM, 0600)
	policy := syncTestPolicy(t, sourceDir, destDir)
	cfg := config.CertificateConfig{
		Name: "test", Enabled: true,
		Source:      config.CertificateSource{Certificate: filepath.Join(sourceDir, "cert.pem"), PrivateKey: filepath.Join(sourceDir, "key.pem")},
		Destination: config.CertificateDestination{TargetDirectory: destDir, TargetName: "test"},
	}
	return cfg, policy, certPath, keyPath
}

func assertPair(t *testing.T, certPath, keyPath string, wantCert, wantKey []byte) {
	t.Helper()
	if got := mustRead(t, certPath); !bytes.Equal(got, wantCert) {
		t.Fatal("unexpected certificate content")
	}
	if got := mustRead(t, keyPath); !bytes.Equal(got, wantKey) {
		t.Fatal("unexpected private key content")
	}
	certStat, err := os.Lstat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyStat, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if certStat.Mode().Perm() != 0644 || keyStat.Mode().Perm() != 0600 {
		t.Fatalf("unexpected modes: certificate=%04o key=%04o", certStat.Mode().Perm(), keyStat.Mode().Perm())
	}
	if _, err := certutil.ValidatePEMPair(mustRead(t, certPath), mustRead(t, keyPath)); err != nil {
		t.Fatalf("invalid pair: %v", err)
	}
}

func assertNoTransactionFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".test-") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("transaction file was not cleaned: %s", entry.Name())
		}
	}
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
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

func generatePairWithAlternateChain(t *testing.T) (full, keyPEM, shorter []byte) {
	t.Helper()
	now := time.Now()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 1}
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "sync.example.com"}, DNSNames: []string{"sync.example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, intermediate, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	shorter = append(encode(leafDER), encode(intermediateDER)...)
	full = append(append([]byte(nil), shorter...), encode(rootDER)...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return full, keyPEM, shorter
}
