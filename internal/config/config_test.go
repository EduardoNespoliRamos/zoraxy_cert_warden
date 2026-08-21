package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 default certificate, got %d", len(cfg.Certificates))
	}
	cert := cfg.Certificates[0]
	if cert.Source.Certificate != DefaultSourceCertificate {
		t.Errorf("unexpected default source cert: %s", cert.Source.Certificate)
	}
}

func TestCertificateConfig_Validate(t *testing.T) {
	cfg := DefaultConfig().Certificates[0]
	cfg.Destination.TargetDirectory = "/tmp"
	if err := cfg.Validate(false, broadTestPolicy(t)); err != nil {
		t.Fatalf("expected valid config: %v", err)
	}
}

func TestCertificateConfig_Validate_InvalidName(t *testing.T) {
	cfg := DefaultConfig().Certificates[0]
	cfg.Name = "../../etc/passwd"
	if err := cfg.Validate(false, broadTestPolicy(t)); err == nil {
		t.Fatal("expected error for invalid name")
	}
}

func TestCertificateConfig_Validate_RelativePath(t *testing.T) {
	cfg := DefaultConfig().Certificates[0]
	cfg.Source.Certificate = "relative/path.pem"
	if err := cfg.Validate(false, broadTestPolicy(t)); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	policy := broadTestPolicy(t)
	if err := cfg.Save(path, policy); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := Load(path, policy)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(loaded.Certificates) != 1 {
		t.Fatalf("expected 1 certificate after load, got %d", len(loaded.Certificates))
	}
	if loaded.Certificates[0].Name != cfg.Certificates[0].Name {
		t.Errorf("name mismatch")
	}
}

func TestLoad_DefaultWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")
	cfg, err := Load(path, broadTestPolicy(t))
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected default config")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("load should not create file")
	}
}

func TestPathPolicy(t *testing.T) {
	allowed := t.TempDir()
	sibling := allowed + "-other"
	if err := os.Mkdir(sibling, 0755); err != nil {
		t.Fatal(err)
	}
	policy, err := NewPathPolicy([]string{allowed}, []string{allowed})
	if err != nil {
		t.Fatal(err)
	}

	if err := policy.ValidateSource(filepath.Join(allowed, "cert.pem"), false); err != nil {
		t.Fatalf("expected allowed path: %v", err)
	}
	if err := policy.ValidateSource(filepath.Join(sibling, "cert.pem"), false); err == nil {
		t.Fatal("expected sibling prefix to be rejected")
	}
	traversal := allowed + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(sibling) + string(filepath.Separator) + "cert.pem"
	if err := policy.ValidateSource(traversal, false); err == nil {
		t.Fatal("expected non-normalized traversal path to be rejected")
	}
}

func TestPathPolicyRejectsUnsupportedCharacters(t *testing.T) {
	policy := broadTestPolicy(t)
	if err := policy.ValidateSource("/tmp/cert file.pem", false); err == nil {
		t.Fatal("expected path containing spaces to be rejected")
	}
}

func TestPathPolicyRejectsSymlinkEscape(t *testing.T) {
	allowed := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(allowed, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	policy, err := NewPathPolicy([]string{allowed}, []string{allowed})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateSource(filepath.Join(link, "cert.pem"), false); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestPathPolicyFromEnvSupportsMultipleRoots(t *testing.T) {
	sourceA := t.TempDir()
	sourceB := t.TempDir()
	destination := t.TempDir()
	t.Setenv(AllowedSourceRootsEnv, strings.Join([]string{sourceA, sourceB}, string(os.PathListSeparator)))
	t.Setenv(AllowedDestinationRootsEnv, destination)

	policy, err := PathPolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateSource(filepath.Join(sourceA, "a.pem"), false); err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateSource(filepath.Join(sourceB, "b.pem"), false); err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidateDestination(destination, true); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRejectsOutOfPolicyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data, err := json.Marshal(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := NewPathPolicy([]string{dir}, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, policy); err == nil {
		t.Fatal("expected out-of-policy config to be rejected")
	}
}

func broadTestPolicy(t *testing.T) *PathPolicy {
	t.Helper()
	policy, err := NewPathPolicy([]string{"/"}, []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
