package config

import (
	"os"
	"path/filepath"
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
	if err := cfg.Validate(false); err != nil {
		t.Fatalf("expected valid config: %v", err)
	}
}

func TestCertificateConfig_Validate_InvalidName(t *testing.T) {
	cfg := DefaultConfig().Certificates[0]
	cfg.Name = "../../etc/passwd"
	if err := cfg.Validate(false); err == nil {
		t.Fatal("expected error for invalid name")
	}
}

func TestCertificateConfig_Validate_RelativePath(t *testing.T) {
	cfg := DefaultConfig().Certificates[0]
	cfg.Source.Certificate = "relative/path.pem"
	if err := cfg.Validate(false); err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := DefaultConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := Load(path)
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
	cfg, err := Load(path)
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
