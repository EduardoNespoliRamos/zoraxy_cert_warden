package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

func TestConfigValidateAllowsEmptyCertificates(t *testing.T) {
	cfg := &Config{LogLevel: "info", Certificates: []CertificateConfig{}}
	if err := cfg.Validate(false, broadTestPolicy(t)); err != nil {
		t.Fatalf("expected empty certificate list to be valid: %v", err)
	}
}

func TestConfigCloneIsDeep(t *testing.T) {
	original := DefaultConfig()
	clone := original.Clone()

	clone.LogLevel = "debug"
	clone.Certificates[0].Name = "changed"
	clone.Certificates = append(clone.Certificates, CertificateConfig{Name: "another"})

	if original.LogLevel != "info" {
		t.Fatalf("clone changed original log level: %q", original.LogLevel)
	}
	if original.Certificates[0].Name == "changed" {
		t.Fatal("clone shares its certificate slice with the original")
	}
	if len(original.Certificates) != 1 {
		t.Fatalf("clone append changed original length: %d", len(original.Certificates))
	}
}

func TestConfigValidateDoesNotMutate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogLevel = " INFO "
	cfg.Certificates[0].Name = " example-certificate "
	cfg.Certificates[0].Source.Certificate = " " + cfg.Certificates[0].Source.Certificate + " "
	cfg.Certificates[0].Destination.TargetDirectory = " /tmp "
	cfg.Certificates[0].Sync.PollIntervalSeconds = 0
	want := cfg.Clone()

	if err := cfg.Validate(false, broadTestPolicy(t)); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Validate mutated config:\n got: %#v\nwant: %#v", cfg, want)
	}
}

func TestConfigSaveNormalizesCloneWithoutMutatingCaller(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.LogLevel = ""
	cfg.Certificates[0].Name = " example-certificate "
	cfg.Certificates[0].Source.Certificate = " " + cfg.Certificates[0].Source.Certificate + " "
	cfg.Certificates[0].Destination.TargetDirectory = " " + dir + " "
	cfg.Certificates[0].Sync.PollIntervalSeconds = 0
	want := cfg.Clone()

	path := filepath.Join(dir, "config.json")
	if err := cfg.Save(path, broadTestPolicy(t)); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Save mutated caller:\n got: %#v\nwant: %#v", cfg, want)
	}
	loaded, err := Load(path, broadTestPolicy(t))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.LogLevel != "info" || loaded.Certificates[0].Name != "example-certificate" {
		t.Fatalf("saved config was not normalized: %#v", loaded)
	}
	if loaded.Certificates[0].Sync.PollIntervalSeconds != DefaultPollInterval {
		t.Fatalf("unexpected normalized polling interval: %d", loaded.Certificates[0].Sync.PollIntervalSeconds)
	}
}

func TestConfigValidateRejectsDuplicateCanonicalDestination(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "destination")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Certificates[0].Destination.TargetDirectory = dir
	duplicate := cfg.Certificates[0]
	duplicate.Name = "duplicate"
	duplicate.Destination.TargetDirectory = alias
	cfg.Certificates = append(cfg.Certificates, duplicate)

	if err := cfg.Validate(false, broadTestPolicy(t)); err == nil || !strings.Contains(err.Error(), "duplicate destination") {
		t.Fatalf("expected duplicate canonical destination error, got %v", err)
	}
}

func TestConfigValidateRejectsDuplicateNames(t *testing.T) {
	cfg := DefaultConfig()
	duplicate := cfg.Certificates[0]
	duplicate.Destination.TargetName = "different-target"
	cfg.Certificates = append(cfg.Certificates, duplicate)

	if err := cfg.Validate(false, broadTestPolicy(t)); err == nil || !strings.Contains(err.Error(), "duplicate certificate name") {
		t.Fatalf("expected duplicate certificate name error, got %v", err)
	}
}

func TestConfigValidateRejectsDuplicateFallbackDirectory(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "destination")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Certificates[0].Destination.TargetDirectory = dir
	cfg.Certificates[0].Fallback = true
	duplicate := cfg.Certificates[0]
	duplicate.Name = "second-fallback"
	duplicate.Destination.TargetDirectory = alias
	duplicate.Destination.TargetName = "different-target"
	cfg.Certificates = append(cfg.Certificates, duplicate)

	if err := cfg.Validate(false, broadTestPolicy(t)); err == nil || !strings.Contains(err.Error(), "fallback") {
		t.Fatalf("expected duplicate fallback directory error, got %v", err)
	}
}

func TestCertificateConfigValidatePollingBounds(t *testing.T) {
	tests := []struct {
		name    string
		seconds int
		wantErr bool
	}{
		{name: "default", seconds: 0},
		{name: "below minimum", seconds: -1, wantErr: true},
		{name: "minimum", seconds: MinPollIntervalSeconds},
		{name: "maximum", seconds: MaxPollIntervalSeconds},
		{name: "above maximum", seconds: MaxPollIntervalSeconds + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig().Certificates[0]
			cfg.Sync.PollIntervalSeconds = tt.seconds
			err := cfg.Validate(false, broadTestPolicy(t))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateLogLevel(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		cfg := &Config{LogLevel: level}
		if err := cfg.Validate(false, broadTestPolicy(t)); err != nil {
			t.Errorf("expected log level %q to be valid: %v", level, err)
		}
	}
	cfg := &Config{LogLevel: "trace"}
	if err := cfg.Validate(false, broadTestPolicy(t)); err == nil {
		t.Fatal("expected unsupported log level to be rejected")
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

func TestLoadRejectsUnknownFieldsAndTrailingValues(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "unknown field", data: `{"certificates":[],"log_level":"info","unknown":true}`},
		{name: "trailing object", data: `{"certificates":[],"log_level":"info"} {}`},
		{name: "trailing scalar", data: `{"certificates":[],"log_level":"info"} true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, broadTestPolicy(t)); err == nil {
				t.Fatal("expected strict JSON load to fail")
			}
		})
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
