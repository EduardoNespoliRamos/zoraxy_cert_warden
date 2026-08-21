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

func TestCertificateConfigNormalizeSourceType(t *testing.T) {
	tests := []struct {
		name string
		got  SourceType
		want SourceType
	}{
		{name: "legacy missing type becomes local", want: SourceTypeLocal},
		{name: "explicit local remains local", got: SourceTypeLocal, want: SourceTypeLocal},
		{name: "explicit Cert Warden remains remote", got: SourceTypeCertWarden, want: SourceTypeCertWarden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig().Certificates[0]
			cfg.Source.Type = tt.got
			cfg.Normalize()
			if cfg.Source.Type != tt.want {
				t.Fatalf("Normalize() source type = %q, want %q", cfg.Source.Type, tt.want)
			}
		})
	}
}

func TestCertificateConfigValidateCertWardenHTTPSOrigins(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "hostname", url: "https://certwarden.example.com"},
		{name: "explicit port", url: "https://certwarden.example.com:8443"},
		{name: "root path", url: "https://certwarden.example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := certWardenTestCertificate()
			cfg.Source.CertWarden.ServerURL = tt.url
			if err := cfg.Validate(false, broadTestPolicy(t)); err != nil {
				t.Fatalf("Validate() rejected valid HTTPS origin %q: %v", tt.url, err)
			}
		})
	}
}

func TestCertificateConfigValidateRejectsInvalidCertWardenOrigins(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "HTTP", url: "http://certwarden.example.com"},
		{name: "userinfo", url: "https://user:pass@certwarden.example.com"},
		{name: "query", url: "https://certwarden.example.com?token=value"},
		{name: "empty query", url: "https://certwarden.example.com?"},
		{name: "fragment", url: "https://certwarden.example.com#section"},
		{name: "empty fragment", url: "https://certwarden.example.com#"},
		{name: "path", url: "https://certwarden.example.com/api"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := certWardenTestCertificate()
			cfg.Source.CertWarden.ServerURL = tt.url
			err := cfg.Validate(false, broadTestPolicy(t))
			if err == nil || !strings.Contains(err.Error(), "must be an HTTPS origin") {
				t.Fatalf("Validate() error = %v, want HTTPS origin error", err)
			}
		})
	}
}

func TestCertificateConfigValidateRequiresCertWardenSettings(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CertificateConfig)
		wantErr string
	}{
		{
			name: "settings",
			mutate: func(cfg *CertificateConfig) {
				cfg.Source.CertWarden = nil
			},
			wantErr: "source settings are required",
		},
		{
			name: "server URL",
			mutate: func(cfg *CertificateConfig) {
				cfg.Source.CertWarden.ServerURL = ""
			},
			wantErr: "must be an HTTPS origin",
		},
		{
			name: "certificate name",
			mutate: func(cfg *CertificateConfig) {
				cfg.Source.CertWarden.CertificateName = " "
			},
			wantErr: "certificate name is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := certWardenTestCertificate()
			tt.mutate(&cfg)
			err := cfg.Validate(false, broadTestPolicy(t))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCertificateConfigValidateRejectsMixedSourceFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*CertificateConfig)
		wantErr string
	}{
		{
			name: "local with Cert Warden settings",
			mutate: func(cfg *CertificateConfig) {
				local := DefaultConfig().Certificates[0]
				*cfg = local
				cfg.Source.Type = SourceTypeLocal
				cfg.Source.CertWarden = &CertWardenSource{ServerURL: "https://certwarden.example.com", CertificateName: "example"}
			},
			wantErr: "not allowed for a local source",
		},
		{
			name: "remote with certificate path",
			mutate: func(cfg *CertificateConfig) {
				cfg.Source.Certificate = "/source/cert.pem"
			},
			wantErr: "local file paths are not allowed",
		},
		{
			name: "remote with private key path",
			mutate: func(cfg *CertificateConfig) {
				cfg.Source.PrivateKey = "/source/key.pem"
			},
			wantErr: "local file paths are not allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := certWardenTestCertificate()
			tt.mutate(&cfg)
			err := cfg.Validate(false, broadTestPolicy(t))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestCertificateConfigValidateRejectsCertWardenFilesystemWatch(t *testing.T) {
	cfg := certWardenTestCertificate()
	cfg.Sync.FilesystemWatch = true
	if err := cfg.Validate(false, broadTestPolicy(t)); err == nil || !strings.Contains(err.Error(), "filesystem watch is not supported") {
		t.Fatalf("expected unsupported filesystem watch error, got %v", err)
	}
}

func TestCertificateConfigValidateCertWardenPollingBounds(t *testing.T) {
	tests := []struct {
		name           string
		seconds        int
		wantNormalized int
		wantErr        bool
	}{
		{name: "default", seconds: 0, wantNormalized: DefaultRemotePollInterval},
		{name: "below remote minimum", seconds: MinRemotePollIntervalSeconds - 1, wantNormalized: MinRemotePollIntervalSeconds - 1, wantErr: true},
		{name: "remote minimum", seconds: MinRemotePollIntervalSeconds, wantNormalized: MinRemotePollIntervalSeconds},
		{name: "maximum", seconds: MaxPollIntervalSeconds, wantNormalized: MaxPollIntervalSeconds},
		{name: "above maximum", seconds: MaxPollIntervalSeconds + 1, wantNormalized: MaxPollIntervalSeconds + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := certWardenTestCertificate()
			cfg.Sync.PollIntervalSeconds = tt.seconds
			cfg.Normalize()
			if cfg.Sync.PollIntervalSeconds != tt.wantNormalized {
				t.Fatalf("Normalize() poll interval = %d, want %d", cfg.Sync.PollIntervalSeconds, tt.wantNormalized)
			}
			err := cfg.Validate(false, broadTestPolicy(t))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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

func TestConfigCloneDeepCopiesCertWardenSource(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CertWardenSource)
	}{
		{
			name: "server URL",
			mutate: func(source *CertWardenSource) {
				source.ServerURL = "https://changed.example.com"
			},
		},
		{
			name: "certificate name",
			mutate: func(source *CertWardenSource) {
				source.CertificateName = "changed"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := certWardenTestCertificate()
			original := &Config{LogLevel: "info", Certificates: []CertificateConfig{cert}}
			want := *original.Certificates[0].Source.CertWarden
			clone := original.Clone()

			if clone.Certificates[0].Source.CertWarden == original.Certificates[0].Source.CertWarden {
				t.Fatal("Clone() shares its Cert Warden source pointer with the original")
			}
			tt.mutate(clone.Certificates[0].Source.CertWarden)
			if got := *original.Certificates[0].Source.CertWarden; got != want {
				t.Fatalf("mutating clone changed original source: got %#v, want %#v", got, want)
			}
		})
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

func TestLoadSaveSourceSchemaMigrationAndRoundTrip(t *testing.T) {
	tests := []struct {
		name                string
		data                string
		wantType            SourceType
		wantPoll            int
		wantCertWarden      *CertWardenSource
		wantSavedSourceType string
	}{
		{
			name: "legacy local source",
			data: `{
  "certificates": [{
    "name": "legacy",
    "enabled": true,
    "source": {
      "certificate": "/source/cert.pem",
      "private_key": "/source/key.pem"
    },
    "destination": {
      "target_directory": "/destination",
      "target_name": "legacy"
    },
    "sync": {
      "auto_sync": true,
      "filesystem_watch": true,
      "poll_interval_seconds": 10
    },
    "fallback": false
  }],
  "log_level": "info"
}`,
			wantType:            SourceTypeLocal,
			wantPoll:            DefaultPollInterval,
			wantSavedSourceType: `"type": "local"`,
		},
		{
			name: "Cert Warden source",
			data: `{
  "certificates": [{
    "name": "remote",
    "enabled": true,
    "source": {
      "type": "cert_warden",
      "cert_warden": {
        "server_url": "https://certwarden.example.com:8443",
        "certificate_name": "example.com"
      }
    },
    "destination": {
      "target_directory": "/destination",
      "target_name": "remote"
    },
    "sync": {
      "auto_sync": true,
      "filesystem_watch": false,
      "poll_interval_seconds": 0
    },
    "fallback": false
  }],
  "log_level": "info"
}`,
			wantType: SourceTypeCertWarden,
			wantPoll: DefaultRemotePollInterval,
			wantCertWarden: &CertWardenSource{
				ServerURL:       "https://certwarden.example.com:8443",
				CertificateName: "example.com",
			},
			wantSavedSourceType: `"type": "cert_warden"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			inputPath := filepath.Join(dir, "input.json")
			if err := os.WriteFile(inputPath, []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}

			loaded, err := Load(inputPath, broadTestPolicy(t))
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}
			source := loaded.Certificates[0].Source
			if source.Type != tt.wantType {
				t.Fatalf("Load() source type = %q, want %q", source.Type, tt.wantType)
			}
			if loaded.Certificates[0].Sync.PollIntervalSeconds != tt.wantPoll {
				t.Fatalf("Load() poll interval = %d, want %d", loaded.Certificates[0].Sync.PollIntervalSeconds, tt.wantPoll)
			}
			if !reflect.DeepEqual(source.CertWarden, tt.wantCertWarden) {
				t.Fatalf("Load() Cert Warden source = %#v, want %#v", source.CertWarden, tt.wantCertWarden)
			}

			savedPath := filepath.Join(dir, "saved.json")
			if err := loaded.Save(savedPath, broadTestPolicy(t)); err != nil {
				t.Fatalf("Save() failed: %v", err)
			}
			saved, err := os.ReadFile(savedPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(saved), tt.wantSavedSourceType) {
				t.Fatalf("saved JSON does not contain normalized source type %s:\n%s", tt.wantSavedSourceType, saved)
			}

			roundTripped, err := Load(savedPath, broadTestPolicy(t))
			if err != nil {
				t.Fatalf("round-trip Load() failed: %v", err)
			}
			if !reflect.DeepEqual(roundTripped, loaded) {
				t.Fatalf("round-trip mismatch:\n got: %#v\nwant: %#v", roundTripped, loaded)
			}
		})
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

func certWardenTestCertificate() CertificateConfig {
	cfg := DefaultConfig().Certificates[0]
	cfg.Source = CertificateSource{
		Type: SourceTypeCertWarden,
		CertWarden: &CertWardenSource{
			ServerURL:       "https://certwarden.example.com",
			CertificateName: "example.com",
		},
	}
	cfg.Sync.FilesystemWatch = false
	cfg.Sync.PollIntervalSeconds = DefaultRemotePollInterval
	return cfg
}

func broadTestPolicy(t *testing.T) *PathPolicy {
	t.Helper()
	policy, err := NewPathPolicy([]string{"/"}, []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
