package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	DefaultSourceCertificate = "/cert_warden_plugin/certchain0.pem"
	DefaultSourcePrivateKey  = "/cert_warden_plugin/key0.pem"
	DefaultTargetDirectory   = "/opt/zoraxy/config/conf/certs"
	DefaultPollInterval      = 10
)

// CertificateSource holds paths to the source certificate files.
type CertificateSource struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

// CertificateDestination holds the target location for synced files.
type CertificateDestination struct {
	TargetDirectory string `json:"target_directory"`
	TargetName      string `json:"target_name"`
}

// SyncConfig holds sync behavior settings.
type SyncConfig struct {
	AutoSync            bool `json:"auto_sync"`
	FilesystemWatch     bool `json:"filesystem_watch"`
	PollIntervalSeconds int  `json:"poll_interval_seconds"`
}

// CertificateConfig holds configuration for a single certificate sync.
type CertificateConfig struct {
	Name        string                 `json:"name"`
	Enabled     bool                   `json:"enabled"`
	Source      CertificateSource      `json:"source"`
	Destination CertificateDestination `json:"destination"`
	Sync        SyncConfig             `json:"sync"`
	Fallback    bool                   `json:"fallback"`
}

// Config holds the entire plugin configuration.
type Config struct {
	Certificates []CertificateConfig `json:"certificates"`
	LogLevel     string              `json:"log_level,omitempty"`
}

// DefaultConfig returns a configuration with one default certificate entry.
func DefaultConfig() *Config {
	return &Config{
		LogLevel: "info",
		Certificates: []CertificateConfig{
			{
				Name:    "homealone-wildcard",
				Enabled: true,
				Source: CertificateSource{
					Certificate: DefaultSourceCertificate,
					PrivateKey:  DefaultSourcePrivateKey,
				},
				Destination: CertificateDestination{
					TargetDirectory: DefaultTargetDirectory,
					TargetName:      "homealone-wildcard",
				},
				Sync: SyncConfig{
					AutoSync:            true,
					FilesystemWatch:     true,
					PollIntervalSeconds: DefaultPollInterval,
				},
				Fallback: false,
			},
		},
	}
}

var validNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// Validate checks a single certificate configuration.
func (c *CertificateConfig) Validate(checkPaths bool) error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return fmt.Errorf("certificate name is required")
	}
	if !validNameRegex.MatchString(c.Name) {
		return fmt.Errorf("certificate name contains invalid characters")
	}

	if err := validatePath(c.Source.Certificate, "source certificate", checkPaths, false); err != nil {
		return err
	}
	if err := validatePath(c.Source.PrivateKey, "source private key", checkPaths, false); err != nil {
		return err
	}

	c.Destination.TargetDirectory = strings.TrimSpace(c.Destination.TargetDirectory)
	if c.Destination.TargetDirectory == "" {
		return fmt.Errorf("target directory is required")
	}
	if !filepath.IsAbs(c.Destination.TargetDirectory) {
		return fmt.Errorf("target directory must be an absolute path")
	}
	if checkPaths {
		if info, err := os.Stat(c.Destination.TargetDirectory); err != nil {
			return fmt.Errorf("target directory is not accessible: %w", err)
		} else if !info.IsDir() {
			return fmt.Errorf("target directory is not a directory")
		}
	}

	c.Destination.TargetName = strings.TrimSpace(c.Destination.TargetName)
	if c.Destination.TargetName == "" {
		return fmt.Errorf("target name is required")
	}
	if !validNameRegex.MatchString(c.Destination.TargetName) {
		return fmt.Errorf("target name contains invalid characters")
	}
	if c.Destination.TargetName != filepath.Base(c.Destination.TargetName) {
		return fmt.Errorf("target name must be a basename")
	}

	if c.Sync.PollIntervalSeconds < 1 {
		c.Sync.PollIntervalSeconds = DefaultPollInterval
	}

	return nil
}

func validatePath(path, label string, checkExists, mustBeDir bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("%s path is required", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute", label)
	}
	clean := filepath.Clean(path)
	if clean != path {
		return fmt.Errorf("%s path must be normalized", label)
	}
	if checkExists {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%s path is not accessible: %w", label, err)
		}
		if mustBeDir && !info.IsDir() {
			return fmt.Errorf("%s path is not a directory", label)
		}
	}
	return nil
}

// Validate checks the whole configuration.
func (cfg *Config) Validate(checkPaths bool) error {
	if len(cfg.Certificates) == 0 {
		return fmt.Errorf("at least one certificate must be configured")
	}
	seen := map[string]bool{}
	for i := range cfg.Certificates {
		if err := cfg.Certificates[i].Validate(checkPaths); err != nil {
			return fmt.Errorf("certificate %d (%s): %w", i, cfg.Certificates[i].Name, err)
		}
		if seen[cfg.Certificates[i].Name] {
			return fmt.Errorf("duplicate certificate name: %s", cfg.Certificates[i].Name)
		}
		seen[cfg.Certificates[i].Name] = true
	}
	return nil
}

// Load reads configuration from a JSON file. If the file does not exist, it
// returns the default configuration.
func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	return cfg, nil
}

// Save writes configuration to a JSON file atomically.
func (cfg *Config) Save(path string) error {
	if err := cfg.Validate(false); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("failed to write config temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to rename config file: %w", err)
	}
	return nil
}
