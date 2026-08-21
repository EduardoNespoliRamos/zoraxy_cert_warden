package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	MinPollIntervalSeconds   = 1
	MaxPollIntervalSeconds   = 86400
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

// Normalize trims user-provided values and applies defaults.
func (c *CertificateConfig) Normalize() {
	if c == nil {
		return
	}
	c.Name = strings.TrimSpace(c.Name)
	c.Source.Certificate = strings.TrimSpace(c.Source.Certificate)
	c.Source.PrivateKey = strings.TrimSpace(c.Source.PrivateKey)
	c.Destination.TargetDirectory = strings.TrimSpace(c.Destination.TargetDirectory)
	c.Destination.TargetName = strings.TrimSpace(c.Destination.TargetName)
	if c.Sync.PollIntervalSeconds == 0 {
		c.Sync.PollIntervalSeconds = DefaultPollInterval
	}
}

// Validate checks a single certificate configuration against the path policy.
func (c *CertificateConfig) Validate(checkPaths bool, policy *PathPolicy) error {
	if c == nil {
		return fmt.Errorf("certificate configuration is required")
	}
	normalized := *c
	normalized.Normalize()
	_, err := normalized.validate(checkPaths, policy)
	return err
}

func (c *CertificateConfig) validate(checkPaths bool, policy *PathPolicy) (string, error) {
	if c == nil {
		return "", fmt.Errorf("certificate configuration is required")
	}
	if policy == nil {
		return "", fmt.Errorf("path policy is required")
	}
	if c.Name == "" {
		return "", fmt.Errorf("certificate name is required")
	}
	if !validNameRegex.MatchString(c.Name) {
		return "", fmt.Errorf("certificate name contains invalid characters")
	}

	if err := validatePath(c.Source.Certificate, "source certificate"); err != nil {
		return "", err
	}
	_, err := policy.ResolveSource(c.Source.Certificate, checkPaths)
	if err != nil {
		return "", fmt.Errorf("source certificate: %w", err)
	}
	if err := validatePath(c.Source.PrivateKey, "source private key"); err != nil {
		return "", err
	}
	_, err = policy.ResolveSource(c.Source.PrivateKey, checkPaths)
	if err != nil {
		return "", fmt.Errorf("source private key: %w", err)
	}

	if c.Destination.TargetDirectory == "" {
		return "", fmt.Errorf("target directory is required")
	}
	if !filepath.IsAbs(c.Destination.TargetDirectory) {
		return "", fmt.Errorf("target directory must be an absolute path")
	}
	if filepath.Clean(c.Destination.TargetDirectory) != c.Destination.TargetDirectory {
		return "", fmt.Errorf("target directory must be normalized")
	}
	resolvedDestination, err := policy.ResolveDestination(c.Destination.TargetDirectory, checkPaths)
	if err != nil {
		return "", fmt.Errorf("target directory: %w", err)
	}

	if c.Destination.TargetName == "" {
		return "", fmt.Errorf("target name is required")
	}
	if !validNameRegex.MatchString(c.Destination.TargetName) {
		return "", fmt.Errorf("target name contains invalid characters")
	}
	if c.Destination.TargetName != filepath.Base(c.Destination.TargetName) {
		return "", fmt.Errorf("target name must be a basename")
	}

	if c.Sync.PollIntervalSeconds < MinPollIntervalSeconds || c.Sync.PollIntervalSeconds > MaxPollIntervalSeconds {
		return "", fmt.Errorf("poll interval must be between %d and %d seconds", MinPollIntervalSeconds, MaxPollIntervalSeconds)
	}

	return resolvedDestination, nil
}

func validatePath(path, label string) error {
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
	return nil
}

// Validate checks the whole configuration against the path policy.
func (cfg *Config) Validate(checkPaths bool, policy *PathPolicy) error {
	if cfg == nil {
		return fmt.Errorf("configuration is required")
	}
	normalized := cfg.Clone()
	normalized.Normalize()
	return normalized.validate(checkPaths, policy)
}

func (cfg *Config) validate(checkPaths bool, policy *PathPolicy) error {
	if policy == nil {
		return fmt.Errorf("path policy is required")
	}
	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("unsupported log level: %q", cfg.LogLevel)
	}
	seenNames := make(map[string]bool, len(cfg.Certificates))
	type destinationKey struct {
		directory string
		name      string
	}
	seenDestinations := make(map[destinationKey]bool, len(cfg.Certificates))
	fallbackDirectories := make(map[string]bool)
	for i := range cfg.Certificates {
		cert := &cfg.Certificates[i]
		resolvedDestination, err := cert.validate(checkPaths, policy)
		if err != nil {
			return fmt.Errorf("certificate %d (%s): %w", i, cfg.Certificates[i].Name, err)
		}
		if seenNames[cert.Name] {
			return fmt.Errorf("duplicate certificate name: %s", cert.Name)
		}
		seenNames[cert.Name] = true

		destination := destinationKey{directory: resolvedDestination, name: cert.Destination.TargetName}
		if seenDestinations[destination] {
			return fmt.Errorf("duplicate destination: %s/%s", resolvedDestination, cert.Destination.TargetName)
		}
		seenDestinations[destination] = true
		if cert.Fallback {
			if fallbackDirectories[resolvedDestination] {
				return fmt.Errorf("multiple fallback certificates for destination directory: %s", resolvedDestination)
			}
			fallbackDirectories[resolvedDestination] = true
		}
	}
	return nil
}

// Normalize trims user-provided values and applies defaults.
func (cfg *Config) Normalize() {
	if cfg == nil {
		return
	}
	cfg.LogLevel = strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	for i := range cfg.Certificates {
		cfg.Certificates[i].Normalize()
	}
}

// Clone returns a deep copy of the configuration.
func (cfg *Config) Clone() *Config {
	if cfg == nil {
		return nil
	}
	clone := *cfg
	if cfg.Certificates != nil {
		clone.Certificates = append([]CertificateConfig(nil), cfg.Certificates...)
	}
	return &clone
}

// Load reads configuration from a JSON file. If the file does not exist, it
// returns the default configuration.
func Load(path string, policy *PathPolicy) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := DefaultConfig()
		if err := cfg.Validate(false, policy); err != nil {
			return nil, fmt.Errorf("default config is invalid: %w", err)
		}
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	cfg := &Config{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("failed to parse config: trailing JSON value")
		}
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	cfg.Normalize()
	if err := cfg.Validate(false, policy); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	return cfg, nil
}

// Save writes configuration durably without modifying the receiver.
func (cfg *Config) Save(path string, policy *PathPolicy) error {
	return NewStore(nil).Save(cfg, path, policy)
}
