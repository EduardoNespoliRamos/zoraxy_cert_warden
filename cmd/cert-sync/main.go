package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	plugin "github.com/eduardoramos/zoraxy-cert-warden/mod/zoraxy_plugin"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/certwarden"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/poller"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/secretstore"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
	certSync "github.com/eduardoramos/zoraxy-cert-warden/internal/sync"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/watcher"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/web"
)

const (
	pluginID = "com.eduardoramos.zoraxy.certwarden"
	uiPath   = "/ui"
	webRoot  = "/web"
)

//go:embed web/index.html
//go:embed web/js/app.js
//go:embed web/css/style.css
var content embed.FS

// Version is replaced with the release tag version at build time.
var Version = "dev"

type manager struct {
	mu          sync.RWMutex // protects only active snapshots and runtime handles
	applyMu     sync.Mutex
	cfg         *config.Config
	states      map[string]*status.State
	watchers    map[string]managedWatcher
	generation  uint64
	configPath  string
	secretsPath string
	secrets     secretstore.Data
	logger      *slog.Logger
	logLevel    *slog.LevelVar
	policy      *config.PathPolicy

	destinationMu    sync.Mutex
	destinationLocks map[string]*sync.Mutex
	defaultsOnce     sync.Once
	fallbackMu       sync.Mutex
	fallbackApplyMu  sync.RWMutex
	fallbackPending  map[string]bool
	runtimeLoaded    bool

	saveConfig          func(*config.Config, string, *config.PathPolicy) error
	saveSecrets         func(string, secretstore.Data) error
	watcherFactory      func([]string, time.Duration, time.Duration, bool, func(), *config.PathPolicy) (managedWatcher, error)
	pollerFactory       func(time.Duration, func(context.Context)) managedWatcher
	syncFunc            func(config.CertificateConfig, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error)
	syncMaterialFunc    func(config.CertificateConfig, []byte, []byte, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error)
	validateFunc        func(string, string) (*certutil.CertInfo, error)
	readDestinationFunc func(string, string, *config.PathPolicy) (*certutil.CertInfo, error)
	remoteClientFactory func(string, certwarden.Credentials) (remoteFetcher, error)
}

type remoteFetcher interface {
	Fetch(context.Context, string) (certwarden.Material, error)
}

type managedWatcher interface {
	Start() error
	Stop()
}

type configValidationError struct{ err error }

func (e configValidationError) Error() string       { return e.err.Error() }
func (e configValidationError) Unwrap() error       { return e.err }
func (e configValidationError) InvalidConfig() bool { return true }

type configConflictError struct{ err error }

func (e configConflictError) Error() string        { return e.err.Error() }
func (e configConflictError) Unwrap() error        { return e.err }
func (e configConflictError) ConfigConflict() bool { return true }

type certificateNotFoundError struct{ name string }

func (e certificateNotFoundError) Error() string {
	return fmt.Sprintf("certificate %q not found", e.name)
}
func (e certificateNotFoundError) NotFound() bool { return true }

type sourceValidationError struct{ err error }

func (e sourceValidationError) Error() string          { return e.err.Error() }
func (e sourceValidationError) Unwrap() error          { return e.err }
func (e sourceValidationError) SourceValidation() bool { return true }

func main() {
	runtimeCfg, err := plugin.ServeAndRecvSpec(pluginSpec())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to receive configure spec: %v\n", err)
		os.Exit(1)
	}

	logLevel := &slog.LevelVar{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	execPath, err := os.Executable()
	if err != nil {
		logger.Error("failed to determine executable path", "error", err)
		os.Exit(1)
	}
	pluginDir := filepath.Dir(execPath)
	configPath := filepath.Join(pluginDir, "config.json")
	secretsPath := filepath.Join(pluginDir, "secrets.json")

	policy, err := config.PathPolicyFromEnv()
	if err != nil {
		logger.Error("failed to initialize path policy", "error", err)
		os.Exit(1)
	}

	cfg, err := config.Load(configPath, policy)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	secrets, err := secretstore.Load(secretsPath)
	if err != nil {
		logger.Error("failed to load secrets", "error", err)
		os.Exit(1)
	}

	m := &manager{
		cfg:         &config.Config{LogLevel: "info"},
		states:      make(map[string]*status.State),
		watchers:    make(map[string]managedWatcher),
		configPath:  configPath,
		secretsPath: secretsPath,
		secrets:     secrets,
		logger:      logger,
		logLevel:    logLevel,
		policy:      policy,
	}

	if err := m.ApplyConfig(context.Background(), cfg); err != nil {
		logger.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	server := web.NewServer(m, logger)
	server.RegisterRoutes(mux, uiPath)

	embedWebRouter := plugin.NewPluginEmbedUIRouter(pluginID, &content, webRoot, uiPath)
	embedWebRouter.RegisterTerminateHandler(func() {
		logger.Info("plugin terminating")
		m.stopWatchers()
	}, mux)
	mux.Handle(uiPath+"/", embedWebRouter.Handler())

	// Also register API routes directly under uiPath so Zoraxy proxies them
	// together with the static UI. Zoraxy only forwards requests under the
	// plugin's declared UIPath.
	server.RegisterRoutesUnderPrefix(mux, uiPath)

	addr := "127.0.0.1:" + strconv.Itoa(runtimeCfg.Port)
	logger.Info("starting plugin", "addr", addr)
	if err := newHTTPServer(addr, server.Handler(mux)).ListenAndServe(); err != nil {
		logger.Error("http server error", "error", err)
		os.Exit(1)
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func pluginSpec() *plugin.IntroSpect {
	major, minor, patch := semanticVersion(Version)
	return &plugin.IntroSpect{
		ID:            pluginID,
		Name:          "Zoraxy Cert Warden Sync",
		Author:        "Eduardo Ramos",
		AuthorContact: "",
		Description:   "Synchronizes certificates from local files or Cert Warden into Zoraxy TLS store.",
		URL:           "https://github.com/EduardoNespoliRamos/zoraxy_cert_warden",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  major,
		VersionMinor:  minor,
		VersionPatch:  patch,
		UIPath:        uiPath,
	}
}

func semanticVersion(version string) (int, int, int) {
	version = strings.TrimPrefix(version, "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return 0, 0, 0
	}
	values := make([]int, 3)
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return 0, 0, 0
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return 0, 0, 0
		}
		values[i] = value
	}
	return values[0], values[1], values[2]
}

func (m *manager) defaults() {
	m.defaultsOnce.Do(func() {
		if m.logger == nil {
			m.logger = slog.Default()
		}
		if m.saveConfig == nil {
			m.saveConfig = func(cfg *config.Config, path string, policy *config.PathPolicy) error {
				return cfg.Save(path, policy)
			}
		}
		if m.saveSecrets == nil {
			m.saveSecrets = secretstore.Save
		}
		if m.watcherFactory == nil {
			m.watcherFactory = func(paths []string, poll, debounce time.Duration, fsnotify bool, callback func(), policy *config.PathPolicy) (managedWatcher, error) {
				return watcher.New(paths, poll, debounce, fsnotify, callback, policy)
			}
		}
		if m.pollerFactory == nil {
			m.pollerFactory = func(interval time.Duration, callback func(context.Context)) managedWatcher {
				return poller.New(interval, callback)
			}
		}
		if m.syncFunc == nil {
			m.syncFunc = certSync.Sync
		}
		if m.syncMaterialFunc == nil {
			m.syncMaterialFunc = certSync.SyncMaterial
		}
		if m.validateFunc == nil {
			m.validateFunc = certutil.LoadAndValidate
		}
		if m.readDestinationFunc == nil {
			m.readDestinationFunc = certSync.ReadDestinationInfo
		}
		if m.remoteClientFactory == nil {
			m.remoteClientFactory = func(baseURL string, credentials certwarden.Credentials) (remoteFetcher, error) {
				return certwarden.NewClient(baseURL, credentials, nil)
			}
		}
	})
}

// SnapshotConfig returns a deep copy detached from manager-owned memory.
func (m *manager) SnapshotConfig() *config.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return &config.Config{}
	}
	return m.cfg.Clone()
}

// SnapshotStatus returns immutable status values in certificate-name order.
func (m *manager) SnapshotStatus() []status.CertificateStatus {
	m.mu.RLock()
	items := make([]status.CertificateStatus, 0, len(m.states))
	for _, state := range m.states {
		items = append(items, state.ToCertificateStatus())
	}
	m.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

// ApplyConfig serializes preparation, persistence, and activation. No active
// state changes until every new watcher has started and persistence succeeds.
func (m *manager) ApplyConfig(ctx context.Context, candidate *config.Config) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	return m.applyConfigAndSecretsLocked(ctx, candidate, m.currentSecrets())
}

// MutateConfig creates its candidate after entering the apply serialization,
// preventing read-modify-write updates from losing concurrent changes.
func (m *manager) MutateConfig(ctx context.Context, mutation web.ConfigMutation) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate := m.SnapshotConfig()
	if err := mutation(candidate); err != nil {
		return err
	}
	return m.applyConfigAndSecretsLocked(ctx, candidate, m.currentSecrets())
}

func (m *manager) MutateConfigAndCredentials(ctx context.Context, mutation web.ConfigMutation, credentialMutation *web.CredentialMutation) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	candidate := m.SnapshotConfig()
	if err := mutation(candidate); err != nil {
		return err
	}
	oldSecrets := m.currentSecrets()
	nextSecrets := oldSecrets.Clone()
	if credentialMutation != nil {
		if credentialMutation.Delete {
			delete(nextSecrets, credentialMutation.Name)
		} else if credentialMutation.CertificateAPIKey != nil || credentialMutation.PrivateKeyAPIKey != nil {
			if credentialMutation.CertificateAPIKey == nil || credentialMutation.PrivateKeyAPIKey == nil {
				return configValidationError{err: fmt.Errorf("both Cert Warden API keys are required")}
			}
			certKey := strings.TrimSpace(*credentialMutation.CertificateAPIKey)
			privateKey := strings.TrimSpace(*credentialMutation.PrivateKeyAPIKey)
			if certKey == "" && privateKey == "" {
				if _, ok := nextSecrets.Get(credentialMutation.Name); !ok {
					return configValidationError{err: fmt.Errorf("remote API credentials are required")}
				}
			} else {
				if certKey == "" || privateKey == "" {
					return configValidationError{err: fmt.Errorf("both Cert Warden API keys are required")}
				}
				serverURL, certificateName, ok := remoteIdentity(candidate, credentialMutation.Name)
				if !ok {
					return configValidationError{err: fmt.Errorf("remote source settings are required")}
				}
				nextSecrets[credentialMutation.Name] = secretstore.Credentials{
					CertificateAPIKey: certKey,
					PrivateKeyAPIKey:  privateKey,
					ServerURL:         serverURL,
					CertificateName:   certificateName,
				}
			}
		}
	}
	return m.applyConfigAndSecretsLocked(ctx, candidate, nextSecrets)
}

func remoteIdentity(cfg *config.Config, name string) (string, string, bool) {
	if cfg == nil {
		return "", "", false
	}
	for _, certCfg := range cfg.Certificates {
		if certCfg.Name == name && certCfg.Source.Type == config.SourceTypeCertWarden && certCfg.Source.CertWarden != nil {
			return certCfg.Source.CertWarden.ServerURL, certCfg.Source.CertWarden.CertificateName, true
		}
	}
	return "", "", false
}

func (m *manager) CredentialsConfigured(name string) (bool, bool) {
	credentials, ok := m.credentialsFor(name)
	if !ok {
		return false, false
	}
	return credentials.CertificateAPIKey != "", credentials.PrivateKeyAPIKey != ""
}

func (m *manager) credentialsFor(name string) (secretstore.Credentials, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.secrets.Get(name)
}

func (m *manager) currentSecrets() secretstore.Data {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.secrets.Clone()
}

func validateRemoteCredentials(cfg *config.Config, secrets secretstore.Data) error {
	if cfg == nil {
		return fmt.Errorf("configuration is required")
	}
	for _, certCfg := range cfg.Certificates {
		if certCfg.Source.Type != config.SourceTypeCertWarden {
			continue
		}
		credentials, ok := secrets.Get(certCfg.Name)
		if !ok || credentials.CertificateAPIKey == "" || credentials.PrivateKeyAPIKey == "" || certCfg.Source.CertWarden == nil ||
			credentials.ServerURL != certCfg.Source.CertWarden.ServerURL || credentials.CertificateName != certCfg.Source.CertWarden.CertificateName {
			return fmt.Errorf("certificate %s: Cert Warden API credentials are required", certCfg.Name)
		}
	}
	return nil
}

func pruneSecrets(cfg *config.Config, secrets secretstore.Data) secretstore.Data {
	pruned := make(secretstore.Data)
	if cfg == nil {
		return pruned
	}
	for _, certCfg := range cfg.Certificates {
		if certCfg.Source.Type == config.SourceTypeCertWarden {
			if credentials, ok := secrets.Get(certCfg.Name); ok {
				pruned[certCfg.Name] = credentials
			}
		}
	}
	return pruned
}

func secretsEqual(a, b secretstore.Data) bool {
	if len(a) != len(b) {
		return false
	}
	for name, credentials := range a {
		if other, ok := b.Get(name); !ok || other != credentials {
			return false
		}
	}
	return true
}

func (m *manager) applyConfigAndSecretsLocked(ctx context.Context, candidate *config.Config, requestedSecrets secretstore.Data) error {
	oldSecrets := m.currentSecrets()
	nextSecrets := pruneSecrets(candidate, requestedSecrets)
	if err := validateRemoteCredentials(candidate, nextSecrets); err != nil {
		return configValidationError{err: err}
	}
	secretsChanged := !secretsEqual(oldSecrets, nextSecrets)
	if secretsChanged {
		if err := m.saveSecrets(m.secretsPath, nextSecrets); err != nil {
			return fmt.Errorf("persist credentials: %w", err)
		}
	}
	if err := m.applyConfigLocked(ctx, candidate, nextSecrets); err != nil {
		if secretsChanged {
			return errors.Join(err, m.saveSecrets(m.secretsPath, oldSecrets))
		}
		return err
	}
	return nil
}

// ReloadConfig remains the non-HTTP compatibility entry point.
func (m *manager) ReloadConfig(cfg *config.Config) error {
	return m.ApplyConfig(context.Background(), cfg)
}

func (m *manager) applyConfigLocked(ctx context.Context, candidate *config.Config, stagedSecrets secretstore.Data) error {
	m.defaults()
	if err := ctx.Err(); err != nil {
		return err
	}
	staged := candidate.Clone()
	if staged == nil {
		return configValidationError{err: fmt.Errorf("configuration is required")}
	}
	staged.Normalize()
	if err := staged.Validate(false, m.policy); err != nil {
		if isConfigConflict(err) {
			return configConflictError{err: err}
		}
		return configValidationError{err: err}
	}
	if err := validateRemoteCredentials(staged, stagedSecrets); err != nil {
		return configValidationError{err: err}
	}
	if err := m.loadRuntimeState(); err != nil {
		return err
	}
	oldConfig := m.SnapshotConfig()

	m.mu.RLock()
	generation := m.generation + 1
	m.mu.RUnlock()
	newStates := make(map[string]*status.State, len(staged.Certificates))
	newWatchers := make(map[string]managedWatcher)
	for _, certCfg := range staged.Certificates {
		newStates[certCfg.Name] = &status.State{Config: certCfg}
		if !certCfg.Enabled || !certCfg.Sync.AutoSync {
			continue
		}
		name := certCfg.Name
		var watch managedWatcher
		var err error
		if certCfg.Source.Type == config.SourceTypeCertWarden {
			watch = m.pollerFactory(
				time.Duration(certCfg.Sync.PollIntervalSeconds)*time.Second,
				func(ctx context.Context) { _ = m.syncGenerationContext(ctx, name, generation) },
			)
		} else {
			watch, err = m.watcherFactory(
				[]string{certCfg.Source.Certificate, certCfg.Source.PrivateKey},
				time.Duration(certCfg.Sync.PollIntervalSeconds)*time.Second,
				2*time.Second, certCfg.Sync.FilesystemWatch,
				func() { _ = m.syncGeneration(name, generation) }, m.policy,
			)
		}
		if err != nil {
			stopWatchers(newWatchers)
			return err
		}
		newWatchers[name] = watch
	}

	for _, watch := range newWatchers {
		if err := watch.Start(); err != nil {
			stopWatchers(newWatchers)
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		stopWatchers(newWatchers)
		return err
	}
	m.fallbackApplyMu.Lock()
	changedDestinations, err := m.reconcileFallbacks(oldConfig, staged)
	if err != nil {
		_, rollbackErr := m.reconcileFallbacks(staged, oldConfig)
		m.fallbackApplyMu.Unlock()
		stopWatchers(newWatchers)
		return errors.Join(err, rollbackErr)
	}
	if err := m.saveConfig(staged, m.configPath, m.policy); err != nil {
		_, rollbackErr := m.reconcileFallbacks(staged, oldConfig)
		m.fallbackApplyMu.Unlock()
		stopWatchers(newWatchers)
		return errors.Join(err, rollbackErr)
	}
	if pendingErr := m.markFallbackPending(changedDestinations...); pendingErr != nil {
		configRollbackErr := m.saveConfig(oldConfig, m.configPath, m.policy)
		_, fallbackRollbackErr := m.reconcileFallbacks(staged, oldConfig)
		m.fallbackApplyMu.Unlock()
		stopWatchers(newWatchers)
		return errors.Join(pendingErr, configRollbackErr, fallbackRollbackErr)
	}
	for _, state := range newStates {
		if state.Config.Fallback {
			destination, resolveErr := m.policy.ResolveDestination(state.Config.Destination.TargetDirectory, false)
			state.FallbackPendingRestart = resolveErr == nil && m.fallbackPendingFor(destination)
		}
	}

	m.mu.Lock()
	oldWatchers := m.watchers
	m.cfg = staged
	m.secrets = stagedSecrets.Clone()
	m.states = newStates
	m.watchers = newWatchers
	m.generation = generation
	m.setLogLevel(staged.LogLevel)
	m.mu.Unlock()
	m.fallbackApplyMu.Unlock()

	stopWatchers(oldWatchers)
	for _, certCfg := range staged.Certificates {
		if certCfg.Enabled {
			_ = m.syncGeneration(certCfg.Name, generation)
		}
	}
	return nil
}

func (m *manager) setLogLevel(level string) {
	if m.logLevel == nil {
		return
	}
	switch level {
	case "debug":
		m.logLevel.Set(slog.LevelDebug)
	case "warn":
		m.logLevel.Set(slog.LevelWarn)
	case "error":
		m.logLevel.Set(slog.LevelError)
	default:
		m.logLevel.Set(slog.LevelInfo)
	}
}

func isConfigConflict(err error) bool {
	message := err.Error()
	return strings.Contains(message, "duplicate certificate name:") ||
		strings.Contains(message, "duplicate destination:") ||
		strings.Contains(message, "multiple fallback certificates for destination directory:")
}

func (m *manager) SyncCertificate(name string) error {
	m.mu.RLock()
	generation := m.generation
	m.mu.RUnlock()
	return m.syncGenerationContext(context.Background(), name, generation)
}

func (m *manager) syncGeneration(name string, generation uint64) error {
	return m.syncGenerationContext(context.Background(), name, generation)
}

func (m *manager) syncGenerationContext(ctx context.Context, name string, generation uint64) error {
	m.defaults()
	m.mu.RLock()
	state, ok := m.states[name]
	activeGeneration := m.generation
	if !ok || activeGeneration != generation {
		m.mu.RUnlock()
		if !ok && activeGeneration == generation {
			return certificateNotFoundError{name: name}
		}
		return nil
	}
	cfg := state.Config
	m.mu.RUnlock()
	if cfg.Fallback {
		m.fallbackApplyMu.RLock()
		defer m.fallbackApplyMu.RUnlock()
	}

	destination, err := m.policy.ResolveDestination(cfg.Destination.TargetDirectory, false)
	if err != nil {
		m.recordSync(name, generation, nil, nil, time.Time{}, nil, err, "", err)
		return err
	}
	lock := m.destinationLock(filepath.Join(destination, cfg.Destination.TargetName))
	lock.Lock()
	defer lock.Unlock()
	var info *certutil.CertInfo
	var result *certSync.Result
	var syncErr error
	var modified time.Time
	var material certwarden.Material
	if cfg.Source.Type == config.SourceTypeCertWarden {
		var fetchErr error
		material, fetchErr = m.fetchRemote(ctx, name, generation, cfg)
		if fetchErr != nil {
			m.logger.Error("Cert Warden query failed", "certificate", name, "error", fetchErr)
			return fetchErr
		}
	}

	// Keep configuration activation from overtaking publication by an operation
	// that started under the previous generation.
	m.mu.RLock()
	_, stillActive := m.states[name]
	if !stillActive || m.generation != generation {
		m.mu.RUnlock()
		return nil
	}
	if cfg.Source.Type == config.SourceTypeCertWarden {
		modified = material.RetrievedAt
		info, result, syncErr = m.syncMaterialFunc(cfg, material.CertificatePEM, material.PrivateKeyPEM, m.policy)
	} else {
		info, result, syncErr = m.syncFunc(cfg, m.policy)
	}
	if syncErr != nil && info == nil && !isFilesystemError(syncErr) {
		syncErr = sourceValidationError{err: syncErr}
	}
	if cfg.Source.Type == config.SourceTypeLocal {
		if sourcePath, resolveErr := m.policy.ResolveSource(cfg.Source.Certificate, true); resolveErr == nil {
			if fileInfo, statErr := os.Stat(sourcePath); statErr == nil {
				modified = fileInfo.ModTime()
			}
		}
	}
	var destinationInfo *certutil.CertInfo
	var destinationErr error
	if info != nil {
		destinationInfo, destinationErr = m.readDestinationFunc(
			cfg.Destination.TargetDirectory, cfg.Destination.TargetName, m.policy,
		)
	}
	if result != nil && result.FallbackChanged {
		if pendingErr := m.markFallbackPending(destination); pendingErr != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("persist fallback restart state: %w", pendingErr))
		}
	}
	m.mu.RUnlock()
	m.recordSync(name, generation, info, result, modified, destinationInfo, destinationErr, destination, syncErr)
	if syncErr != nil {
		m.logger.Error("cert-sync failed", "certificate", name, "error", syncErr)
	}
	return syncErr
}

func (m *manager) fetchRemote(ctx context.Context, name string, generation uint64, cfg config.CertificateConfig) (certwarden.Material, error) {
	m.mu.Lock()
	state, ok := m.states[name]
	if !ok || m.generation != generation {
		m.mu.Unlock()
		return certwarden.Material{}, context.Canceled
	}
	if state.CertWardenQuery == nil {
		state.CertWardenQuery = &status.CertWardenQueryStatus{Status: status.StatusUnknown}
	}
	state.CertWardenQuery.InProgress = true
	state.CertWardenQuery.Message = "Querying Cert Warden"
	credentials, credentialsOK := m.secrets.Get(name)
	m.mu.Unlock()

	if !credentialsOK {
		err := &certwarden.FetchError{Kind: certwarden.ErrorKindAuthentication}
		m.recordRemoteQuery(name, generation, certwarden.Material{}, err, cfg)
		return certwarden.Material{}, err
	}
	if cfg.Source.CertWarden == nil || credentials.ServerURL != cfg.Source.CertWarden.ServerURL || credentials.CertificateName != cfg.Source.CertWarden.CertificateName {
		err := &certwarden.FetchError{Kind: certwarden.ErrorKindAuthentication}
		m.recordRemoteQuery(name, generation, certwarden.Material{}, err, cfg)
		return certwarden.Material{}, err
	}
	client, err := m.remoteClientFactory(cfg.Source.CertWarden.ServerURL, certwarden.Credentials{
		CertificateAPIKey: credentials.CertificateAPIKey,
		PrivateKeyAPIKey:  credentials.PrivateKeyAPIKey,
	})
	if err != nil {
		m.recordRemoteQuery(name, generation, certwarden.Material{}, err, cfg)
		return certwarden.Material{}, err
	}
	material, err := client.Fetch(ctx, cfg.Source.CertWarden.CertificateName)
	m.recordRemoteQuery(name, generation, material, err, cfg)
	return material, err
}

func (m *manager) recordRemoteQuery(name string, generation uint64, material certwarden.Material, queryErr error, cfg config.CertificateConfig) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[name]
	if !ok || m.generation != generation {
		return
	}
	if state.CertWardenQuery == nil {
		state.CertWardenQuery = &status.CertWardenQueryStatus{}
	}
	query := state.CertWardenQuery
	query.InProgress = false
	query.LastAttempt = &now
	query.HTTPStatus = material.HTTPStatus
	query.LatencyMillis = material.Latency.Milliseconds()
	query.NextAttempt = nil
	if cfg.Sync.AutoSync {
		next := now.Add(time.Duration(cfg.Sync.PollIntervalSeconds) * time.Second)
		query.NextAttempt = &next
	}
	if queryErr == nil {
		query.Status = status.StatusHealthy
		query.LastSuccess = &now
		query.FailureKind = ""
		query.Message = "Certificate bundle downloaded"
		return
	}
	query.Status = status.StatusError
	query.Message = "Cert Warden query failed"
	var fetchErr *certwarden.FetchError
	if errors.As(queryErr, &fetchErr) {
		query.FailureKind = string(fetchErr.Kind)
		query.HTTPStatus = fetchErr.HTTPStatus
	}
}

func (m *manager) recordSync(name string, generation uint64, info *certutil.CertInfo, result *certSync.Result, modified time.Time, destinationInfo *certutil.CertInfo, destinationErr error, fallbackDestination string, syncErr error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[name]
	if !ok || m.generation != generation {
		return
	}
	state.LastAttemptedSync = &now
	state.LastSourceModification = modified
	state.SyncError = syncErr
	state.FallbackPendingRestart = state.Config.Fallback && fallbackDestination != "" && m.fallbackPendingFor(fallbackDestination)
	state.SourceInfo = info
	if info == nil {
		if destinationErr != nil {
			state.LastDestinationValidation = &now
			state.DestinationValidationError = destinationErr
			return
		}
		state.LastSourceValidation = &now
		state.SourceValidationError = syncErr
		return
	}
	state.LastSourceValidation = &now
	state.SourceValidationError = nil
	state.SourceFingerprint = info.Fingerprint
	state.SourceDigest = info.BundleDigest
	state.LastDestinationValidation = &now
	state.DestinationValidationError = destinationErr
	if destinationErr == nil {
		state.DestinationDigest = destinationInfo.BundleDigest
		state.DestinationFingerprint = destinationInfo.Fingerprint
	}
	if syncErr != nil || result == nil {
		return
	}
	state.LastSuccessfulSync = &now
	if state.DestinationDigest == "" {
		state.DestinationDigest = result.DestBundleDigest
	}
	if state.DestinationFingerprint == "" {
		state.DestinationFingerprint = result.DestFP
	}
}

type runtimeState struct {
	FallbackPendingRestart []string `json:"fallback_pending_restart"`
}

func (m *manager) runtimeStatePath() string {
	if m.configPath == "" {
		return ""
	}
	return m.configPath + ".runtime.json"
}

func (m *manager) loadRuntimeState() error {
	m.fallbackMu.Lock()
	defer m.fallbackMu.Unlock()
	if m.runtimeLoaded {
		return nil
	}
	m.fallbackPending = make(map[string]bool)
	path := m.runtimeStatePath()
	if path == "" {
		m.runtimeLoaded = true
		return nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		m.runtimeLoaded = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect runtime state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("runtime state must be a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runtime state: %w", err)
	}
	var persisted runtimeState
	if err := json.Unmarshal(data, &persisted); err != nil {
		return fmt.Errorf("parse runtime state: %w", err)
	}
	for _, destination := range persisted.FallbackPendingRestart {
		resolved, err := m.policy.ResolveDestination(destination, false)
		if err != nil || resolved != destination {
			return fmt.Errorf("invalid runtime fallback destination %q", destination)
		}
		m.fallbackPending[destination] = true
	}
	m.runtimeLoaded = true
	return nil
}

func (m *manager) saveRuntimeStateLocked(pending map[string]bool) error {
	path := m.runtimeStatePath()
	if path == "" {
		return nil
	}
	destinations := make([]string, 0, len(pending))
	for destination := range pending {
		destinations = append(destinations, destination)
	}
	sort.Strings(destinations)
	data, err := json.Marshal(runtimeState{FallbackPendingRestart: destinations})
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".runtime-state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	ok = true
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (m *manager) markFallbackPending(destinations ...string) error {
	if len(destinations) == 0 {
		return nil
	}
	m.fallbackMu.Lock()
	defer m.fallbackMu.Unlock()
	next := make(map[string]bool, len(m.fallbackPending)+len(destinations))
	for destination := range m.fallbackPending {
		next[destination] = true
	}
	for _, destination := range destinations {
		next[destination] = true
	}
	if err := m.saveRuntimeStateLocked(next); err != nil {
		return err
	}
	m.fallbackPending = next
	return nil
}

func (m *manager) fallbackPendingFor(destination string) bool {
	m.fallbackMu.Lock()
	defer m.fallbackMu.Unlock()
	return m.fallbackPending[destination]
}

func (m *manager) FallbackRestartPending() bool {
	m.fallbackMu.Lock()
	defer m.fallbackMu.Unlock()
	return len(m.fallbackPending) > 0
}

func (m *manager) AcknowledgeFallbackRestart(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.fallbackMu.Lock()
	if len(m.fallbackPending) == 0 {
		m.fallbackMu.Unlock()
		return nil
	}
	if err := m.saveRuntimeStateLocked(map[string]bool{}); err != nil {
		m.fallbackMu.Unlock()
		return err
	}
	m.fallbackPending = make(map[string]bool)
	m.fallbackMu.Unlock()
	m.mu.Lock()
	for _, state := range m.states {
		state.FallbackPendingRestart = false
	}
	m.mu.Unlock()
	return nil
}

func (m *manager) reconcileFallbacks(oldConfig, newConfig *config.Config) ([]string, error) {
	directories := make(map[string]bool)
	desired := make(map[string]string)
	for _, cfg := range []*config.Config{oldConfig, newConfig} {
		if cfg == nil {
			continue
		}
		for _, certificate := range cfg.Certificates {
			destination, err := m.policy.ResolveDestination(certificate.Destination.TargetDirectory, false)
			if err != nil {
				return nil, err
			}
			directories[destination] = true
		}
	}
	if newConfig != nil {
		for _, certificate := range newConfig.Certificates {
			if !certificate.Enabled || !certificate.Fallback {
				continue
			}
			destination, err := m.policy.ResolveDestination(certificate.Destination.TargetDirectory, false)
			if err != nil {
				return nil, err
			}
			desired[destination] = certificate.Destination.TargetName
		}
	}
	ordered := make([]string, 0, len(directories))
	for destination := range directories {
		ordered = append(ordered, destination)
	}
	sort.Strings(ordered)
	changed := make([]string, 0)
	for _, destination := range ordered {
		var wanted *string
		if name, ok := desired[destination]; ok {
			wanted = &name
		}
		wasChanged, err := certSync.EnsureFallback(destination, wanted, m.policy)
		if wasChanged {
			changed = append(changed, destination)
		}
		if err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func (m *manager) ValidateCertificate(name string) error {
	m.defaults()
	m.mu.RLock()
	state, ok := m.states[name]
	generation := m.generation
	if !ok {
		m.mu.RUnlock()
		return certificateNotFoundError{name: name}
	}
	cfg := state.Config
	m.mu.RUnlock()
	if cfg.Source.Type == config.SourceTypeCertWarden {
		material, err := m.fetchRemote(context.Background(), name, generation, cfg)
		if err != nil {
			return err
		}
		info, err := certutil.ValidatePEMPair(material.CertificatePEM, material.PrivateKeyPEM)
		if err != nil {
			err = sourceValidationError{err: err}
		}
		m.recordValidation(name, generation, info, err)
		return err
	}

	certPath, err := m.policy.ResolveSource(cfg.Source.Certificate, true)
	if err == nil {
		var keyPath string
		keyPath, err = m.policy.ResolveSource(cfg.Source.PrivateKey, true)
		if err == nil {
			var info *certutil.CertInfo
			info, err = m.validateFunc(certPath, keyPath)
			if err != nil && !isFilesystemError(err) {
				err = sourceValidationError{err: err}
			}
			m.recordValidation(name, generation, info, err)
			return err
		}
	}
	m.recordValidation(name, generation, nil, err)
	return err
}

func (m *manager) TestCertWardenConnection(ctx context.Context, serverURL, certificateName, certificateAPIKey, privateKeyAPIKey string) error {
	client, err := m.remoteClientFactory(strings.TrimSpace(serverURL), certwarden.Credentials{
		CertificateAPIKey: strings.TrimSpace(certificateAPIKey),
		PrivateKeyAPIKey:  strings.TrimSpace(privateKeyAPIKey),
	})
	if err != nil {
		return configValidationError{err: err}
	}
	material, err := client.Fetch(ctx, strings.TrimSpace(certificateName))
	if err != nil {
		return err
	}
	if _, err := certutil.ValidatePEMPair(material.CertificatePEM, material.PrivateKeyPEM); err != nil {
		return sourceValidationError{err: err}
	}
	return nil
}

func isFilesystemError(err error) bool {
	var pathErr *os.PathError
	return errors.As(err, &pathErr)
}

func (m *manager) recordValidation(name string, generation uint64, info *certutil.CertInfo, validationErr error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[name]
	if !ok || m.generation != generation {
		return
	}
	state.LastSourceValidation = &now
	state.SourceValidationError = validationErr
	state.SourceInfo = info
	if info != nil {
		state.SourceFingerprint = info.Fingerprint
		state.SourceDigest = info.BundleDigest
	}
}

func (m *manager) destinationLock(destination string) *sync.Mutex {
	m.destinationMu.Lock()
	defer m.destinationMu.Unlock()
	if m.destinationLocks == nil {
		m.destinationLocks = make(map[string]*sync.Mutex)
	}
	lock := m.destinationLocks[destination]
	if lock == nil {
		lock = &sync.Mutex{}
		m.destinationLocks[destination] = lock
	}
	return lock
}

func (m *manager) stopWatchers() {
	m.mu.Lock()
	oldWatchers := m.watchers
	m.watchers = make(map[string]managedWatcher)
	m.generation++
	m.mu.Unlock()
	stopWatchers(oldWatchers)
}

func stopWatchers(watchers map[string]managedWatcher) {
	for _, watch := range watchers {
		watch.Stop()
	}
}
