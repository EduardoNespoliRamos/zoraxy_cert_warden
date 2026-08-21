package main

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	plugin "github.com/eduardoramos/zoraxy-cert-warden/mod/zoraxy_plugin"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
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

type manager struct {
	mu         sync.RWMutex // protects only active snapshots and runtime handles
	applyMu    sync.Mutex
	cfg        *config.Config
	states     map[string]*status.State
	watchers   map[string]managedWatcher
	generation uint64
	configPath string
	logger     *slog.Logger
	policy     *config.PathPolicy

	destinationMu    sync.Mutex
	destinationLocks map[string]*sync.Mutex
	defaultsOnce     sync.Once

	saveConfig          func(*config.Config, string, *config.PathPolicy) error
	watcherFactory      func([]string, time.Duration, time.Duration, bool, func(), *config.PathPolicy) (managedWatcher, error)
	syncFunc            func(config.CertificateConfig, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error)
	validateFunc        func(string, string) (*certutil.CertInfo, error)
	readDestinationFunc func(string, string, *config.PathPolicy) (*certutil.CertInfo, error)
}

type managedWatcher interface {
	Start() error
	Stop()
}

type configValidationError struct{ err error }

func (e configValidationError) Error() string       { return e.err.Error() }
func (e configValidationError) Unwrap() error       { return e.err }
func (e configValidationError) InvalidConfig() bool { return true }

func main() {
	runtimeCfg, err := plugin.ServeAndRecvSpec(pluginSpec())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to receive configure spec: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	execPath, err := os.Executable()
	if err != nil {
		logger.Error("failed to determine executable path", "error", err)
		os.Exit(1)
	}
	pluginDir := filepath.Dir(execPath)
	configPath := filepath.Join(pluginDir, "config.json")

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

	m := &manager{
		cfg:        &config.Config{LogLevel: "info"},
		states:     make(map[string]*status.State),
		watchers:   make(map[string]managedWatcher),
		configPath: configPath,
		logger:     logger,
		policy:     policy,
	}

	if err := m.ApplyConfig(context.Background(), cfg); err != nil {
		logger.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	server := web.NewServer(m)
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
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("http server error", "error", err)
		os.Exit(1)
	}
}

func pluginSpec() *plugin.IntroSpect {
	return &plugin.IntroSpect{
		ID:            pluginID,
		Name:          "Zoraxy Cert Warden Sync",
		Author:        "Eduardo Ramos",
		AuthorContact: "",
		Description:   "Synchronizes certificates from Cert Warden Client into Zoraxy TLS store.",
		URL:           "https://github.com/EduardoNespoliRamos/zoraxy_cert_warden",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  1,
		VersionMinor:  0,
		VersionPatch:  0,
		UIPath:        uiPath,
	}
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
		if m.watcherFactory == nil {
			m.watcherFactory = func(paths []string, poll, debounce time.Duration, fsnotify bool, callback func(), policy *config.PathPolicy) (managedWatcher, error) {
				return watcher.New(paths, poll, debounce, fsnotify, callback, policy)
			}
		}
		if m.syncFunc == nil {
			m.syncFunc = certSync.Sync
		}
		if m.validateFunc == nil {
			m.validateFunc = certutil.LoadAndValidate
		}
		if m.readDestinationFunc == nil {
			m.readDestinationFunc = certSync.ReadDestinationInfo
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
	return m.applyConfigLocked(ctx, candidate)
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
	return m.applyConfigLocked(ctx, candidate)
}

// ReloadConfig remains the non-HTTP compatibility entry point.
func (m *manager) ReloadConfig(cfg *config.Config) error {
	return m.ApplyConfig(context.Background(), cfg)
}

func (m *manager) applyConfigLocked(ctx context.Context, candidate *config.Config) error {
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
		return configValidationError{err: err}
	}

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
		watch, err := m.watcherFactory(
			[]string{certCfg.Source.Certificate, certCfg.Source.PrivateKey},
			time.Duration(certCfg.Sync.PollIntervalSeconds)*time.Second,
			2*time.Second, certCfg.Sync.FilesystemWatch,
			func() { _ = m.syncGeneration(name, generation) }, m.policy,
		)
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
	if err := m.saveConfig(staged, m.configPath, m.policy); err != nil {
		stopWatchers(newWatchers)
		return err
	}

	m.mu.Lock()
	oldWatchers := m.watchers
	m.cfg = staged
	m.states = newStates
	m.watchers = newWatchers
	m.generation = generation
	m.mu.Unlock()

	stopWatchers(oldWatchers)
	for _, certCfg := range staged.Certificates {
		if certCfg.Enabled {
			_ = m.syncGeneration(certCfg.Name, generation)
		}
	}
	return nil
}

func (m *manager) SyncCertificate(name string) error {
	m.mu.RLock()
	generation := m.generation
	m.mu.RUnlock()
	return m.syncGeneration(name, generation)
}

func (m *manager) syncGeneration(name string, generation uint64) error {
	m.defaults()
	m.mu.RLock()
	state, ok := m.states[name]
	activeGeneration := m.generation
	if !ok || activeGeneration != generation {
		m.mu.RUnlock()
		if !ok && activeGeneration == generation {
			return fmt.Errorf("certificate not found")
		}
		return nil
	}
	cfg := state.Config
	m.mu.RUnlock()

	destination, err := m.policy.ResolveDestination(cfg.Destination.TargetDirectory, false)
	if err != nil {
		m.recordSync(name, generation, nil, nil, time.Time{}, nil, err, false, err)
		return err
	}
	lock := m.destinationLock(filepath.Join(destination, cfg.Destination.TargetName))
	lock.Lock()
	defer lock.Unlock()
	if !m.isGenerationActive(name, generation) {
		return nil
	}

	info, result, syncErr := m.syncFunc(cfg, m.policy)
	var modified time.Time
	if sourcePath, resolveErr := m.policy.ResolveSource(cfg.Source.Certificate, true); resolveErr == nil {
		if fileInfo, statErr := os.Stat(sourcePath); statErr == nil {
			modified = fileInfo.ModTime()
		}
	}
	var destinationInfo *certutil.CertInfo
	var destinationErr error
	if info != nil {
		destinationInfo, destinationErr = m.readDestinationFunc(
			cfg.Destination.TargetDirectory, cfg.Destination.TargetName, m.policy,
		)
	}
	fallbackPending := false
	if syncErr == nil && cfg.Fallback {
		currentFallback, fallbackErr := certSync.ReadFallback(cfg.Destination.TargetDirectory, m.policy)
		fallbackPending = fallbackErr != nil || currentFallback != cfg.Destination.TargetName
	}
	m.recordSync(name, generation, info, result, modified, destinationInfo, destinationErr, fallbackPending, syncErr)
	if syncErr != nil {
		m.logger.Error("cert-sync failed", "certificate", name, "error", syncErr)
	}
	return syncErr
}

func (m *manager) recordSync(name string, generation uint64, info *certutil.CertInfo, result *certSync.Result, modified time.Time, destinationInfo *certutil.CertInfo, destinationErr error, fallbackPending bool, syncErr error) {
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
	state.FallbackPendingRestart = state.Config.Fallback && fallbackPending
}

func (m *manager) ValidateCertificate(name string) error {
	m.defaults()
	m.mu.RLock()
	state, ok := m.states[name]
	generation := m.generation
	if !ok {
		m.mu.RUnlock()
		return fmt.Errorf("certificate not found")
	}
	cfg := state.Config
	m.mu.RUnlock()

	certPath, err := m.policy.ResolveSource(cfg.Source.Certificate, true)
	if err == nil {
		var keyPath string
		keyPath, err = m.policy.ResolveSource(cfg.Source.PrivateKey, true)
		if err == nil {
			var info *certutil.CertInfo
			info, err = m.validateFunc(certPath, keyPath)
			m.recordValidation(name, generation, info, err)
			return err
		}
	}
	m.recordValidation(name, generation, nil, err)
	return err
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

func (m *manager) isGenerationActive(name string, generation uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.states[name]
	return ok && m.generation == generation
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
