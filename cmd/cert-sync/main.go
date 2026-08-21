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
	fallbackMu       sync.Mutex
	fallbackApplyMu  sync.RWMutex
	fallbackPending  map[string]bool
	runtimeLoaded    bool

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
	m.states = newStates
	m.watchers = newWatchers
	m.generation = generation
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
	if result != nil && result.FallbackChanged {
		if pendingErr := m.markFallbackPending(destination); pendingErr != nil {
			syncErr = errors.Join(syncErr, fmt.Errorf("persist fallback restart state: %w", pendingErr))
		}
	}
	m.recordSync(name, generation, info, result, modified, destinationInfo, destinationErr, destination, syncErr)
	if syncErr != nil {
		m.logger.Error("cert-sync failed", "certificate", name, "error", syncErr)
	}
	return syncErr
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
