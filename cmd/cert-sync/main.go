package main

import (
	"embed"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
	mu         sync.RWMutex
	cfg        *config.Config
	states     map[string]*status.State
	watchers   map[string]*watcher.Watcher
	configPath string
	logger     *slog.Logger
	policy     *config.PathPolicy
}

func main() {
	runtimeCfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            pluginID,
		Name:          "Zoraxy Cert Warden Sync",
		Author:        "Eduardo Ramos",
		AuthorContact: "",
		Description:   "Synchronizes certificates from Cert Warden Client into Zoraxy TLS store.",
		URL:           "https://github.com/EduardoNespoliRamos/zoraxy_cert_warden",
		Type:          plugin.PluginType_Utilities,
		VersionMajor:  0,
		VersionMinor:  0,
		VersionPatch:  1,
		UIPath:        uiPath,
		PermittedAPIEndpoints: []plugin.PermittedAPIEndpoint{
			{Method: "GET", Endpoint: "/plugin.ui/com.eduardoramos.zoraxy.certwarden/api/status", Reason: "Read plugin status"},
			{Method: "GET", Endpoint: "/plugin.ui/com.eduardoramos.zoraxy.certwarden/api/config", Reason: "Read plugin config"},
			{Method: "POST", Endpoint: "/plugin.ui/com.eduardoramos.zoraxy.certwarden/api/config", Reason: "Update plugin config"},
			{Method: "GET", Endpoint: "/plugin.ui/com.eduardoramos.zoraxy.certwarden/api/certificates", Reason: "List certificates"},
			{Method: "POST", Endpoint: "/plugin.ui/com.eduardoramos.zoraxy.certwarden/api/certificates/*/validate", Reason: "Validate certificate"},
			{Method: "POST", Endpoint: "/plugin.ui/com.eduardoramos.zoraxy.certwarden/api/certificates/*/sync", Reason: "Sync certificate"},
			{Method: "POST", Endpoint: "/plugin.ui/com.eduardoramos.zoraxy.certwarden/api/certificates/*/toggle", Reason: "Toggle certificate"},
		},
	})
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
		cfg:        cfg,
		states:     make(map[string]*status.State),
		watchers:   make(map[string]*watcher.Watcher),
		configPath: configPath,
		logger:     logger,
		policy:     policy,
	}

	if err := m.ReloadConfig(cfg); err != nil {
		logger.Error("failed to initialize config", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	server := web.NewServer(cfg, m.states, m, configPath, policy)
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

func (m *manager) ReloadConfig(cfg *config.Config) error {
	stagedCfg := *cfg
	stagedCfg.Certificates = append([]config.CertificateConfig(nil), cfg.Certificates...)
	if err := stagedCfg.Validate(false, m.policy); err != nil {
		return err
	}
	cfg = &stagedCfg

	newStates := make(map[string]*status.State, len(cfg.Certificates))
	newWatchers := make(map[string]*watcher.Watcher)
	for _, certCfg := range cfg.Certificates {
		newStates[certCfg.Name] = &status.State{Config: certCfg}
		if !certCfg.Enabled || !certCfg.Sync.AutoSync {
			continue
		}
		paths := []string{certCfg.Source.Certificate, certCfg.Source.PrivateKey}
		poll := time.Duration(certCfg.Sync.PollIntervalSeconds) * time.Second
		if poll < time.Second {
			poll = time.Second
		}
		name := certCfg.Name
		w, err := watcher.New(paths, poll, 2*time.Second, certCfg.Sync.FilesystemWatch, func() {
			m.SyncCertificate(name)
		}, m.policy)
		if err != nil {
			return err
		}
		newWatchers[name] = w
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopWatchersLocked()
	m.cfg = cfg
	m.states = newStates
	m.watchers = newWatchers

	for _, certCfg := range cfg.Certificates {
		if certCfg.Enabled {
			m.syncOneLocked(certCfg.Name)
		}
		if w, ok := m.watchers[certCfg.Name]; ok {
			if err := w.Start(); err != nil {
				m.logger.Error("failed to start watcher", "certificate", certCfg.Name, "error", err)
			}
		}
	}
	return nil
}

func (m *manager) SyncCertificate(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncOneLocked(name)
}

func (m *manager) ValidateCertificate(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.states[name]
	if !ok {
		return fmt.Errorf("certificate not found")
	}
	now := time.Now()
	st.LastAttemptedSync = &now
	certPath, err := m.policy.ResolveSource(st.Config.Source.Certificate, true)
	if err != nil {
		st.LastError = err
		return err
	}
	keyPath, err := m.policy.ResolveSource(st.Config.Source.PrivateKey, true)
	if err != nil {
		st.LastError = err
		return err
	}
	certInfo, err := certutil.LoadAndValidate(certPath, keyPath)
	st.SourceInfo = certInfo
	if err != nil {
		st.LastError = err
		return err
	}
	st.LastError = nil
	return nil
}

func (m *manager) syncOneLocked(name string) error {
	st, ok := m.states[name]
	if !ok {
		return fmt.Errorf("certificate not found")
	}
	now := time.Now()
	st.LastAttemptedSync = &now

	certInfo, result, err := certSync.Sync(st.Config, m.policy)
	st.SourceInfo = certInfo

	var info os.FileInfo
	var errStat error
	if sourcePath, policyErr := m.policy.ResolveSource(st.Config.Source.Certificate, true); policyErr == nil {
		info, errStat = os.Stat(sourcePath)
	} else {
		errStat = policyErr
	}
	if errStat == nil {
		st.LastSourceModification = info.ModTime()
	}

	if err != nil {
		st.LastError = err
		m.logger.Error("cert-sync failed",
			"certificate", name,
			"error", err,
		)
		return err
	}

	st.LastError = nil
	if result.Synced {
		st.LastSuccessfulSync = &now
		st.DestinationFingerprint = result.SourceFP
		m.logger.Info("cert-sync success",
			"certificate", name,
			"fingerprint", result.SourceFP,
		)
	} else if result.NoChanges {
		destFP, _ := certSync.ReadDestinationFingerprint(st.Config.Destination.TargetDirectory, st.Config.Destination.TargetName, m.policy)
		st.DestinationFingerprint = destFP
		m.logger.Info("cert-sync no changes",
			"certificate", name,
		)
	}

	if st.Config.Fallback {
		currentFallback, _ := certSync.ReadFallback(st.Config.Destination.TargetDirectory, m.policy)
		st.FallbackPendingRestart = currentFallback != st.Config.Destination.TargetName
	} else {
		st.FallbackPendingRestart = false
	}

	return nil
}

func (m *manager) stopWatchers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopWatchersLocked()
}

func (m *manager) stopWatchersLocked() {
	for _, w := range m.watchers {
		w.Stop()
	}
	m.watchers = make(map[string]*watcher.Watcher)
}
