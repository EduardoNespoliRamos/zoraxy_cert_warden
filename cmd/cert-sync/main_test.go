package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
	certSync "github.com/eduardoramos/zoraxy-cert-warden/internal/sync"
)

func TestPluginSpecDoesNotRequestZoraxyAPIAccess(t *testing.T) {
	spec := pluginSpec()
	if len(spec.PermittedAPIEndpoints) != 0 {
		t.Fatalf("expected no permitted Zoraxy API endpoints, got %d", len(spec.PermittedAPIEndpoints))
	}
}

func TestPluginSpecUsesBuildVersion(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "1.2.3"

	spec := pluginSpec()
	if spec.VersionMajor != 1 || spec.VersionMinor != 2 || spec.VersionPatch != 3 {
		t.Fatalf("introspect version = %d.%d.%d, want 1.2.3", spec.VersionMajor, spec.VersionMinor, spec.VersionPatch)
	}
}

func TestSemanticVersion(t *testing.T) {
	for _, test := range []struct {
		version             string
		major, minor, patch int
	}{
		{version: "dev"},
		{version: "1.2"},
		{version: "1.2.3-rc1"},
		{version: "01.2.3"},
		{version: "v4.5.6", major: 4, minor: 5, patch: 6},
		{version: "10.20.30", major: 10, minor: 20, patch: 30},
	} {
		t.Run(test.version, func(t *testing.T) {
			major, minor, patch := semanticVersion(test.version)
			if major != test.major || minor != test.minor || patch != test.patch {
				t.Fatalf("semanticVersion(%q) = %d.%d.%d, want %d.%d.%d", test.version, major, minor, patch, test.major, test.minor, test.patch)
			}
		})
	}
}

func TestHTTPServerHasLoopbackBindAndTimeouts(t *testing.T) {
	handler := http.NewServeMux()
	server := newHTTPServer("127.0.0.1:12345", handler)
	if server.Addr != "127.0.0.1:12345" {
		t.Fatalf("server address = %q", server.Addr)
	}
	if server.Handler != handler {
		t.Fatal("server handler was not preserved")
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatalf("server timeouts must be positive: read-header=%s read=%s write=%s idle=%s",
			server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout)
	}
}

func TestManagerErrorMarkers(t *testing.T) {
	notFound := certificateNotFoundError{name: "missing"}
	var missing interface{ NotFound() bool }
	if !errors.As(notFound, &missing) || !missing.NotFound() {
		t.Fatal("certificate-not-found error lacks marker")
	}

	invalid := sourceValidationError{err: errors.New("invalid PEM")}
	var sourceInvalid interface{ SourceValidation() bool }
	if !errors.As(invalid, &sourceInvalid) || !sourceInvalid.SourceValidation() {
		t.Fatal("source-validation error lacks marker")
	}
}

func TestConfigConflictClassification(t *testing.T) {
	for _, message := range []string{
		"duplicate certificate name: cert",
		"duplicate destination: /destination/cert",
		"multiple fallback certificates for destination directory: /destination",
	} {
		if !isConfigConflict(errors.New(message)) {
			t.Fatalf("not classified as conflict: %s", message)
		}
	}
	if isConfigConflict(errors.New("certificate name is required")) {
		t.Fatal("invalid field was classified as conflict")
	}
}

type fakeWatcher struct {
	startErr error
	started  atomic.Bool
	stopped  atomic.Bool
	callback func()
	stop     func()
}

func (w *fakeWatcher) Start() error {
	w.started.Store(true)
	return w.startErr
}

func (w *fakeWatcher) Stop() {
	w.stopped.Store(true)
	if w.stop != nil {
		w.stop()
	}
}

func testPolicy(t *testing.T) (*config.PathPolicy, string, string) {
	t.Helper()
	source, destination := t.TempDir(), t.TempDir()
	policy, err := config.NewPathPolicy([]string{source}, []string{destination})
	if err != nil {
		t.Fatal(err)
	}
	return policy, source, destination
}

func testCertificate(name, source, destination string) config.CertificateConfig {
	return config.CertificateConfig{
		Name: name, Enabled: true,
		Source:      config.CertificateSource{Certificate: filepath.Join(source, name+".pem"), PrivateKey: filepath.Join(source, name+".key")},
		Destination: config.CertificateDestination{TargetDirectory: destination, TargetName: name},
		Sync:        config.SyncConfig{PollIntervalSeconds: 1},
	}
}

func inertManager(policy *config.PathPolicy) *manager {
	return &manager{
		cfg: &config.Config{LogLevel: "info"}, states: make(map[string]*status.State),
		watchers: make(map[string]managedWatcher), policy: policy,
		saveConfig: func(*config.Config, string, *config.PathPolicy) error { return nil },
		watcherFactory: func(_ []string, _, _ time.Duration, _ bool, callback func(), _ *config.PathPolicy) (managedWatcher, error) {
			return &fakeWatcher{callback: callback}, nil
		},
		syncFunc: func(config.CertificateConfig, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
			return &certutil.CertInfo{Fingerprint: "source"}, &certSync.Result{NoChanges: true, SourceFP: "source"}, nil
		},
		readDestinationFunc: func(string, string, *config.PathPolicy) (*certutil.CertInfo, error) {
			return &certutil.CertInfo{Fingerprint: "source", BundleDigest: "source-bundle"}, nil
		},
	}
}

func TestManagerSnapshotsAreDeepAndStatusIsSorted(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{
		testCertificate("b", source, destination), testCertificate("a", source, destination),
	}}
	m.states = map[string]*status.State{
		"b": {Config: m.cfg.Certificates[0]},
		"a": {Config: m.cfg.Certificates[1]},
	}

	snapshot := m.SnapshotConfig()
	snapshot.Certificates[0].Name = "changed"
	if m.SnapshotConfig().Certificates[0].Name != "b" {
		t.Fatal("config snapshot aliases active configuration")
	}
	items := m.SnapshotStatus()
	if len(items) != 2 || items[0].Name != "a" || items[1].Name != "b" {
		t.Fatalf("status snapshot is not deterministic: %+v", items)
	}
}

func TestApplyConfigUpdatesLogLevel(t *testing.T) {
	policy, _, _ := testPolicy(t)
	m := inertManager(policy)
	level := &slog.LevelVar{}
	m.logLevel = level

	if err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "debug"}); err != nil {
		t.Fatal(err)
	}
	if level.Level() != slog.LevelDebug {
		t.Fatalf("logger level = %s, want debug", level.Level())
	}
}

func TestApplyConfigFailedSaveLeavesRuntimeUnchanged(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	old := testCertificate("old", source, destination)
	oldWatcher := &fakeWatcher{}
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{old}}
	m.states = map[string]*status.State{"old": {Config: old}}
	m.watchers = map[string]managedWatcher{"old": oldWatcher}
	m.generation = 4
	m.saveConfig = func(*config.Config, string, *config.PathPolicy) error { return errors.New("disk full") }
	newCertificate := testCertificate("new", source, destination)
	newCertificate.Sync.AutoSync = true

	err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{newCertificate}})
	if err == nil {
		t.Fatal("expected save failure")
	}
	if got := m.SnapshotConfig().Certificates[0].Name; got != "old" {
		t.Fatalf("active config changed to %q", got)
	}
	if oldWatcher.stopped.Load() {
		t.Fatal("active watcher stopped after failed save")
	}
	if got := m.SnapshotStatus()[0].Name; got != "old" {
		t.Fatalf("active status changed to %q", got)
	}
}

func TestApplyConfigStartFailureLeavesRuntimeUnchanged(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	old := testCertificate("old", source, destination)
	oldWatcher := &fakeWatcher{}
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{old}}
	m.states = map[string]*status.State{"old": {Config: old}}
	m.watchers = map[string]managedWatcher{"old": oldWatcher}
	m.watcherFactory = func(_ []string, _, _ time.Duration, _ bool, callback func(), _ *config.PathPolicy) (managedWatcher, error) {
		return &fakeWatcher{startErr: errors.New("start failed"), callback: callback}, nil
	}

	newCertificate := testCertificate("new", source, destination)
	newCertificate.Sync.AutoSync = true
	if err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{newCertificate}}); err == nil {
		t.Fatal("expected watcher start failure")
	}
	if m.SnapshotConfig().Certificates[0].Name != "old" || oldWatcher.stopped.Load() {
		t.Fatal("old runtime changed after watcher start failure")
	}
}

func TestApplyEmptyConfigRemovesStaleStatus(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	old := testCertificate("old", source, destination)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{old}}
	m.states = map[string]*status.State{"old": {Config: old}}
	if err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info"}); err != nil {
		t.Fatal(err)
	}
	if len(m.SnapshotStatus()) != 0 || len(m.SnapshotConfig().Certificates) != 0 {
		t.Fatal("empty apply retained stale configuration or status")
	}
}

func TestSameDestinationSyncsAreSerialized(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	certificate := testCertificate("cert", source, destination)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
	m.states = map[string]*status.State{"cert": {Config: certificate}}
	m.generation = 1
	var active, maximum atomic.Int32
	m.syncFunc = func(config.CertificateConfig, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		current := active.Add(1)
		for current > maximum.Load() && !maximum.CompareAndSwap(maximum.Load(), current) {
		}
		time.Sleep(30 * time.Millisecond)
		active.Add(-1)
		return &certutil.CertInfo{Fingerprint: "fp"}, &certSync.Result{SourceFP: "fp"}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.SyncCertificate("cert") }()
	}
	wg.Wait()
	if maximum.Load() != 1 {
		t.Fatalf("same destination had %d concurrent syncs", maximum.Load())
	}
}

func TestDifferentDestinationSyncsRunInParallel(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	one, two := testCertificate("one", source, destination), testCertificate("two", source, destination)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{one, two}}
	m.states = map[string]*status.State{"one": {Config: one}, "two": {Config: two}}
	m.generation = 1
	entered, release := make(chan struct{}, 2), make(chan struct{})
	m.syncFunc = func(config.CertificateConfig, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		entered <- struct{}{}
		<-release
		return &certutil.CertInfo{Fingerprint: "fp"}, &certSync.Result{SourceFP: "fp"}, nil
	}
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = m.SyncCertificate("one") }()
		go func() { defer wg.Done(); _ = m.SyncCertificate("two") }()
		wg.Wait()
		close(done)
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("different destinations did not run concurrently")
		}
	}
	close(release)
	<-done
}

func TestOldGenerationCallbackIsIgnored(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	var watchers []*fakeWatcher
	m.watcherFactory = func(_ []string, _, _ time.Duration, _ bool, callback func(), _ *config.PathPolicy) (managedWatcher, error) {
		watch := &fakeWatcher{callback: callback}
		watchers = append(watchers, watch)
		return watch, nil
	}
	var calls atomic.Int32
	m.syncFunc = func(config.CertificateConfig, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		calls.Add(1)
		return &certutil.CertInfo{Fingerprint: "fp"}, &certSync.Result{SourceFP: "fp"}, nil
	}
	first := testCertificate("cert", source, destination)
	first.Sync.AutoSync = true
	if err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{first}}); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Source.Certificate = filepath.Join(source, "replacement.pem")
	if err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{second}}); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	watchers[0].callback()
	if calls.Load() != before {
		t.Fatal("old-generation callback performed a sync")
	}
}

func TestWatcherStopDoesNotHoldManagerLock(t *testing.T) {
	policy, source, destination := testPolicy(t)
	m := inertManager(policy)
	old := testCertificate("old", source, destination)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{old}}
	m.states = map[string]*status.State{"old": {Config: old}}
	m.watchers = map[string]managedWatcher{"old": &fakeWatcher{stop: func() { _ = m.SnapshotConfig() }}}
	done := make(chan error, 1)
	go func() { done <- m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info"}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher Stop ran while manager lock was held")
	}
}

func TestValidationDoesNotClearSyncError(t *testing.T) {
	policy, source, destination := testPolicy(t)
	certificate := testCertificate("cert", source, destination)
	for _, path := range []string{certificate.Source.Certificate, certificate.Source.PrivateKey} {
		if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
	m.states = map[string]*status.State{"cert": {Config: certificate, SyncError: errors.New("sync failed")}}
	m.generation = 1
	m.validateFunc = func(string, string) (*certutil.CertInfo, error) {
		return &certutil.CertInfo{Fingerprint: "valid"}, nil
	}
	if err := m.ValidateCertificate("cert"); err != nil {
		t.Fatal(err)
	}
	if got := m.SnapshotStatus()[0]; got.SyncError != "sync failed" || got.Status != status.StatusError {
		t.Fatalf("validation erased sync error: %+v", got)
	}
}

func TestApplyConfigReconcilesFallbackTransitions(t *testing.T) {
	policy, source, destinationRoot := testPolicy(t)
	for _, test := range []struct {
		name       string
		mutate     func(*config.Config, string)
		wantOld    string
		wantNew    string
		wantItems  int
		newDirName string
	}{
		{name: "delete", mutate: func(cfg *config.Config, _ string) { cfg.Certificates = nil }, wantItems: 0},
		{name: "disable", mutate: func(cfg *config.Config, _ string) { cfg.Certificates[0].Enabled = false }, wantItems: 1},
		{name: "rename", mutate: func(cfg *config.Config, _ string) { cfg.Certificates[0].Destination.TargetName = "renamed" }, wantNew: "renamed", wantItems: 1},
		{name: "move", mutate: func(cfg *config.Config, root string) {
			cfg.Certificates[0].Destination.TargetDirectory = filepath.Join(root, "moved")
		}, wantNew: "fallback", wantItems: 1, newDirName: "moved"},
		{name: "switch", mutate: func(cfg *config.Config, _ string) {
			cfg.Certificates[0].Fallback = false
			second := cfg.Certificates[0]
			second.Name = "second"
			second.Destination.TargetName = "second"
			second.Fallback = true
			cfg.Certificates = append(cfg.Certificates, second)
		}, wantNew: "second", wantItems: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := filepath.Join(destinationRoot, test.name)
			certificate := testCertificate("fallback", source, destination)
			certificate.Fallback = true
			m := inertManager(policy)
			m.configPath = filepath.Join(t.TempDir(), "config.json")
			initial := &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
			if err := m.ApplyConfig(context.Background(), initial); err != nil {
				t.Fatal(err)
			}
			if err := m.AcknowledgeFallbackRestart(context.Background()); err != nil {
				t.Fatal(err)
			}
			updated := initial.Clone()
			test.mutate(updated, destinationRoot)
			if err := m.ApplyConfig(context.Background(), updated); err != nil {
				t.Fatal(err)
			}
			if !m.FallbackRestartPending() {
				t.Fatal("fallback change did not set pending restart")
			}
			if got := len(m.SnapshotStatus()); got != test.wantItems {
				t.Fatalf("got %d status items, want %d", got, test.wantItems)
			}
			oldPath := filepath.Join(destination, "fallback.json")
			if test.wantNew == "" || test.newDirName != "" {
				if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
					t.Fatalf("old fallback remains: %v", err)
				}
			}
			if test.wantNew != "" {
				newDestination := destination
				if test.newDirName != "" {
					newDestination = filepath.Join(destinationRoot, test.newDirName)
				}
				if got, err := certSync.ReadFallback(newDestination, policy); err != nil || got != test.wantNew {
					t.Fatalf("fallback = %q, %v; want %q", got, err, test.wantNew)
				}
			}
		})
	}
}

func TestFallbackPendingPersistsUntilAcknowledged(t *testing.T) {
	policy, source, destination := testPolicy(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	certificate := testCertificate("fallback", source, destination)
	certificate.Fallback = true
	cfg := &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}

	first := inertManager(policy)
	first.configPath = configPath
	if err := first.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !first.FallbackRestartPending() || !first.SnapshotStatus()[0].FallbackPendingRestart {
		t.Fatal("initial fallback write did not set pending state")
	}

	second := inertManager(policy)
	second.configPath = configPath
	if err := second.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if !second.FallbackRestartPending() || !second.SnapshotStatus()[0].FallbackPendingRestart {
		t.Fatal("pending state did not survive manager restart or unchanged sync")
	}
	if err := second.AcknowledgeFallbackRestart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if second.FallbackRestartPending() || second.SnapshotStatus()[0].FallbackPendingRestart {
		t.Fatal("acknowledgment did not clear pending state")
	}

	third := inertManager(policy)
	third.configPath = configPath
	if err := third.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if third.FallbackRestartPending() || third.SnapshotStatus()[0].FallbackPendingRestart {
		t.Fatal("acknowledgment did not persist")
	}
}
