package main

import (
	"context"
	"errors"
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
