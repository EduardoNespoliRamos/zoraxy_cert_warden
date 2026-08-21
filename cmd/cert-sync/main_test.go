package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/certwarden"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/secretstore"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
	certSync "github.com/eduardoramos/zoraxy-cert-warden/internal/sync"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/web"
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

type fakeRemoteFetcher struct {
	material certwarden.Material
	err      error
	calls    int
	name     string
}

type blockingRemoteFetcher struct {
	material certwarden.Material
	entered  chan<- struct{}
	release  <-chan struct{}
}

func (f *fakeRemoteFetcher) Fetch(_ context.Context, name string) (certwarden.Material, error) {
	f.calls++
	f.name = name
	return f.material, f.err
}

func (f *blockingRemoteFetcher) Fetch(context.Context, string) (certwarden.Material, error) {
	f.entered <- struct{}{}
	<-f.release
	return f.material, nil
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

func testRemoteCertificate(name, destination string) config.CertificateConfig {
	return config.CertificateConfig{
		Name: name, Enabled: true,
		Source: config.CertificateSource{
			Type: config.SourceTypeCertWarden,
			CertWarden: &config.CertWardenSource{
				ServerURL:       "https://certwarden.example",
				CertificateName: "remote-" + name,
			},
		},
		Destination: config.CertificateDestination{TargetDirectory: destination, TargetName: name},
		Sync:        config.SyncConfig{PollIntervalSeconds: config.MinRemotePollIntervalSeconds},
	}
}

func testSecrets(name string) secretstore.Data {
	return secretstore.Data{name: {
		ServerURL:         "https://certwarden.example",
		CertificateName:   "remote-" + name,
		CertificateAPIKey: "certificate-api-key",
		PrivateKeyAPIKey:  "private-key-api-key",
	}}
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

func TestRemoteFetchKeepsGenerationCredentialsAndCannotInstallAfterRotation(t *testing.T) {
	policy, _, destination := testPolicy(t)
	oldConfig := testRemoteCertificate("cert", destination)
	oldSecrets := testSecrets("cert")
	oldCredentials, _ := oldSecrets.Get("cert")
	newCertificateKey := "rotated-certificate-key"
	newPrivateKey := "rotated-private-key"
	newCredentials := secretstore.Credentials{
		ServerURL:         "https://rotated-certwarden.example",
		CertificateName:   oldConfig.Source.CertWarden.CertificateName,
		CertificateAPIKey: newCertificateKey,
		PrivateKeyAPIKey:  newPrivateKey,
	}
	oldFetchEntered := make(chan struct{}, 1)
	releaseOldFetch := make(chan struct{})
	oldFetcher := &blockingRemoteFetcher{
		material: certwarden.Material{CertificatePEM: []byte("old-material"), HTTPStatus: http.StatusOK},
		entered:  oldFetchEntered,
		release:  releaseOldFetch,
	}
	newFetcher := &fakeRemoteFetcher{material: certwarden.Material{
		CertificatePEM: []byte("new-material"),
		HTTPStatus:     http.StatusOK,
	}}
	type clientObservation struct {
		server      string
		credentials certwarden.Credentials
	}
	var observationsMu sync.Mutex
	var observations []clientObservation
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{oldConfig}}
	m.states = map[string]*status.State{"cert": {Config: oldConfig}}
	m.secrets = oldSecrets
	m.generation = 1
	newGenerationActive := make(chan struct{}, 1)
	m.watchers = map[string]managedWatcher{"cert": &fakeWatcher{stop: func() { newGenerationActive <- struct{}{} }}}
	m.saveSecrets = func(string, secretstore.Data) error { return nil }
	m.remoteClientFactory = func(server string, credentials certwarden.Credentials) (remoteFetcher, error) {
		observationsMu.Lock()
		observations = append(observations, clientObservation{server: server, credentials: credentials})
		observationsMu.Unlock()
		if server == oldConfig.Source.CertWarden.ServerURL {
			return oldFetcher, nil
		}
		return newFetcher, nil
	}
	var installedMu sync.Mutex
	var installedMaterials []string
	m.syncMaterialFunc = func(cfg config.CertificateConfig, certPEM, _ []byte, _ *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		installedMu.Lock()
		installedMaterials = append(installedMaterials, cfg.Source.CertWarden.ServerURL+":"+string(certPEM))
		installedMu.Unlock()
		return &certutil.CertInfo{Fingerprint: "new-fingerprint", BundleDigest: "new-digest"}, &certSync.Result{}, nil
	}
	m.readDestinationFunc = func(string, string, *config.PathPolicy) (*certutil.CertInfo, error) {
		return &certutil.CertInfo{Fingerprint: "new-fingerprint", BundleDigest: "new-digest"}, nil
	}

	oldSyncDone := make(chan error, 1)
	go func() { oldSyncDone <- m.SyncCertificate("cert") }()
	<-oldFetchEntered

	newServer := "https://rotated-certwarden.example"
	applyDone := make(chan error, 1)
	go func() {
		applyDone <- m.MutateConfigAndCredentials(context.Background(), func(cfg *config.Config) error {
			cfg.Certificates[0].Source.CertWarden.ServerURL = newServer
			return nil
		}, &web.CredentialMutation{
			Name:              "cert",
			CertificateAPIKey: &newCertificateKey,
			PrivateKeyAPIKey:  &newPrivateKey,
		})
	}()
	<-newGenerationActive
	close(releaseOldFetch)
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if err := <-oldSyncDone; err != nil {
		t.Fatal(err)
	}

	observationsMu.Lock()
	gotObservations := append([]clientObservation(nil), observations...)
	observationsMu.Unlock()
	if len(gotObservations) != 2 {
		t.Fatalf("remote client creations = %d, want 2", len(gotObservations))
	}
	if gotObservations[0].server != oldConfig.Source.CertWarden.ServerURL ||
		gotObservations[0].credentials.CertificateAPIKey != oldCredentials.CertificateAPIKey ||
		gotObservations[0].credentials.PrivateKeyAPIKey != oldCredentials.PrivateKeyAPIKey {
		t.Fatal("paused old fetch did not retain only the old server and credentials")
	}
	if gotObservations[1].server != newServer ||
		newCredentials.ServerURL != newServer ||
		newCredentials.CertificateName != oldConfig.Source.CertWarden.CertificateName ||
		gotObservations[1].credentials.CertificateAPIKey != newCredentials.CertificateAPIKey ||
		gotObservations[1].credentials.PrivateKeyAPIKey != newCredentials.PrivateKeyAPIKey {
		t.Fatal("new generation fetch did not use the rotated server and credentials")
	}
	installedMu.Lock()
	gotInstalled := append([]string(nil), installedMaterials...)
	installedMu.Unlock()
	if len(gotInstalled) != 1 || gotInstalled[0] != newServer+":new-material" {
		t.Fatal("old-generation remote material was installed after credential rotation")
	}
	activeCredentials, activeCredentialsOK := m.secrets.Get("cert")
	if !activeCredentialsOK || activeCredentials != newCredentials {
		t.Fatal("rotated credentials were not bound to the new remote identity")
	}
	items := m.SnapshotStatus()
	if len(items) != 1 || items[0].SourceFingerprint != "new-fingerprint" || items[0].CertWardenQuery == nil || items[0].CertWardenQuery.Status != status.StatusHealthy {
		t.Fatal("rotated generation did not retain the new fetch and sync status")
	}
}

func TestPausedSyncCannotPublishAfterEntryDeletion(t *testing.T) {
	policy, _, destination := testPolicy(t)
	certificate := testRemoteCertificate("cert", destination)
	fetchEntered := make(chan struct{}, 1)
	releaseFetch := make(chan struct{})
	fetcher := &blockingRemoteFetcher{
		material: certwarden.Material{CertificatePEM: []byte("stale-material"), HTTPStatus: http.StatusOK},
		entered:  fetchEntered,
		release:  releaseFetch,
	}
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
	m.states = map[string]*status.State{"cert": {Config: certificate}}
	m.secrets = testSecrets("cert")
	m.generation = 1
	m.saveSecrets = func(string, secretstore.Data) error { return nil }
	m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) { return fetcher, nil }
	var syncCalls atomic.Int32
	var destinationReads atomic.Int32
	m.syncMaterialFunc = func(config.CertificateConfig, []byte, []byte, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		syncCalls.Add(1)
		return &certutil.CertInfo{Fingerprint: "stale"}, &certSync.Result{}, nil
	}
	m.readDestinationFunc = func(string, string, *config.PathPolicy) (*certutil.CertInfo, error) {
		destinationReads.Add(1)
		return &certutil.CertInfo{Fingerprint: "stale"}, nil
	}

	syncDone := make(chan error, 1)
	go func() { syncDone <- m.SyncCertificate("cert") }()
	<-fetchEntered

	if err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info"}); err != nil {
		t.Fatal(err)
	}
	if len(m.SnapshotConfig().Certificates) != 0 || len(m.SnapshotStatus()) != 0 {
		t.Fatal("entry deletion was not active while the old sync remained paused")
	}
	close(releaseFetch)
	if err := <-syncDone; err != nil {
		t.Fatal(err)
	}
	if syncCalls.Load() != 0 || destinationReads.Load() != 0 {
		t.Fatal("paused old-generation sync published after entry deletion")
	}
	if len(m.SnapshotConfig().Certificates) != 0 || len(m.SnapshotStatus()) != 0 {
		t.Fatal("old-generation completion restored deleted runtime state")
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

func TestManagerRemoteSyncFetchesAndRecordsHealthyQuery(t *testing.T) {
	policy, _, destination := testPolicy(t)
	certificate := testRemoteCertificate("cert", destination)
	retrievedAt := time.Now().Add(-time.Minute)
	fetcher := &fakeRemoteFetcher{material: certwarden.Material{
		CertificatePEM: []byte("certificate material"),
		PrivateKeyPEM:  []byte("private key material"),
		RetrievedAt:    retrievedAt,
		HTTPStatus:     http.StatusOK,
		Latency:        1250 * time.Millisecond,
	}}
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
	m.states = map[string]*status.State{"cert": {Config: certificate}}
	m.secrets = testSecrets("cert")
	m.generation = 1
	m.remoteClientFactory = func(baseURL string, credentials certwarden.Credentials) (remoteFetcher, error) {
		if baseURL != certificate.Source.CertWarden.ServerURL {
			t.Fatal("remote client received the wrong server URL")
		}
		if credentials.CertificateAPIKey == "" || credentials.PrivateKeyAPIKey == "" {
			t.Fatal("remote client received incomplete credentials")
		}
		return fetcher, nil
	}
	syncCalls := 0
	m.syncMaterialFunc = func(_ config.CertificateConfig, certPEM, keyPEM []byte, _ *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		syncCalls++
		if string(certPEM) != "certificate material" || string(keyPEM) != "private key material" {
			t.Fatal("sync material did not receive fetched material")
		}
		return &certutil.CertInfo{Fingerprint: "source-fingerprint", BundleDigest: "bundle-digest"}, &certSync.Result{SourceFP: "source-fingerprint"}, nil
	}
	m.readDestinationFunc = func(string, string, *config.PathPolicy) (*certutil.CertInfo, error) {
		return &certutil.CertInfo{Fingerprint: "destination-fingerprint", BundleDigest: "bundle-digest"}, nil
	}

	if err := m.SyncCertificate("cert"); err != nil {
		t.Fatal(err)
	}
	if fetcher.calls != 1 || fetcher.name != certificate.Source.CertWarden.CertificateName || syncCalls != 1 {
		t.Fatal("remote sync did not perform exactly one fetch and material sync")
	}
	item := m.SnapshotStatus()[0]
	query := item.CertWardenQuery
	if query == nil || query.Status != status.StatusHealthy || query.InProgress || query.LastAttempt == nil || query.LastSuccess == nil {
		t.Fatalf("remote query did not become healthy: %+v", query)
	}
	if query.HTTPStatus != http.StatusOK || query.LatencyMillis != 1250 || query.FailureKind != "" || query.NextAttempt != nil {
		t.Fatalf("remote query metadata was not recorded: %+v", query)
	}
	if !item.LastSourceModification.Equal(retrievedAt) || item.Status != status.StatusHealthy {
		t.Fatal("remote sync did not record retrieval time and synchronized health")
	}
}

func TestManagerRemoteAuthenticationErrorPreservesCertificateMetadata(t *testing.T) {
	policy, _, destination := testPolicy(t)
	certificate := testRemoteCertificate("cert", destination)
	validatedAt := time.Now().Add(-time.Hour)
	attemptedAt := validatedAt.Add(time.Minute)
	fetcher := &fakeRemoteFetcher{err: &certwarden.FetchError{
		Kind:       certwarden.ErrorKindAuthentication,
		HTTPStatus: http.StatusUnauthorized,
	}}
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
	m.states = map[string]*status.State{"cert": {
		Config:                    certificate,
		SourceInfo:                &certutil.CertInfo{Fingerprint: "old-source", BundleDigest: "old-source-digest"},
		SourceFingerprint:         "old-source",
		SourceDigest:              "old-source-digest",
		DestinationFingerprint:    "old-destination",
		DestinationDigest:         "old-destination-digest",
		LastSourceValidation:      &validatedAt,
		LastDestinationValidation: &validatedAt,
		LastAttemptedSync:         &attemptedAt,
	}}
	m.secrets = testSecrets("cert")
	m.generation = 1
	m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) { return fetcher, nil }
	syncCalls := 0
	m.syncMaterialFunc = func(config.CertificateConfig, []byte, []byte, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		syncCalls++
		return nil, nil, nil
	}

	err := m.SyncCertificate("cert")
	var fetchErr *certwarden.FetchError
	if !errors.As(err, &fetchErr) || fetchErr.Kind != certwarden.ErrorKindAuthentication {
		t.Fatal("remote sync did not return the authentication fetch error")
	}
	if syncCalls != 0 {
		t.Fatal("authentication failure called material sync")
	}
	item := m.SnapshotStatus()[0]
	query := item.CertWardenQuery
	if query == nil || query.Status != status.StatusError || query.FailureKind != string(certwarden.ErrorKindAuthentication) || query.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("authentication query metadata was not recorded: %+v", query)
	}
	if item.SourceFingerprint != "old-source" || item.SourceBundleDigest != "old-source-digest" ||
		item.DestinationFingerprint != "old-destination" || item.DestinationBundleDigest != "old-destination-digest" {
		t.Fatal("authentication failure changed source or destination metadata")
	}
	if item.LastSourceValidation == nil || !item.LastSourceValidation.Equal(validatedAt) ||
		item.LastDestinationValidation == nil || !item.LastDestinationValidation.Equal(validatedAt) ||
		item.LastAttemptedSync == nil || !item.LastAttemptedSync.Equal(attemptedAt) {
		t.Fatal("authentication failure changed prior validation or sync timestamps")
	}
}

func TestManagerRejectsPersistedRemoteIdentityMismatchBeforeClientCreation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*secretstore.Credentials)
	}{
		{
			name: "server URL",
			mutate: func(credentials *secretstore.Credentials) {
				credentials.ServerURL = "https://other-certwarden.example"
			},
		},
		{
			name: "certificate name",
			mutate: func(credentials *secretstore.Credentials) {
				credentials.CertificateName = "other-certificate"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, _, destination := testPolicy(t)
			certificate := testRemoteCertificate("cert", destination)
			secrets := testSecrets("cert")
			credentials, _ := secrets.Get("cert")
			test.mutate(&credentials)
			secrets["cert"] = credentials
			m := inertManager(policy)
			m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
			m.states = map[string]*status.State{"cert": {Config: certificate}}
			m.secrets = secrets
			m.generation = 1
			var factoryCalls atomic.Int32
			m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) {
				factoryCalls.Add(1)
				return &fakeRemoteFetcher{}, nil
			}

			err := m.SyncCertificate("cert")
			var fetchErr *certwarden.FetchError
			if !errors.As(err, &fetchErr) || fetchErr.Kind != certwarden.ErrorKindAuthentication {
				t.Fatal("remote identity mismatch was not rejected as an authentication failure")
			}
			if factoryCalls.Load() != 0 {
				t.Fatal("remote identity mismatch leaked persisted credentials to the client factory")
			}
			item := m.SnapshotStatus()[0]
			if item.CertWardenQuery == nil || item.CertWardenQuery.Status != status.StatusError ||
				item.CertWardenQuery.FailureKind != string(certwarden.ErrorKindAuthentication) {
				t.Fatal("remote identity mismatch did not record query failure metadata")
			}
		})
	}
}

func TestManagerRemoteValidateFetchesWithoutSyncing(t *testing.T) {
	policy, _, destination := testPolicy(t)
	certificate := testRemoteCertificate("cert", destination)
	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("remote.example", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &fakeRemoteFetcher{material: certwarden.Material{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		HTTPStatus:     http.StatusOK,
	}}
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
	m.states = map[string]*status.State{"cert": {Config: certificate}}
	m.secrets = testSecrets("cert")
	m.generation = 1
	m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) { return fetcher, nil }
	syncCalls := 0
	m.syncMaterialFunc = func(config.CertificateConfig, []byte, []byte, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		syncCalls++
		return nil, nil, nil
	}

	if err := m.ValidateCertificate("cert"); err != nil {
		t.Fatal(err)
	}
	if fetcher.calls != 1 || syncCalls != 0 {
		t.Fatal("remote validation did not fetch exactly once without syncing")
	}
	item := m.SnapshotStatus()[0]
	if item.LastSourceValidation == nil || item.SourceFingerprint == "" || item.CertWardenQuery == nil || item.CertWardenQuery.Status != status.StatusHealthy {
		t.Fatal("remote validation did not record source and query metadata")
	}
	if item.LastAttemptedSync != nil || item.LastSuccessfulSync != nil || item.LastDestinationValidation != nil {
		t.Fatal("remote validation recorded synchronization metadata")
	}
}

func TestCertWardenConnectionForwardsCandidateAndDoesNotMutateRuntime(t *testing.T) {
	policy, _, destination := testPolicy(t)
	certificate := testRemoteCertificate("active", destination)
	validatedAt := time.Now().Add(-time.Hour)
	m := inertManager(policy)
	m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
	m.states = map[string]*status.State{"active": {
		Config:                 certificate,
		SourceFingerprint:      "existing-source",
		DestinationFingerprint: "existing-destination",
		LastSourceValidation:   &validatedAt,
	}}
	m.secrets = testSecrets("active")
	m.generation = 7
	beforeConfig := m.SnapshotConfig()
	beforeStatus := m.SnapshotStatus()

	certPEM, keyPEM, err := certutil.GenerateTestCertificateNow("candidate.example", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &fakeRemoteFetcher{material: certwarden.Material{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		HTTPStatus:     http.StatusOK,
	}}
	var gotServer string
	var gotCredentials certwarden.Credentials
	m.remoteClientFactory = func(server string, credentials certwarden.Credentials) (remoteFetcher, error) {
		gotServer = server
		gotCredentials = credentials
		return fetcher, nil
	}
	var syncCalls atomic.Int32
	var installReads atomic.Int32
	m.syncFunc = func(config.CertificateConfig, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		syncCalls.Add(1)
		return nil, nil, nil
	}
	m.syncMaterialFunc = func(config.CertificateConfig, []byte, []byte, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		syncCalls.Add(1)
		return nil, nil, nil
	}
	m.readDestinationFunc = func(string, string, *config.PathPolicy) (*certutil.CertInfo, error) {
		installReads.Add(1)
		return nil, nil
	}
	candidateServer := "https://candidate-certwarden.example"
	candidateName := "candidate-certificate"
	certificateKey := "candidate-certificate-key"
	privateKey := "candidate-private-key"

	err = m.TestCertWardenConnection(
		context.Background(),
		"  "+candidateServer+"  ",
		"  "+candidateName+"  ",
		"  "+certificateKey+"  ",
		"  "+privateKey+"  ",
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotServer != candidateServer || fetcher.calls != 1 || fetcher.name != candidateName ||
		gotCredentials.CertificateAPIKey != certificateKey || gotCredentials.PrivateKeyAPIKey != privateKey {
		t.Fatal("connection test did not forward the normalized candidate identity and credentials")
	}
	if syncCalls.Load() != 0 || installReads.Load() != 0 {
		t.Fatal("successful connection test invoked synchronization or destination installation")
	}
	if !reflect.DeepEqual(m.SnapshotConfig(), beforeConfig) || !reflect.DeepEqual(m.SnapshotStatus(), beforeStatus) {
		t.Fatal("successful connection test mutated active manager state")
	}
}

func TestCertWardenConnectionReturnsSanitizedFetchError(t *testing.T) {
	m := inertManager(nil)
	fetchErr := &certwarden.FetchError{
		Kind:       certwarden.ErrorKindAuthentication,
		HTTPStatus: http.StatusUnauthorized,
	}
	m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) {
		return &fakeRemoteFetcher{err: fetchErr}, nil
	}
	certificateKey := "unlogged-certificate-key"
	privateKey := "unlogged-private-key"

	err := m.TestCertWardenConnection(context.Background(), "https://candidate-certwarden.example", "candidate", certificateKey, privateKey)
	var gotFetchErr *certwarden.FetchError
	if err != fetchErr || !errors.As(err, &gotFetchErr) || gotFetchErr.Kind != certwarden.ErrorKindAuthentication || gotFetchErr.HTTPStatus != http.StatusUnauthorized {
		t.Fatal("connection test did not preserve the sanitized fetch error")
	}
	if strings.Contains(err.Error(), certificateKey) || strings.Contains(err.Error(), privateKey) {
		t.Fatal("sanitized fetch error exposed candidate credentials")
	}
}

func TestCertWardenConnectionClassifiesInvalidPairAsSourceValidation(t *testing.T) {
	certPEM, _, err := certutil.GenerateTestCertificateNow("candidate.example", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, mismatchedKey, err := certutil.GenerateTestCertificateNow("other.example", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m := inertManager(nil)
	m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) {
		return &fakeRemoteFetcher{material: certwarden.Material{
			CertificatePEM: certPEM,
			PrivateKeyPEM:  mismatchedKey,
		}}, nil
	}

	err = m.TestCertWardenConnection(context.Background(), "https://candidate-certwarden.example", "candidate", "certificate-key", "private-key")
	var invalid interface{ SourceValidation() bool }
	if !errors.As(err, &invalid) || !invalid.SourceValidation() {
		t.Fatal("invalid candidate pair was not classified as a source-validation error")
	}
}

func TestApplyRemoteConfigRequiresStoredCredentials(t *testing.T) {
	policy, _, destination := testPolicy(t)
	m := inertManager(policy)
	pollerCalls := 0
	m.pollerFactory = func(time.Duration, func(context.Context)) managedWatcher {
		pollerCalls++
		return &fakeWatcher{}
	}
	saveCalls := 0
	m.saveConfig = func(*config.Config, string, *config.PathPolicy) error {
		saveCalls++
		return nil
	}

	err := m.ApplyConfig(context.Background(), &config.Config{
		LogLevel:     "info",
		Certificates: []config.CertificateConfig{testRemoteCertificate("cert", destination)},
	})
	var invalid interface{ InvalidConfig() bool }
	if !errors.As(err, &invalid) || !invalid.InvalidConfig() {
		t.Fatal("remote config without stored credentials was not rejected as invalid")
	}
	if pollerCalls != 0 || saveCalls != 0 || len(m.SnapshotConfig().Certificates) != 0 {
		t.Fatal("rejected remote config changed runtime or persistence")
	}
}

func TestApplyRemoteAutoSyncCreatesPollerInsteadOfFilesystemWatcher(t *testing.T) {
	policy, _, destination := testPolicy(t)
	certificate := testRemoteCertificate("cert", destination)
	certificate.Sync.AutoSync = true
	m := inertManager(policy)
	m.secrets = testSecrets("cert")
	filesystemWatcherCalls := 0
	m.watcherFactory = func([]string, time.Duration, time.Duration, bool, func(), *config.PathPolicy) (managedWatcher, error) {
		filesystemWatcherCalls++
		return &fakeWatcher{}, nil
	}
	poller := &fakeWatcher{}
	pollerCalls := 0
	var pollInterval time.Duration
	var pollCallback func(context.Context)
	m.pollerFactory = func(interval time.Duration, callback func(context.Context)) managedWatcher {
		pollerCalls++
		pollInterval = interval
		pollCallback = callback
		return poller
	}
	fetcher := &fakeRemoteFetcher{material: certwarden.Material{HTTPStatus: http.StatusOK}}
	m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) { return fetcher, nil }
	m.syncMaterialFunc = func(config.CertificateConfig, []byte, []byte, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		return &certutil.CertInfo{BundleDigest: "digest"}, &certSync.Result{}, nil
	}
	m.readDestinationFunc = func(string, string, *config.PathPolicy) (*certutil.CertInfo, error) {
		return &certutil.CertInfo{BundleDigest: "digest"}, nil
	}

	if err := m.ApplyConfig(context.Background(), &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}); err != nil {
		t.Fatal(err)
	}
	if pollerCalls != 1 || filesystemWatcherCalls != 0 || pollInterval != time.Minute || pollCallback == nil {
		t.Fatal("remote auto-sync did not create the expected managed poller")
	}
	if !poller.started.Load() || m.watchers["cert"] != poller {
		t.Fatal("remote auto-sync poller was not started and retained")
	}
}

func TestMutateConfigAndCredentialsPersistsCredentials(t *testing.T) {
	policy, _, destination := testPolicy(t)
	m := inertManager(policy)
	m.secretsPath = filepath.Join(t.TempDir(), "secrets.json")
	var persisted secretstore.Data
	m.saveSecrets = func(_ string, data secretstore.Data) error {
		persisted = data.Clone()
		return nil
	}
	fetcher := &fakeRemoteFetcher{material: certwarden.Material{HTTPStatus: http.StatusOK}}
	m.remoteClientFactory = func(string, certwarden.Credentials) (remoteFetcher, error) { return fetcher, nil }
	m.syncMaterialFunc = func(config.CertificateConfig, []byte, []byte, *config.PathPolicy) (*certutil.CertInfo, *certSync.Result, error) {
		return &certutil.CertInfo{BundleDigest: "digest"}, &certSync.Result{}, nil
	}
	m.readDestinationFunc = func(string, string, *config.PathPolicy) (*certutil.CertInfo, error) {
		return &certutil.CertInfo{BundleDigest: "digest"}, nil
	}
	certificateKey := "new-certificate-key"
	privateKey := "new-private-key"
	remote := testRemoteCertificate("cert", destination)

	err := m.MutateConfigAndCredentials(context.Background(), func(cfg *config.Config) error {
		cfg.Certificates = append(cfg.Certificates, remote)
		return nil
	}, &web.CredentialMutation{
		Name:              "cert",
		CertificateAPIKey: &certificateKey,
		PrivateKeyAPIKey:  &privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, storedOK := persisted.Get("cert")
	active, activeOK := m.secrets.Get("cert")
	if !storedOK || !activeOK || stored.ServerURL != remote.Source.CertWarden.ServerURL || stored.CertificateName != remote.Source.CertWarden.CertificateName ||
		stored.CertificateAPIKey != certificateKey || stored.PrivateKeyAPIKey != privateKey || active != stored {
		t.Fatal("credential mutation was not persisted and activated")
	}
}

func TestMutateConfigAndCredentialsRollsBackSecretsOnApplyFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		mutation web.ConfigMutation
		prepare  func(*manager)
	}{
		{
			name:     "config save",
			mutation: func(*config.Config) error { return nil },
			prepare: func(m *manager) {
				m.saveConfig = func(*config.Config, string, *config.PathPolicy) error { return errors.New("save failed") }
			},
		},
		{
			name: "poller start",
			mutation: func(cfg *config.Config) error {
				cfg.Certificates[0].Sync.AutoSync = true
				return nil
			},
			prepare: func(m *manager) {
				m.pollerFactory = func(time.Duration, func(context.Context)) managedWatcher {
					return &fakeWatcher{startErr: errors.New("start failed")}
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, _, destination := testPolicy(t)
			certificate := testRemoteCertificate("cert", destination)
			m := inertManager(policy)
			m.cfg = &config.Config{LogLevel: "info", Certificates: []config.CertificateConfig{certificate}}
			m.states = map[string]*status.State{"cert": {Config: certificate}}
			m.secrets = testSecrets("cert")
			oldCredentials, _ := m.secrets.Get("cert")
			test.prepare(m)
			var saved []secretstore.Data
			m.saveSecrets = func(_ string, data secretstore.Data) error {
				saved = append(saved, data.Clone())
				return nil
			}
			newCertificateKey := "replacement-certificate-key"
			newPrivateKey := "replacement-private-key"

			err := m.MutateConfigAndCredentials(context.Background(), test.mutation, &web.CredentialMutation{
				Name:              "cert",
				CertificateAPIKey: &newCertificateKey,
				PrivateKeyAPIKey:  &newPrivateKey,
			})
			if err == nil {
				t.Fatal("expected config application failure")
			}
			if len(saved) != 2 {
				t.Fatalf("credential persistence calls = %d, want 2", len(saved))
			}
			first, firstOK := saved[0].Get("cert")
			second, secondOK := saved[1].Get("cert")
			active, activeOK := m.secrets.Get("cert")
			if !firstOK || first.ServerURL != certificate.Source.CertWarden.ServerURL || first.CertificateName != certificate.Source.CertWarden.CertificateName ||
				first.CertificateAPIKey != newCertificateKey || first.PrivateKeyAPIKey != newPrivateKey {
				t.Fatal("replacement credentials were not persisted before config application")
			}
			if !secondOK || !activeOK || second != oldCredentials || active != oldCredentials {
				t.Fatal("failed config application did not restore prior credentials")
			}
			if m.SnapshotConfig().Certificates[0].Sync.AutoSync {
				t.Fatal("failed config application changed active configuration")
			}
		})
	}
}

func TestManagerCredentialsConfigured(t *testing.T) {
	m := inertManager(nil)
	m.secrets = secretstore.Data{
		"partial-certificate": {CertificateAPIKey: "configured"},
		"partial-private":     {PrivateKeyAPIKey: "configured"},
		"complete":            {CertificateAPIKey: "configured", PrivateKeyAPIKey: "configured"},
	}
	for _, test := range []struct {
		name               string
		wantCertificateKey bool
		wantPrivateKey     bool
	}{
		{name: "missing"},
		{name: "partial-certificate", wantCertificateKey: true},
		{name: "partial-private", wantPrivateKey: true},
		{name: "complete", wantCertificateKey: true, wantPrivateKey: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificateKey, privateKey := m.CredentialsConfigured(test.name)
			if certificateKey != test.wantCertificateKey || privateKey != test.wantPrivateKey {
				t.Fatal("configured credential components did not match expectation")
			}
		})
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
