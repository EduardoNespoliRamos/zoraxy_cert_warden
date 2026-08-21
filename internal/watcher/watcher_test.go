package watcher

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

func TestWatcherStartOnlyOnce(t *testing.T) {
	dir, file := watcherTestFile(t)
	w := newTestWatcher(t, []string{file}, dir, time.Hour, time.Millisecond, false, nil)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)

	if err := w.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("second Start error = %v, want %v", err, ErrAlreadyStarted)
	}
}

func TestWatcherStopBeforeStartPreventsStart(t *testing.T) {
	dir, file := watcherTestFile(t)
	w := newTestWatcher(t, []string{file}, dir, time.Hour, time.Millisecond, false, nil)
	w.Stop()
	w.Stop()
	if err := w.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Fatalf("Start after Stop error = %v, want %v", err, ErrAlreadyStarted)
	}
}

func TestWatcherStopIsConcurrentAndWaitsForCallback(t *testing.T) {
	dir, file := watcherTestFile(t)
	started := make(chan struct{})
	release := make(chan struct{})
	w := newTestWatcher(t, []string{file}, dir, time.Hour, 0, false, func() {
		close(started)
		<-release
	})
	startWatcher(t, w)
	w.triggerDebounce(w.ctx, w.generation)
	waitSignal(t, started, "callback start")

	const stopCount = 5
	stopped := make(chan struct{}, stopCount)
	for i := 0; i < stopCount; i++ {
		go func() {
			w.Stop()
			stopped <- struct{}{}
		}()
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned while callback was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for i := 0; i < stopCount; i++ {
		waitSignal(t, stopped, "Stop return")
	}
}

func TestWatcherStopCancelsPendingDebounce(t *testing.T) {
	dir, file := watcherTestFile(t)
	var count atomic.Int32
	w := newTestWatcher(t, []string{file}, dir, time.Hour, 100*time.Millisecond, false, func() {
		count.Add(1)
	})
	startWatcher(t, w)
	w.triggerDebounce(w.ctx, w.generation)
	w.Stop()
	time.Sleep(150 * time.Millisecond)
	if got := count.Load(); got != 0 {
		t.Fatalf("callbacks after Stop = %d, want 0", got)
	}
}

func TestWatcherCannotInstallTimerAfterStop(t *testing.T) {
	dir, file := watcherTestFile(t)
	var count atomic.Int32
	w := newTestWatcher(t, []string{file}, dir, time.Hour, time.Millisecond, false, func() {
		count.Add(1)
	})
	startWatcher(t, w)
	ctx, generation := w.ctx, w.generation
	w.Stop()

	var callers sync.WaitGroup
	for i := 0; i < 20; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			w.triggerDebounce(ctx, generation)
		}()
	}
	callers.Wait()
	w.mu.Lock()
	timer := w.debounce
	w.mu.Unlock()
	if timer != nil {
		t.Fatal("debounce timer installed after Stop")
	}
	if got := count.Load(); got != 0 {
		t.Fatalf("callbacks after Stop = %d, want 0", got)
	}
}

func TestWatcherPollingHasNoInitialEvent(t *testing.T) {
	dir, file := watcherTestFile(t)
	var count atomic.Int32
	w := newTestWatcher(t, []string{file}, dir, 20*time.Millisecond, 10*time.Millisecond, false, func() {
		count.Add(1)
	})
	startWatcher(t, w)
	t.Cleanup(w.Stop)
	time.Sleep(100 * time.Millisecond)
	if got := count.Load(); got != 0 {
		t.Fatalf("callbacks without a change = %d, want 0", got)
	}
}

func TestWatcherPollingDetectsChanges(t *testing.T) {
	tests := []struct {
		name    string
		missing bool
		change  func(*testing.T, string)
	}{
		{
			name:    "creation",
			missing: true,
			change: func(t *testing.T, path string) {
				writeFile(t, path, "created")
			},
		},
		{
			name: "removal",
			change: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "size",
			change: func(t *testing.T, path string) {
				writeFile(t, path, "a longer value")
			},
		},
		{
			name: "same metadata content",
			change: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, path, "b")
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "file identity",
			change: func(t *testing.T, path string) {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				replacement := filepath.Join(filepath.Dir(path), "replacement")
				writeFile(t, replacement, "a")
				if err := os.Chmod(replacement, info.Mode()); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "watch.txt")
			if !test.missing {
				writeFile(t, file, "a")
			}
			called := make(chan struct{}, 1)
			w := newTestWatcher(t, []string{file}, dir, 20*time.Millisecond, 10*time.Millisecond, false, func() {
				select {
				case called <- struct{}{}:
				default:
				}
			})
			startWatcher(t, w)
			t.Cleanup(w.Stop)
			test.change(t, file)
			waitSignal(t, called, "polling callback")
		})
	}
}

func TestWatcherFsnotifyOperations(t *testing.T) {
	tests := []struct {
		name    string
		missing bool
		change  func(*testing.T, string)
	}{
		{"write", false, func(t *testing.T, path string) { writeFile(t, path, "b") }},
		{"create", true, func(t *testing.T, path string) { writeFile(t, path, "a") }},
		{"rename", false, func(t *testing.T, path string) {
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
		}},
		{"remove", false, func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "watch.txt")
			if !test.missing {
				writeFile(t, file, "a")
			}
			called := make(chan struct{}, 1)
			w := newTestWatcher(t, []string{file}, dir, time.Hour, 20*time.Millisecond, true, func() {
				select {
				case called <- struct{}{}:
				default:
				}
			})
			startWatcher(t, w)
			t.Cleanup(w.Stop)
			test.change(t, file)
			waitSignal(t, called, "fsnotify callback")
		})
	}
}

func TestWatcherRapidCertAndKeyChangesDebounceOnce(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	writeFile(t, cert, "cert-a")
	writeFile(t, key, "key-a")
	var count atomic.Int32
	called := make(chan struct{}, 1)
	w := newTestWatcher(t, []string{cert, key}, dir, 15*time.Millisecond, 100*time.Millisecond, false, func() {
		count.Add(1)
		select {
		case called <- struct{}{}:
		default:
		}
	})
	startWatcher(t, w)
	t.Cleanup(w.Stop)

	writeFile(t, cert, "cert-b")
	time.Sleep(30 * time.Millisecond)
	writeFile(t, key, "key-b")
	time.Sleep(30 * time.Millisecond)
	writeFile(t, cert, "cert-c")
	waitSignal(t, called, "debounced callback")
	time.Sleep(150 * time.Millisecond)
	if got := count.Load(); got != 1 {
		t.Fatalf("callbacks = %d, want 1", got)
	}
}

func TestWatcherUsesCanonicalResolvedPaths(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "watch.txt")
	writeFile(t, realFile, "a")
	linkedFile := filepath.Join(linkDir, "watch.txt")
	w := newTestWatcher(t, []string{linkedFile}, dir, time.Hour, time.Millisecond, false, nil)
	if got := w.paths[0]; got != realFile {
		t.Fatalf("resolved path = %q, want %q", got, realFile)
	}
	if !w.matches(realFile) {
		t.Fatal("canonical path did not match fsnotify path")
	}
}

func TestWatcherNewWithLogger(t *testing.T) {
	dir, file := watcherTestFile(t)
	policy := watcherTestPolicy(t, dir)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	w, err := NewWithLogger([]string{file}, time.Second, time.Second, false, nil, policy, logger)
	if err != nil {
		t.Fatal(err)
	}
	if w.logger != logger {
		t.Fatal("injected logger was not retained")
	}
}

func watcherTestFile(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "watch.txt")
	writeFile(t, file, "a")
	return dir, file
}

func writeFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		t.Fatal(err)
	}
}

func newTestWatcher(t *testing.T, paths []string, sourceDir string, poll, debounce time.Duration, fsnotifyEnabled bool, callback func()) *Watcher {
	t.Helper()
	w, err := New(paths, poll, debounce, fsnotifyEnabled, callback, watcherTestPolicy(t, sourceDir))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func startWatcher(t *testing.T, w *Watcher) {
	t.Helper()
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
}

func waitSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func watcherTestPolicy(t *testing.T, sourceDir string) *config.PathPolicy {
	t.Helper()
	policy, err := config.NewPathPolicy([]string{sourceDir}, []string{sourceDir})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
