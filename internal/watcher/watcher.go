package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

// Watcher combines fsnotify and polling with debounce.
type Watcher struct {
	paths           []string
	pollInterval    time.Duration
	debounceDelay   time.Duration
	callback        func()
	fsnotifyEnabled bool
	policy          *config.PathPolicy

	watcher  *fsnotify.Watcher
	ticker   *time.Ticker
	debounce *time.Timer
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex

	lastModTimes map[string]time.Time
}

// New creates a new watcher after validating all watched paths.
func New(paths []string, pollInterval, debounceDelay time.Duration, fsnotifyEnabled bool, callback func(), policy *config.PathPolicy) (*Watcher, error) {
	for _, path := range paths {
		if _, err := policy.ResolveSource(path, false); err != nil {
			return nil, fmt.Errorf("invalid watcher path: %w", err)
		}
	}
	return &Watcher{
		paths:           append([]string(nil), paths...),
		pollInterval:    pollInterval,
		debounceDelay:   debounceDelay,
		callback:        callback,
		fsnotifyEnabled: fsnotifyEnabled,
		policy:          policy,
		stopCh:          make(chan struct{}),
		lastModTimes:    make(map[string]time.Time),
	}, nil
}

// Start begins watching the configured paths.
func (w *Watcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.fsnotifyEnabled {
		if watcher, err := fsnotify.NewWatcher(); err == nil {
			w.watcher = watcher
			dirs := map[string]struct{}{}
			for _, p := range w.paths {
				dir := filepath.Dir(p)
				if _, ok := dirs[dir]; !ok {
					dirs[dir] = struct{}{}
					if err := w.watcher.Add(dir); err != nil {
						fmt.Printf("warn: fsnotify add failed for %s: %v\n", dir, err)
					}
				}
			}
			w.wg.Add(1)
			go w.fsnotifyLoop()
		} else {
			fmt.Printf("warn: fsnotify unavailable, using polling only: %v\n", err)
		}
	}

	w.ticker = time.NewTicker(w.pollInterval)
	w.wg.Add(1)
	go w.pollLoop()

	return nil
}

// Stop halts all watchers.
func (w *Watcher) Stop() {
	w.mu.Lock()
	close(w.stopCh)
	if w.ticker != nil {
		w.ticker.Stop()
	}
	if w.watcher != nil {
		w.watcher.Close()
	}
	if w.debounce != nil {
		w.debounce.Stop()
	}
	w.mu.Unlock()
	w.wg.Wait()
}

func (w *Watcher) fsnotifyLoop() {
	defer w.wg.Done()
	for {
		select {
		case <-w.stopCh:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if w.matches(event.Name) {
				if event.Op&fsnotify.Write == fsnotify.Write ||
					event.Op&fsnotify.Create == fsnotify.Create ||
					event.Op&fsnotify.Rename == fsnotify.Rename {
					w.triggerDebounce()
				}
			}
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			fmt.Printf("fsnotify error: %v\n", err)
		}
	}
}

func (w *Watcher) pollLoop() {
	defer w.wg.Done()
	for {
		select {
		case <-w.stopCh:
			return
		case <-w.ticker.C:
			if w.pollChanged() {
				w.triggerDebounce()
			}
		}
	}
}

func (w *Watcher) pollChanged() bool {
	changed := false
	for _, p := range w.paths {
		resolved, err := w.policy.ResolveSource(p, false)
		if err != nil {
			continue
		}
		info, err := os.Stat(resolved)
		var modTime time.Time
		if err == nil {
			modTime = info.ModTime()
		}
		if prev, ok := w.lastModTimes[p]; !ok || !prev.Equal(modTime) {
			changed = true
			w.lastModTimes[p] = modTime
		}
	}
	return changed
}

func (w *Watcher) matches(path string) bool {
	for _, p := range w.paths {
		if filepath.Clean(p) == filepath.Clean(path) {
			return true
		}
	}
	return false
}

func (w *Watcher) triggerDebounce() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.debounce != nil {
		w.debounce.Stop()
	}
	w.debounce = time.AfterFunc(w.debounceDelay, func() {
		if w.callback != nil {
			w.callback()
		}
	})
}
