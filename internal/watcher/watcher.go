package watcher

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

// ErrAlreadyStarted is returned when Start is called more than once.
var ErrAlreadyStarted = errors.New("watcher already started")

type lifecycleState uint8

const (
	stateReady lifecycleState = iota
	stateRunning
	stateStopped
)

type fileSnapshot struct {
	exists   bool
	size     int64
	modTime  time.Time
	mode     os.FileMode
	info     os.FileInfo
	digest   [sha256.Size]byte
	digestOK bool
}

// Watcher combines fsnotify and polling with debounce.
type Watcher struct {
	paths           []string
	pollInterval    time.Duration
	debounceDelay   time.Duration
	callback        func()
	fsnotifyEnabled bool
	logger          *slog.Logger

	mu         sync.Mutex
	state      lifecycleState
	generation uint64
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	watcher    *fsnotify.Watcher
	ticker     *time.Ticker
	debounce   *time.Timer
	loopWG     sync.WaitGroup
	callbackWG sync.WaitGroup
	snapshots  map[string]fileSnapshot
}

// New creates a watcher using slog.Default after validating and resolving all paths.
func New(paths []string, pollInterval, debounceDelay time.Duration, fsnotifyEnabled bool, callback func(), policy *config.PathPolicy) (*Watcher, error) {
	return NewWithLogger(paths, pollInterval, debounceDelay, fsnotifyEnabled, callback, policy, slog.Default())
}

// NewWithLogger creates a watcher with an injected logger.
func NewWithLogger(paths []string, pollInterval, debounceDelay time.Duration, fsnotifyEnabled bool, callback func(), policy *config.PathPolicy, logger *slog.Logger) (*Watcher, error) {
	if pollInterval <= 0 {
		return nil, fmt.Errorf("poll interval must be positive")
	}
	if debounceDelay < 0 {
		return nil, fmt.Errorf("debounce delay must not be negative")
	}
	if logger == nil {
		logger = slog.Default()
	}

	resolvedPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		resolved, err := policy.ResolveSource(path, false)
		if err != nil {
			return nil, fmt.Errorf("invalid watcher path: %w", err)
		}
		resolvedPaths = append(resolvedPaths, resolved)
	}

	return &Watcher{
		paths:           resolvedPaths,
		pollInterval:    pollInterval,
		debounceDelay:   debounceDelay,
		callback:        callback,
		fsnotifyEnabled: fsnotifyEnabled,
		logger:          logger,
		done:            make(chan struct{}),
		snapshots:       make(map[string]fileSnapshot, len(resolvedPaths)),
	}, nil
}

// Start begins watching the configured paths. A Watcher cannot be restarted.
func (w *Watcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.state != stateReady {
		return ErrAlreadyStarted
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.ctx = ctx
	w.cancel = cancel
	w.state = stateRunning
	w.generation++
	generation := w.generation

	// Establish the polling baseline before either event loop can report changes.
	for _, path := range w.paths {
		w.snapshots[path] = snapshot(path)
	}

	if w.fsnotifyEnabled {
		fsWatcher, err := fsnotify.NewWatcher()
		if err != nil {
			w.logger.Warn("fsnotify unavailable; using polling only", "error", err)
		} else {
			w.watcher = fsWatcher
			dirs := make(map[string]struct{})
			for _, path := range w.paths {
				dir := filepath.Dir(path)
				if _, ok := dirs[dir]; ok {
					continue
				}
				dirs[dir] = struct{}{}
				if err := fsWatcher.Add(dir); err != nil {
					w.logger.Warn("failed to watch directory; polling will remain active", "directory", dir, "error", err)
				}
			}
			w.loopWG.Add(1)
			go w.fsnotifyLoop(ctx, generation, fsWatcher)
		}
	}

	w.ticker = time.NewTicker(w.pollInterval)
	w.loopWG.Add(1)
	go w.pollLoop(ctx, generation, w.ticker)
	return nil
}

// Stop halts all watchers and waits for any callback already in progress.
func (w *Watcher) Stop() {
	w.mu.Lock()
	if w.state == stateStopped {
		done := w.done
		w.mu.Unlock()
		<-done
		return
	}
	if w.state == stateReady {
		w.state = stateStopped
		w.generation++
		close(w.done)
		w.mu.Unlock()
		return
	}

	w.state = stateStopped
	w.generation++
	w.cancel()
	if w.ticker != nil {
		w.ticker.Stop()
	}
	if w.watcher != nil {
		_ = w.watcher.Close()
	}
	if w.debounce != nil {
		if w.debounce.Stop() {
			w.callbackWG.Done()
		}
		w.debounce = nil
	}
	w.mu.Unlock()

	w.loopWG.Wait()
	w.callbackWG.Wait()
	close(w.done)
}

func (w *Watcher) fsnotifyLoop(ctx context.Context, generation uint64, fsWatcher *fsnotify.Watcher) {
	defer w.loopWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-fsWatcher.Events:
			if !ok {
				return
			}
			if w.matches(event.Name) && event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
				w.triggerDebounce(ctx, generation)
			}
		case err, ok := <-fsWatcher.Errors:
			if !ok {
				return
			}
			w.logger.Warn("fsnotify error", "error", err)
		}
	}
}

func (w *Watcher) pollLoop(ctx context.Context, generation uint64, ticker *time.Ticker) {
	defer w.loopWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if w.pollChanged() {
				w.triggerDebounce(ctx, generation)
			}
		}
	}
}

func (w *Watcher) pollChanged() bool {
	changed := false
	for _, path := range w.paths {
		current := snapshot(path)
		if previous, ok := w.snapshots[path]; !ok || snapshotsDiffer(previous, current) {
			changed = true
		}
		w.snapshots[path] = current
	}
	return changed
}

func snapshot(path string) fileSnapshot {
	info, err := os.Stat(path)
	if err != nil {
		return fileSnapshot{}
	}
	state := fileSnapshot{
		exists:  true,
		size:    info.Size(),
		modTime: info.ModTime(),
		mode:    info.Mode(),
		info:    info,
	}
	if info.Mode().IsRegular() {
		file, err := os.Open(path)
		if err != nil {
			return state
		}
		defer file.Close()
		if openInfo, err := file.Stat(); err == nil {
			state.size = openInfo.Size()
			state.modTime = openInfo.ModTime()
			state.mode = openInfo.Mode()
			state.info = openInfo
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err == nil {
			copy(state.digest[:], hash.Sum(nil))
			state.digestOK = true
		}
	}
	return state
}

func snapshotsDiffer(previous, current fileSnapshot) bool {
	if previous.exists != current.exists {
		return true
	}
	if !current.exists {
		return false
	}
	if previous.size != current.size || !previous.modTime.Equal(current.modTime) || previous.mode != current.mode {
		return true
	}
	if previous.info != nil && current.info != nil && !os.SameFile(previous.info, current.info) {
		return true
	}
	return previous.digestOK != current.digestOK || (current.digestOK && previous.digest != current.digest)
}

func (w *Watcher) matches(path string) bool {
	path = filepath.Clean(path)
	for _, watchedPath := range w.paths {
		if watchedPath == path {
			return true
		}
	}
	return false
}

func (w *Watcher) triggerDebounce(ctx context.Context, generation uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != stateRunning || w.generation != generation || ctx.Err() != nil {
		return
	}

	if w.debounce != nil && w.debounce.Stop() {
		w.callbackWG.Done()
	}

	w.callbackWG.Add(1)
	var timer *time.Timer
	timer = time.AfterFunc(w.debounceDelay, func() {
		defer w.callbackWG.Done()

		w.mu.Lock()
		if w.state != stateRunning || w.generation != generation || ctx.Err() != nil || w.debounce != timer {
			w.mu.Unlock()
			return
		}
		w.debounce = nil
		callback := w.callback
		w.mu.Unlock()

		if callback != nil {
			callback()
		}
	})
	w.debounce = timer
}
