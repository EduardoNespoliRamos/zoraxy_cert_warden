package watcher

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

func TestWatcher_Polling(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "watch.txt")
	if err := os.WriteFile(file, []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}

	var count atomic.Int32
	policy := watcherTestPolicy(t, dir)
	w, err := New([]string{file}, 100*time.Millisecond, 200*time.Millisecond, false, func() {
		count.Add(1)
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	time.Sleep(300 * time.Millisecond)
	if err := os.WriteFile(file, []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(600 * time.Millisecond)
	if count.Load() < 1 {
		t.Fatal("expected callback to be triggered")
	}
}

func TestWatcher_Debounce(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "watch.txt")
	if err := os.WriteFile(file, []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}

	var count atomic.Int32
	policy := watcherTestPolicy(t, dir)
	w, err := New([]string{file}, 100*time.Millisecond, 300*time.Millisecond, false, func() {
		count.Add(1)
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := os.WriteFile(file, []byte(string('b'+byte(i))), 0644); err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(800 * time.Millisecond)
	if count.Load() != 1 {
		t.Fatalf("expected exactly one callback after debounce, got %d", count.Load())
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
