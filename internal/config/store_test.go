package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStoreSaveFailurePreservesCallerOldFileAndCleansTemps(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		call      int
	}{
		{name: "temp create", operation: "create", call: 1},
		{name: "temp write", operation: "write", call: 1},
		{name: "temp sync", operation: "file-sync", call: 1},
		{name: "backup directory sync", operation: "dir-sync", call: 1},
		{name: "replacement rename", operation: "rename", call: 1},
		{name: "replacement directory sync", operation: "dir-sync", call: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			old := []byte("old config\n")
			if err := os.WriteFile(path, old, 0640); err != nil {
				t.Fatal(err)
			}
			cfg := saveTestConfig(dir)
			wantCaller := cfg.Clone()
			fs := newFaultFileSystem()
			fs.fail(tt.operation, tt.call, errors.New("injected "+tt.operation+" failure"))

			if err := NewStore(fs).Save(cfg, path, broadTestPolicy(t)); err == nil {
				t.Fatal("expected Save to fail")
			}
			if !reflect.DeepEqual(cfg, wantCaller) {
				t.Fatalf("Save mutated caller:\n got: %#v\nwant: %#v", cfg, wantCaller)
			}
			assertFile(t, path, old, 0640)
			assertNoStoreTemps(t, dir)
		})
	}
}

func TestStoreSaveChmodsBeforeSyncAndPersistsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	fs := newFaultFileSystem()
	if err := NewStore(fs).Save(saveTestConfig(dir), path, broadTestPolicy(t)); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	chmodIndex := eventIndex(fs.events, "chmod")
	syncIndex := eventIndex(fs.events, "file-sync")
	if chmodIndex < 0 || syncIndex < 0 || chmodIndex >= syncIndex {
		t.Fatalf("expected chmod before file sync, events: %v", fs.events)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("saved mode = %04o, want 0600", got)
	}
	assertNoStoreTemps(t, dir)
}

func TestStoreSaveRollsBackAbsentPreviousConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	fs := newFaultFileSystem()
	fs.fail("dir-sync", 1, errors.New("replacement sync failed"))

	err := NewStore(fs).Save(saveTestConfig(dir), path, broadTestPolicy(t))
	if err == nil || !strings.Contains(err.Error(), "failed to sync config directory") {
		t.Fatalf("expected directory sync error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rollback should restore absent config, stat error = %v", err)
	}
	assertNoStoreTemps(t, dir)
}

func TestStoreSaveExposesRollbackFailureAndRetainsBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := []byte("old config\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	fs := newFaultFileSystem()
	fs.fail("dir-sync", 2, errors.New("replacement sync failed"))
	fs.fail("rename", 2, errors.New("rollback rename failed"))

	err := NewStore(fs).Save(saveTestConfig(dir), path, broadTestPolicy(t))
	var rollbackErr *RollbackError
	if !errors.As(err, &rollbackErr) {
		t.Fatalf("expected RollbackError, got %T: %v", err, err)
	}
	if !strings.Contains(rollbackErr.SaveErr.Error(), "replacement sync failed") {
		t.Fatalf("missing save failure detail: %v", rollbackErr.SaveErr)
	}
	if !strings.Contains(rollbackErr.RollbackErr.Error(), "rollback rename failed") {
		t.Fatalf("missing rollback failure detail: %v", rollbackErr.RollbackErr)
	}
	if rollbackErr.BackupPath == "" {
		t.Fatal("rollback error did not expose retained backup path")
	}
	assertFile(t, rollbackErr.BackupPath, old, 0600)
}

func TestStoreSaveRollbackDirectorySyncFailureIsDetailed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := []byte("old config\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	fs := newFaultFileSystem()
	fs.fail("dir-sync", 2, errors.New("replacement sync failed"))
	fs.fail("dir-sync", 3, errors.New("rollback sync failed"))

	err := NewStore(fs).Save(saveTestConfig(dir), path, broadTestPolicy(t))
	var rollbackErr *RollbackError
	if !errors.As(err, &rollbackErr) {
		t.Fatalf("expected RollbackError, got %T: %v", err, err)
	}
	if !strings.Contains(rollbackErr.RollbackErr.Error(), "rollback sync failed") {
		t.Fatalf("missing rollback sync detail: %v", rollbackErr.RollbackErr)
	}
	if rollbackErr.BackupPath != "" {
		t.Fatalf("rollback consumed backup but reported it at %s", rollbackErr.BackupPath)
	}
	assertFile(t, path, old, 0600)
	assertNoStoreTemps(t, dir)
}

func saveTestConfig(dir string) *Config {
	cfg := DefaultConfig()
	cfg.LogLevel = " INFO "
	cfg.Certificates[0].Destination.TargetDirectory = dir
	return cfg
}

func assertFile(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("file %s = %q, want %q", path, got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if gotMode := info.Mode().Perm(); gotMode != mode {
		t.Fatalf("file %s mode = %04o, want %04o", path, gotMode, mode)
	}
}

func assertNoStoreTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".config-*.json.tmp*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", matches)
	}
}

func eventIndex(events []string, event string) int {
	for i, got := range events {
		if got == event {
			return i
		}
	}
	return -1
}

type faultFileSystem struct {
	osFileSystem
	calls  map[string]int
	faults map[string]map[int]error
	events []string
}

func newFaultFileSystem() *faultFileSystem {
	return &faultFileSystem{
		calls:  make(map[string]int),
		faults: make(map[string]map[int]error),
	}
}

func (fs *faultFileSystem) fail(operation string, call int, err error) {
	if fs.faults[operation] == nil {
		fs.faults[operation] = make(map[int]error)
	}
	fs.faults[operation][call] = err
}

func (fs *faultFileSystem) hit(operation string) error {
	fs.events = append(fs.events, operation)
	fs.calls[operation]++
	return fs.faults[operation][fs.calls[operation]]
}

func (fs *faultFileSystem) CreateTemp(dir, pattern string) (File, error) {
	if err := fs.hit("create"); err != nil {
		return nil, err
	}
	file, err := fs.osFileSystem.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &faultFile{File: file, fs: fs, directory: false}, nil
}

func (fs *faultFileSystem) Open(path string) (File, error) {
	file, err := fs.osFileSystem.Open(path)
	if err != nil {
		return nil, err
	}
	return &faultFile{File: file, fs: fs, directory: true}, nil
}

func (fs *faultFileSystem) Rename(oldPath, newPath string) error {
	if err := fs.hit("rename"); err != nil {
		return err
	}
	return fs.osFileSystem.Rename(oldPath, newPath)
}

type faultFile struct {
	File
	fs        *faultFileSystem
	directory bool
}

func (f *faultFile) Chmod(mode os.FileMode) error {
	if err := f.fs.hit("chmod"); err != nil {
		return err
	}
	return f.File.Chmod(mode)
}

func (f *faultFile) Write(data []byte) (int, error) {
	if err := f.fs.hit("write"); err != nil {
		return 0, err
	}
	return f.File.Write(data)
}

func (f *faultFile) Sync() error {
	operation := "file-sync"
	if f.directory {
		operation = "dir-sync"
	}
	if err := f.fs.hit(operation); err != nil {
		return err
	}
	return f.File.Sync()
}
