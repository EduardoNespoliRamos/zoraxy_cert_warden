package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// File is the subset of an OS file needed to persist configuration safely.
type File interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

// FileSystem contains the filesystem operations used by Store. It allows
// callers to inject faulting implementations when verifying persistence.
type FileSystem interface {
	CreateTemp(dir, pattern string) (File, error)
	Open(path string) (File, error)
	Stat(path string) (os.FileInfo, error)
	Link(oldPath, newPath string) error
	Rename(oldPath, newPath string) error
	Remove(path string) error
}

// Store persists configurations using an injectable filesystem.
type Store struct {
	fs FileSystem
}

// RollbackError reports both the save failure and a failure to durably restore
// the previous configuration. BackupPath is populated when a recovery copy
// remains available on disk.
type RollbackError struct {
	SaveErr     error
	RollbackErr error
	BackupPath  string
}

func (e *RollbackError) Error() string {
	if e.BackupPath != "" {
		return fmt.Sprintf("%v; rollback failed: %v (previous config retained at %s)", e.SaveErr, e.RollbackErr, e.BackupPath)
	}
	return fmt.Sprintf("%v; rollback failed: %v", e.SaveErr, e.RollbackErr)
}

// Unwrap exposes the original save failure.
func (e *RollbackError) Unwrap() error {
	return e.SaveErr
}

// NewStore creates a configuration store. A nil filesystem uses the OS.
func NewStore(fs FileSystem) *Store {
	if fs == nil {
		fs = osFileSystem{}
	}
	return &Store{fs: fs}
}

// Save validates and durably replaces a configuration file. If an operation
// after replacement fails, Save restores the prior file before returning.
func (s *Store) Save(cfg *Config, path string, policy *PathPolicy) error {
	normalized := cfg.Clone()
	if normalized == nil {
		return fmt.Errorf("configuration is required")
	}
	normalized.Normalize()
	if err := normalized.Validate(false, policy); err != nil {
		return err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	tmpFile, err := s.fs.CreateTemp(dir, ".config-*.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create config temp file: %w", err)
	}
	tmp := tmpFile.Name()
	defer s.fs.Remove(tmp)
	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to secure config temp file: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write config temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync config temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close config temp file: %w", err)
	}

	backup := tmp + ".backup"
	hadPrevious := false
	if _, err := s.fs.Stat(path); err == nil {
		hadPrevious = true
		if err := s.fs.Link(path, backup); err != nil {
			return fmt.Errorf("failed to create config backup: %w", err)
		}
		if err := s.syncDir(dir); err != nil {
			_ = s.fs.Remove(backup)
			return fmt.Errorf("failed to sync config backup: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to inspect existing config: %w", err)
	}

	keepBackup := false
	defer func() {
		if !keepBackup {
			_ = s.fs.Remove(backup)
		}
	}()
	if err := s.fs.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to rename config file: %w", err)
	}

	if err := s.syncDir(dir); err != nil {
		saveErr := fmt.Errorf("failed to sync config directory: %w", err)
		rollbackErr, backupRetained := s.rollback(path, backup, dir, hadPrevious)
		if rollbackErr != nil {
			keepBackup = backupRetained
			return &RollbackError{SaveErr: saveErr, RollbackErr: rollbackErr, BackupPath: retainedBackup(backup, backupRetained)}
		}
		return saveErr
	}
	if hadPrevious {
		if err := s.fs.Remove(backup); err != nil {
			saveErr := fmt.Errorf("failed to remove config backup: %w", err)
			rollbackErr, backupRetained := s.rollback(path, backup, dir, true)
			if rollbackErr != nil {
				keepBackup = backupRetained
				return &RollbackError{SaveErr: saveErr, RollbackErr: rollbackErr, BackupPath: retainedBackup(backup, backupRetained)}
			}
			return saveErr
		}
	}
	return nil
}

func (s *Store) rollback(path, backup, dir string, hadPrevious bool) (err error, backupRetained bool) {
	if hadPrevious {
		if err := s.fs.Rename(backup, path); err != nil {
			return fmt.Errorf("failed to restore previous config: %w", err), true
		}
	} else if err := s.fs.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove replacement config: %w", err), false
	}
	if err := s.syncDir(dir); err != nil {
		return fmt.Errorf("failed to sync restored config directory: %w", err), false
	}
	return nil, false
}

func (s *Store) syncDir(path string) error {
	dir, err := s.fs.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func retainedBackup(path string, retain bool) string {
	if retain {
		return path
	}
	return ""
}

type osFileSystem struct{}

func (osFileSystem) CreateTemp(dir, pattern string) (File, error) {
	return os.CreateTemp(dir, pattern)
}

func (osFileSystem) Open(path string) (File, error) {
	return os.Open(path)
}

func (osFileSystem) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (osFileSystem) Link(oldPath, newPath string) error {
	return os.Link(oldPath, newPath)
}

func (osFileSystem) Rename(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func (osFileSystem) Remove(path string) error {
	return os.Remove(path)
}
