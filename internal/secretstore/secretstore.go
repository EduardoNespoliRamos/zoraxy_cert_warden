// Package secretstore persists API credentials separately from plugin configuration.
package secretstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Credentials binds API keys to one remote certificate identity.
type Credentials struct {
	ServerURL         string `json:"server_url"`
	CertificateName   string `json:"certificate_name"`
	CertificateAPIKey string `json:"certificate_api_key"`
	PrivateKeyAPIKey  string `json:"private_key_api_key"`
}

// Data maps immutable plugin certificate entry names to their credentials.
type Data map[string]Credentials

// RollbackError reports that Save could not restore the previous state.
// BackupPath is set when the previous store remains available for recovery.
type RollbackError struct {
	SaveErr     error
	RollbackErr error
	BackupPath  string
}

func (e *RollbackError) Error() string {
	if e.BackupPath != "" {
		return fmt.Sprintf("%v; rollback failed: %v (previous data retained in backup)", e.SaveErr, e.RollbackErr)
	}
	return fmt.Sprintf("%v; rollback failed: %v", e.SaveErr, e.RollbackErr)
}

// Unwrap exposes the sanitized save failure.
func (e *RollbackError) Unwrap() error {
	return e.SaveErr
}

// Clone returns an independent copy of d.
func (d Data) Clone() Data {
	clone := make(Data, len(d))
	for name, credentials := range d {
		clone[name] = credentials
	}
	return clone
}

// Get returns a copy of the credentials for name.
func (d Data) Get(name string) (Credentials, bool) {
	credentials, ok := d[name]
	return credentials, ok
}

// Load reads and validates a secret store. A missing file returns empty data.
func Load(path string) (Data, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Data{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open secret store: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var data Data
	if err := decoder.Decode(&data); err != nil {
		return nil, errors.New("decode secret store: invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode secret store: trailing JSON data")
	}
	if data == nil {
		return nil, errors.New("validate secret store: data must be a JSON object")
	}
	if err := validate(data); err != nil {
		return nil, err
	}
	return data.Clone(), nil
}

// Save validates and durably replaces a secret store.
func Save(path string, data Data) error {
	return save(path, data, osFileSystem{})
}

func validate(data Data) error {
	for name, credentials := range data {
		if strings.TrimSpace(name) == "" {
			return errors.New("validate secret store: certificate entry name must not be empty")
		}
		if strings.TrimSpace(credentials.ServerURL) == "" {
			return fmt.Errorf("validate secret store entry %q: server URL must not be empty", name)
		}
		if strings.TrimSpace(credentials.CertificateName) == "" {
			return fmt.Errorf("validate secret store entry %q: certificate name must not be empty", name)
		}
		if strings.TrimSpace(credentials.CertificateAPIKey) == "" {
			return fmt.Errorf("validate secret store entry %q: certificate API key must not be empty", name)
		}
		if strings.TrimSpace(credentials.PrivateKeyAPIKey) == "" {
			return fmt.Errorf("validate secret store entry %q: private key API key must not be empty", name)
		}
	}
	return nil
}

type writableFile interface {
	io.Writer
	Name() string
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

type fileSystem interface {
	MkdirAll(string, os.FileMode) error
	CreateTemp(string, string) (writableFile, error)
	Stat(string) (os.FileInfo, error)
	Link(string, string) error
	Rename(string, string) error
	Remove(string) error
	Open(string) (writableFile, error)
}

func save(path string, data Data, fs fileSystem) error {
	data = data.Clone()
	if err := validate(data); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.New("encode secret store")
	}
	encoded = append(encoded, '\n')

	dir := filepath.Dir(path)
	if err := fs.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create secret store directory: %w", err)
	}
	temp, err := fs.CreateTemp(dir, ".secretstore-*.tmp")
	if err != nil {
		return fmt.Errorf("create secret store temporary file: %w", err)
	}
	tempPath := temp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temp.Close()
		}
		_ = fs.Remove(tempPath)
	}()

	if err := temp.Chmod(0600); err != nil {
		return fmt.Errorf("secure secret store temporary file: %w", err)
	}
	if _, err := temp.Write(encoded); err != nil {
		return fmt.Errorf("write secret store temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync secret store temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		closed = true
		return fmt.Errorf("close secret store temporary file: %w", err)
	}
	closed = true

	backupPath := tempPath + ".backup"
	hadPrevious := false
	if _, err := fs.Stat(path); err == nil {
		hadPrevious = true
		if err := fs.Link(path, backupPath); err != nil {
			return fmt.Errorf("create secret store backup: %w", err)
		}
		if err := syncDirectory(fs, dir); err != nil {
			_ = fs.Remove(backupPath)
			return fmt.Errorf("sync secret store backup: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing secret store: %w", err)
	}

	keepBackup := false
	defer func() {
		if !keepBackup {
			_ = fs.Remove(backupPath)
		}
	}()
	if err := fs.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace secret store: %w", err)
	}
	if err := syncDirectory(fs, dir); err != nil {
		rollbackErr, backupRetained := rollback(fs, path, backupPath, dir, hadPrevious)
		if rollbackErr != nil {
			keepBackup = backupRetained
			return newRollbackError("sync secret store directory", backupPath, backupRetained)
		}
		return errors.New("sync secret store directory")
	}
	if hadPrevious {
		if err := fs.Remove(backupPath); err != nil {
			rollbackErr, backupRetained := rollback(fs, path, backupPath, dir, true)
			if rollbackErr != nil {
				keepBackup = backupRetained
				return newRollbackError("finalize secret store replacement", backupPath, backupRetained)
			}
			return errors.New("finalize secret store replacement")
		}
	}
	return nil
}

func newRollbackError(saveOperation, backupPath string, backupRetained bool) *RollbackError {
	return &RollbackError{
		SaveErr:     errors.New(saveOperation),
		RollbackErr: errors.New("restore previous secret store state"),
		BackupPath:  retainedBackup(backupPath, backupRetained),
	}
}

func rollback(fs fileSystem, path, backupPath, dir string, hadPrevious bool) (err error, backupRetained bool) {
	if hadPrevious {
		if err := fs.Rename(backupPath, path); err != nil {
			return err, true
		}
	} else if err := fs.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err, false
	}
	if err := syncDirectory(fs, dir); err != nil {
		return err, false
	}
	return nil, false
}

func retainedBackup(path string, retained bool) string {
	if retained {
		return path
	}
	return ""
}

func syncDirectory(fs fileSystem, path string) error {
	dir, err := fs.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

type osFileSystem struct{}

func (osFileSystem) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func (osFileSystem) CreateTemp(dir, pattern string) (writableFile, error) {
	return os.CreateTemp(dir, pattern)
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

func (osFileSystem) Open(path string) (writableFile, error) {
	return os.Open(path)
}
