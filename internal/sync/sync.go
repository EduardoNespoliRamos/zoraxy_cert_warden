package sync

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	stdsync "sync"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

const (
	publicCertFileMode os.FileMode = 0644
	privateKeyFileMode os.FileMode = 0600
	fallbackFileMode   os.FileMode = 0644
)

// Result describes the outcome of a sync attempt.
type Result struct {
	Synced    bool
	NoChanges bool
	SourceFP  string
	DestFP    string
	Fallback  bool
	Error     error
}

type syncFile interface {
	Write([]byte) (int, error)
	Sync() error
	Chmod(os.FileMode) error
	Close() error
	Name() string
}

type filesystem struct {
	lstat      func(string) (os.FileInfo, error)
	readFile   func(string) ([]byte, error)
	mkdirAll   func(string, os.FileMode) error
	createTemp func(string, string) (syncFile, error)
	rename     func(string, string) error
	remove     func(string) error
	readDir    func(string) ([]os.DirEntry, error)
	syncDir    func(string) error
}

var osFilesystem = filesystem{
	lstat: os.Lstat, readFile: os.ReadFile, mkdirAll: os.MkdirAll,
	createTemp: func(dir, pattern string) (syncFile, error) { return os.CreateTemp(dir, pattern) },
	rename:     os.Rename, remove: os.Remove, readDir: os.ReadDir,
	syncDir: func(path string) error {
		dir, err := os.Open(path)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	},
}

// Replacements are serialized per canonical destination while unrelated
// certificate targets remain independent.
var replacementLocks stdsync.Map

// Sync performs a validated sync from source to destination.
func Sync(cfg config.CertificateConfig, policy *config.PathPolicy) (*certutil.CertInfo, *Result, error) {
	res := &Result{}
	if err := cfg.Validate(false, policy); err != nil {
		res.Error = err
		return nil, res, err
	}
	certPath, err := policy.ResolveSource(cfg.Source.Certificate, true)
	if err != nil {
		res.Error = err
		return nil, res, err
	}
	keyPath, err := policy.ResolveSource(cfg.Source.PrivateKey, true)
	if err != nil {
		res.Error = err
		return nil, res, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		res.Error = err
		return nil, res, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		res.Error = err
		return nil, res, err
	}
	certInfo, err := certutil.ValidatePEMPair(certPEM, keyPEM)
	if err != nil {
		res.Error = err
		return nil, res, err
	}
	res.SourceFP = certInfo.Fingerprint

	destDir := cfg.Destination.TargetDirectory
	destName := cfg.Destination.TargetName
	destInfo, destErr := readDestinationPair(destDir, destName, policy, osFilesystem)
	if destErr == nil {
		res.DestFP = destInfo.Fingerprint
		if destInfo.BundleDigest == certInfo.BundleDigest {
			res.NoChanges = true
			if cfg.Fallback {
				if err := WriteFallback(destDir, destName, policy); err != nil {
					res.Error = err
					return certInfo, res, err
				}
				res.Fallback = true
			}
			return certInfo, res, nil
		}
	}

	if err := replacePair(destDir, destName, certPEM, keyPEM, certInfo.BundleDigest, policy, osFilesystem); err != nil {
		res.Error = err
		return certInfo, res, err
	}
	res.Synced = true
	res.DestFP = certInfo.Fingerprint

	if cfg.Fallback {
		if err := WriteFallback(destDir, destName, policy); err != nil {
			res.Error = err
			return certInfo, res, err
		}
		res.Fallback = true
	}
	return certInfo, res, nil
}

// AtomicWrite is retained for callers of the original API. Pair replacement is
// transactional with rollback, not atomic as a unit at the filesystem level.
func AtomicWrite(destDir, destName string, certPEM, keyPEM []byte, policy *config.PathPolicy) error {
	info, err := certutil.ValidatePEMPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid source certificate pair: %w", err)
	}
	return replacePair(destDir, destName, certPEM, keyPEM, info.BundleDigest, policy, osFilesystem)
}

type oldEntry struct {
	path       string
	backupPath string
	existed    bool
	backedUp   bool
}

func replacePair(destDir, destName string, certPEM, keyPEM []byte, expectedDigest string, policy *config.PathPolicy, fsys filesystem) error {
	// Validation deliberately precedes directory creation and all staging writes.
	info, err := certutil.ValidatePEMPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid source certificate pair: %w", err)
	}
	if expectedDigest == "" {
		expectedDigest = info.BundleDigest
	}

	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return err
	}
	lockKey := filepath.Join(resolvedDir, destName)
	lockValue, _ := replacementLocks.LoadOrStore(lockKey, &stdsync.Mutex{})
	lock := lockValue.(*stdsync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	if err := fsys.mkdirAll(resolvedDir, 0755); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	if err := cleanupStaging(resolvedDir, destName, fsys); err != nil {
		return fmt.Errorf("clean stale staging files: %w", err)
	}

	certTmp, err := writeTempFileFS(resolvedDir, "."+destName+"-cert-sync-*.tmp", certPEM, publicCertFileMode, fsys)
	if err != nil {
		return fmt.Errorf("stage certificate: %w", err)
	}
	keyTmp, err := writeTempFileFS(resolvedDir, "."+destName+"-key-sync-*.tmp", keyPEM, privateKeyFileMode, fsys)
	if err != nil {
		_ = fsys.remove(certTmp)
		return fmt.Errorf("stage private key: %w", err)
	}

	certOld := oldEntry{path: filepath.Join(resolvedDir, destName+".pem")}
	keyOld := oldEntry{path: filepath.Join(resolvedDir, destName+".key")}
	cleanupPaths := []string{certTmp, keyTmp}
	defer func() {
		for _, path := range cleanupPaths {
			_ = fsys.remove(path)
		}
	}()

	if err := prepareBackup(&certOld, resolvedDir, "."+destName+"-cert-backup-*.tmp", fsys); err != nil {
		return fmt.Errorf("prepare certificate backup: %w", err)
	}
	if err := prepareBackup(&keyOld, resolvedDir, "."+destName+"-key-backup-*.tmp", fsys); err != nil {
		return failWithRollback(fmt.Errorf("prepare private key backup: %w", err), resolvedDir, &certOld, &keyOld, fsys)
	}

	if err := fsys.rename(certTmp, certOld.path); err != nil {
		return failWithRollback(fmt.Errorf("publish certificate: %w", err), resolvedDir, &certOld, &keyOld, fsys)
	}
	certTmp = ""
	if err := fsys.rename(keyTmp, keyOld.path); err != nil {
		return failWithRollback(fmt.Errorf("publish private key: %w", err), resolvedDir, &certOld, &keyOld, fsys)
	}
	keyTmp = ""

	installed, err := readPairAt(certOld.path, keyOld.path, fsys)
	if err == nil && installed.BundleDigest != expectedDigest {
		err = fmt.Errorf("installed bundle digest mismatch: got %s, want %s", installed.BundleDigest, expectedDigest)
	}
	if err != nil {
		return failWithRollback(fmt.Errorf("validate installed pair: %w", err), resolvedDir, &certOld, &keyOld, fsys)
	}
	if err := fsys.syncDir(resolvedDir); err != nil {
		return failWithRollback(fmt.Errorf("sync target directory: %w", err), resolvedDir, &certOld, &keyOld, fsys)
	}

	for _, old := range []*oldEntry{&certOld, &keyOld} {
		if old.backupPath != "" {
			if err := fsys.remove(old.backupPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("installed pair is valid but backup cleanup failed: %w", err)
			}
			old.backupPath = ""
		}
	}
	if err := fsys.syncDir(resolvedDir); err != nil {
		return fmt.Errorf("installed pair is valid but final directory sync failed: %w", err)
	}
	return nil
}

func prepareBackup(old *oldEntry, dir, pattern string, fsys filesystem) error {
	_, err := fsys.lstat(old.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	old.existed = true
	marker, err := fsys.createTemp(dir, pattern)
	if err != nil {
		return err
	}
	old.backupPath = marker.Name()
	if err := marker.Close(); err != nil {
		_ = fsys.remove(old.backupPath)
		old.backupPath = ""
		return err
	}
	if err := fsys.remove(old.backupPath); err != nil {
		old.backupPath = ""
		return err
	}
	if err := fsys.rename(old.path, old.backupPath); err != nil {
		old.backupPath = ""
		return err
	}
	old.backedUp = true
	return nil
}

func failWithRollback(original error, dir string, certOld, keyOld *oldEntry, fsys filesystem) error {
	certState, certErr := restoreEntry(certOld, fsys)
	keyState, keyErr := restoreEntry(keyOld, fsys)
	dirErr := fsys.syncDir(dir)

	var validationErr error
	if certOld.existed && keyOld.existed && certErr == nil && keyErr == nil {
		_, validationErr = readPairAt(certOld.path, keyOld.path, fsys)
		if validationErr != nil {
			validationErr = fmt.Errorf("restored pair validation: %w", validationErr)
		}
	}
	rollbackErr := errors.Join(certErr, keyErr, validationErr, dirErr)
	state := fmt.Sprintf("rollback states: certificate=%s, private key=%s", certState, keyState)
	if rollbackErr != nil {
		return errors.Join(original, fmt.Errorf("%s: %w", state, rollbackErr))
	}
	return fmt.Errorf("%w; %s", original, state)
}

func restoreEntry(old *oldEntry, fsys filesystem) (string, error) {
	if old.existed {
		if !old.backedUp {
			return "unchanged", nil
		}
		if err := fsys.remove(old.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "unknown", fmt.Errorf("remove current %s: %w", old.path, err)
		}
		if err := fsys.rename(old.backupPath, old.path); err != nil {
			return "unknown", fmt.Errorf("restore %s: %w", old.path, err)
		}
		old.backedUp = false
		old.backupPath = ""
		return "restored", nil
	}
	if err := fsys.remove(old.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "unknown", fmt.Errorf("restore absence of %s: %w", old.path, err)
	}
	return "absent", nil
}

func cleanupStaging(dir, destName string, fsys filesystem) error {
	entries, err := fsys.readDir(dir)
	if err != nil {
		return err
	}
	prefixes := []string{"." + destName + "-cert-sync-", "." + destName + "-key-sync-"}
	for _, entry := range entries {
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".tmp") {
				if err := fsys.remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			}
		}
	}
	return nil
}

func writeTempFileFS(dir, pattern string, data []byte, mode os.FileMode, fsys filesystem) (string, error) {
	file, err := fsys.createTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = fsys.remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return "", err
	}
	if err := file.Chmod(mode); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func readDestinationPair(destDir, destName string, policy *config.PathPolicy, fsys filesystem) (*certutil.CertInfo, error) {
	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return nil, err
	}
	return readPairAt(filepath.Join(resolvedDir, destName+".pem"), filepath.Join(resolvedDir, destName+".key"), fsys)
}

func readPairAt(certPath, keyPath string, fsys filesystem) (*certutil.CertInfo, error) {
	certInfo, certStatErr := fsys.lstat(certPath)
	keyInfo, keyStatErr := fsys.lstat(keyPath)
	if err := errors.Join(wrapPathError("inspect certificate", certStatErr), wrapPathError("inspect private key", keyStatErr)); err != nil {
		return nil, err
	}
	if certInfo.Mode()&os.ModeSymlink != 0 || keyInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("destination certificate pair contains a symlink")
	}
	if !certInfo.Mode().IsRegular() || !keyInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("destination certificate pair must contain regular files")
	}
	certPEM, certReadErr := fsys.readFile(certPath)
	keyPEM, keyReadErr := fsys.readFile(keyPath)
	if err := errors.Join(wrapPathError("read certificate", certReadErr), wrapPathError("read private key", keyReadErr)); err != nil {
		return nil, err
	}
	if certInfo.Mode().Perm() != publicCertFileMode || keyInfo.Mode().Perm() != privateKeyFileMode {
		return nil, fmt.Errorf("destination modes are certificate=%04o private-key=%04o", certInfo.Mode().Perm(), keyInfo.Mode().Perm())
	}
	return certutil.ValidatePEMPair(certPEM, keyPEM)
}

func wrapPathError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// ReadDestinationFingerprint reads the validated destination pair's leaf fingerprint.
func ReadDestinationFingerprint(destDir, destName string, policy *config.PathPolicy) (string, error) {
	info, err := readDestinationPair(destDir, destName, policy, osFilesystem)
	if err != nil {
		return "", err
	}
	return info.Fingerprint, nil
}

// WriteFallback writes the fallback.json file used by Zoraxy.
func WriteFallback(destDir, destName string, policy *config.PathPolicy) error {
	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(resolvedDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}
	data, err := json.Marshal(map[string]string{"fallbackCert": destName})
	if err != nil {
		return err
	}
	tmp, err := writeTempFileFS(resolvedDir, ".fallback-*.json.tmp", data, fallbackFileMode, osFilesystem)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, filepath.Join(resolvedDir, "fallback.json"))
}

// ReadFallback reads the currently configured fallback certificate name.
func ReadFallback(destDir string, policy *config.PathPolicy) (string, error) {
	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return "", err
	}
	path := filepath.Join(resolvedDir, "fallback.json")
	if err := rejectSymlink(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var fb struct {
		FallbackCert string `json:"fallbackCert"`
	}
	if err := json.Unmarshal(data, &fb); err != nil {
		return "", err
	}
	return fb.FallbackCert, nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to read symlink: %s", path)
	}
	return nil
}
