package sync

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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

// Sync performs a validated atomic sync from source to destination.
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

	destFP, err := ReadDestinationFingerprint(destDir, destName, policy)
	if err == nil {
		res.DestFP = destFP
	}

	if certutil.IsSameFingerprint(certInfo.Fingerprint, destFP) {
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

	if err := AtomicWrite(destDir, destName, certPEM, keyPEM, policy); err != nil {
		res.Error = err
		return certInfo, res, err
	}
	res.Synced = true

	if cfg.Fallback {
		if err := WriteFallback(destDir, destName, policy); err != nil {
			res.Error = err
			return certInfo, res, err
		}
		res.Fallback = true
	}

	return certInfo, res, nil
}

// AtomicWrite writes certificate and key files atomically.
func AtomicWrite(destDir, destName string, certPEM, keyPEM []byte, policy *config.PathPolicy) error {
	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return err
	}
	destDir = resolvedDir
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	pemPath := filepath.Join(destDir, destName+".pem")
	keyPath := filepath.Join(destDir, destName+".key")

	pemTmp, err := writeTempFile(destDir, "."+destName+"-*.pem.tmp", certPEM, publicCertFileMode)
	if err != nil {
		return fmt.Errorf("failed to write certificate temp file: %w", err)
	}
	keyTmp, err := writeTempFile(destDir, "."+destName+"-*.key.tmp", keyPEM, privateKeyFileMode)
	if err != nil {
		os.Remove(pemTmp)
		return fmt.Errorf("failed to write private key temp file: %w", err)
	}

	if err := os.Rename(keyTmp, keyPath); err != nil {
		os.Remove(pemTmp)
		os.Remove(keyTmp)
		return fmt.Errorf("failed to rename private key file: %w", err)
	}
	if err := os.Rename(pemTmp, pemPath); err != nil {
		os.Remove(pemTmp)
		return fmt.Errorf("failed to rename certificate file: %w", err)
	}

	return nil
}

func writeTempFile(dir, pattern string, data []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(path)
		}
	}()

	if _, err := file.Write(data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Chmod(mode); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

// ReadDestinationFingerprint reads the fingerprint of the destination certificate.
func ReadDestinationFingerprint(destDir, destName string, policy *config.PathPolicy) (string, error) {
	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return "", err
	}
	destDir = resolvedDir
	pemPath := filepath.Join(destDir, destName+".pem")
	if err := rejectSymlink(pemPath); err != nil {
		return "", err
	}
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}
	return certutil.Fingerprint(data)
}

// WriteFallback writes the fallback.json file used by Zoraxy.
func WriteFallback(destDir, destName string, policy *config.PathPolicy) error {
	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return err
	}
	destDir = resolvedDir
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}
	data, err := json.Marshal(map[string]string{"fallbackCert": destName})
	if err != nil {
		return err
	}
	path := filepath.Join(destDir, "fallback.json")
	tmp, err := writeTempFile(destDir, ".fallback-*.json.tmp", data, fallbackFileMode)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, path)
}

// ReadFallback reads the currently configured fallback certificate name.
func ReadFallback(destDir string, policy *config.PathPolicy) (string, error) {
	resolvedDir, err := policy.ResolveDestination(destDir, false)
	if err != nil {
		return "", err
	}
	destDir = resolvedDir
	path := filepath.Join(destDir, "fallback.json")
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
