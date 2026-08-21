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
	publicCertFileMode  os.FileMode = 0644
	privateKeyFileMode  os.FileMode = 0600
	fallbackFileMode    os.FileMode = 0644
)

// Result describes the outcome of a sync attempt.
type Result struct {
	Synced     bool
	NoChanges  bool
	SourceFP   string
	DestFP     string
	Fallback   bool
	Error      error
}

// Sync performs a validated atomic sync from source to destination.
func Sync(cfg config.CertificateConfig) (*certutil.CertInfo, *Result, error) {
	res := &Result{}

	certInfo, err := certutil.LoadAndValidate(cfg.Source.Certificate, cfg.Source.PrivateKey)
	if err != nil {
		res.Error = err
		return nil, res, err
	}
	res.SourceFP = certInfo.Fingerprint

	destDir := cfg.Destination.TargetDirectory
	destName := cfg.Destination.TargetName

	destFP, err := ReadDestinationFingerprint(destDir, destName)
	if err == nil {
		res.DestFP = destFP
	}

	if certutil.IsSameFingerprint(certInfo.Fingerprint, destFP) {
		res.NoChanges = true
		if cfg.Fallback {
			if err := WriteFallback(destDir, destName); err != nil {
				res.Error = err
				return certInfo, res, err
			}
			res.Fallback = true
		}
		return certInfo, res, nil
	}

	certPEM, err := os.ReadFile(cfg.Source.Certificate)
	if err != nil {
		res.Error = err
		return certInfo, res, err
	}
	keyPEM, err := os.ReadFile(cfg.Source.PrivateKey)
	if err != nil {
		res.Error = err
		return certInfo, res, err
	}

	if err := AtomicWrite(destDir, destName, certPEM, keyPEM); err != nil {
		res.Error = err
		return certInfo, res, err
	}
	res.Synced = true

	if cfg.Fallback {
		if err := WriteFallback(destDir, destName); err != nil {
			res.Error = err
			return certInfo, res, err
		}
		res.Fallback = true
	}

	return certInfo, res, nil
}

// AtomicWrite writes certificate and key files atomically.
func AtomicWrite(destDir, destName string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	pemPath := filepath.Join(destDir, destName+".pem")
	keyPath := filepath.Join(destDir, destName+".key")
	pemTmp := pemPath + ".tmp"
	keyTmp := keyPath + ".tmp"

	if err := writeAndSync(pemTmp, certPEM, publicCertFileMode); err != nil {
		os.Remove(pemTmp)
		return fmt.Errorf("failed to write certificate temp file: %w", err)
	}
	if err := writeAndSync(keyTmp, keyPEM, privateKeyFileMode); err != nil {
		os.Remove(pemTmp)
		os.Remove(keyTmp)
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

func writeAndSync(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	return nil
}

// ReadDestinationFingerprint reads the fingerprint of the destination certificate.
func ReadDestinationFingerprint(destDir, destName string) (string, error) {
	pemPath := filepath.Join(destDir, destName+".pem")
	data, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}
	return certutil.Fingerprint(data)
}

// WriteFallback writes the fallback.json file used by Zoraxy.
func WriteFallback(destDir, destName string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}
	data, err := json.Marshal(map[string]string{"fallbackCert": destName})
	if err != nil {
		return err
	}
	path := filepath.Join(destDir, "fallback.json")
	tmp := path + ".tmp"
	if err := writeAndSync(tmp, data, fallbackFileMode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ReadFallback reads the currently configured fallback certificate name.
func ReadFallback(destDir string) (string, error) {
	path := filepath.Join(destDir, "fallback.json")
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
