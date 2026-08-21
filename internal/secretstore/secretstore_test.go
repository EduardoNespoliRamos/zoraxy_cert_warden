package secretstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "secrets.json")
	want := testData()

	if err := Save(path, want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestSaveMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, testData()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("mode = %04o, want 0600", got)
	}
}

func TestLoadMissingReturnsEmptyData(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("Load() = %#v, want non-nil empty data", got)
	}
}

func TestLoadRejectsMalformedData(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "malformed", content: `{"entry":`},
		{name: "trailing object", content: `{}` + "\n" + `{}`},
		{name: "trailing token", content: `{} true`},
		{name: "wrong top-level type", content: `[]`},
		{name: "null", content: `null`},
		{name: "wrong credential type", content: `{"entry":"value"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeStore(t, tt.content)
			if _, err := Load(path); err == nil {
				t.Fatal("Load() error = nil, want rejection")
			}
		})
	}
}

func TestLoadRejectsUnknownCredentialFields(t *testing.T) {
	path := writeStore(t, `{
  "entry": {
	"server_url": "https://certwarden.example",
	"certificate_name": "example-certificate",
    "certificate_api_key": "certificate-secret",
    "private_key_api_key": "private-secret",
    "extra": "unexpected"
  }
}`)
	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want unknown field rejection")
	}
}

func TestEmptyData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := Save(path, Data{}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("Load() = %#v, want non-nil empty data", got)
	}
}

func TestValidationRejectsEmptyNamesAndValues(t *testing.T) {
	tests := []struct {
		name string
		data Data
	}{
		{name: "empty name", data: Data{"": validCredentials()}},
		{name: "whitespace name", data: Data{"  ": validCredentials()}},
		{name: "empty server URL", data: Data{"entry": credentialsWith("", "certificate-name", "certificate", "private")}},
		{name: "whitespace server URL", data: Data{"entry": credentialsWith("\t", "certificate-name", "certificate", "private")}},
		{name: "empty certificate name", data: Data{"entry": credentialsWith("https://certwarden.example", "", "certificate", "private")}},
		{name: "whitespace certificate name", data: Data{"entry": credentialsWith("https://certwarden.example", "\n", "certificate", "private")}},
		{name: "empty certificate key", data: Data{"entry": credentialsWith("https://certwarden.example", "certificate-name", "", "private")}},
		{name: "whitespace certificate key", data: Data{"entry": credentialsWith("https://certwarden.example", "certificate-name", "\t", "private")}},
		{name: "empty private key", data: Data{"entry": credentialsWith("https://certwarden.example", "certificate-name", "certificate", "")}},
		{name: "whitespace private key", data: Data{"entry": credentialsWith("https://certwarden.example", "certificate-name", "certificate", "\n")}},
	}
	for _, tt := range tests {
		t.Run(tt.name+" on save", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secrets.json")
			if err := Save(path, tt.data); err == nil {
				t.Fatal("Save() error = nil, want validation error")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid Save() created a file, stat error = %v", err)
			}
		})
		t.Run(tt.name+" on load", func(t *testing.T) {
			encoded, err := marshalForTest(tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Load(writeStore(t, encoded)); err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}

func TestSaveReplacesExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	old := Data{"old": credentialsWith("https://old.example", "old-name", "old-certificate", "old-private")}
	want := Data{"new": credentialsWith("https://new.example", "new-name", "new-certificate", "new-private")}
	if err := Save(path, old); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("replacement Save() error = %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestSaveRenameFailurePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	old := []byte("previous contents\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	fs := renameFailFileSystem{osFileSystem: osFileSystem{}, err: errors.New("injected failure")}
	if err := save(path, testData(), fs); err == nil {
		t.Fatal("save() error = nil, want rename failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, old) {
		t.Fatalf("existing file = %q, want %q", got, old)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestSaveDirectorySyncFailureRestoresExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	old := []byte("previous contents\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	fs := &faultFileSystem{failDirectorySyncCall: 2, fault: errors.New("publish sync failed")}

	err := save(path, testData(), fs)
	if err == nil {
		t.Fatal("save() error = nil, want directory sync failure")
	}
	var rollbackErr *RollbackError
	if errors.As(err, &rollbackErr) {
		t.Fatalf("save() returned RollbackError after successful rollback: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(got, old) {
		t.Fatalf("restored file = %q, want %q", got, old)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestSaveDirectorySyncFailureRemovesNewFileWithoutPreviousStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	fs := &faultFileSystem{failDirectorySyncCall: 1, fault: errors.New("publish sync failed")}

	if err := save(path, testData(), fs); err == nil {
		t.Fatal("save() error = nil, want directory sync failure")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback left newly published file, stat error = %v", err)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestSaveFinalizationFailureRestoresExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	old := []byte("previous contents\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	fs := &faultFileSystem{failBackupRemove: true, fault: errors.New("backup removal failed")}

	if err := save(path, testData(), fs); err == nil {
		t.Fatal("save() error = nil, want finalization failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, old) {
		t.Fatalf("restored file = %q, want %q", got, old)
	}
	assertNoTemporaryFiles(t, dir)
}

func TestSaveRollbackFailureRetainsSanitizedBackup(t *testing.T) {
	const secret = "ROLLBACK-SUPER-SECRET"
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	old := []byte("previous contents\n")
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	fs := &faultFileSystem{
		failDirectorySyncCall: 2,
		failRenameCall:        2,
		fault:                 errors.New(secret),
	}

	err := save(path, testData(), fs)
	var rollbackErr *RollbackError
	if !errors.As(err, &rollbackErr) {
		t.Fatalf("save() error type = %T, want *RollbackError", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("rollback error exposed secret: %v", err)
	}
	if strings.Contains(rollbackErr.SaveErr.Error(), secret) || strings.Contains(rollbackErr.RollbackErr.Error(), secret) {
		t.Fatalf("rollback error details exposed secret: %#v", rollbackErr)
	}
	if rollbackErr.BackupPath == "" {
		t.Fatal("RollbackError did not expose retained backup path")
	}
	backup, readErr := os.ReadFile(rollbackErr.BackupPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !reflect.DeepEqual(backup, old) {
		t.Fatalf("retained backup = %q, want %q", backup, old)
	}
}

func TestErrorsRedactSecrets(t *testing.T) {
	const serverURL = "https://SENSITIVE-SERVER.example"
	const certificateName = "SENSITIVE-CERTIFICATE-NAME"
	const certificateSecret = "CERTIFICATE-SUPER-SECRET"
	const privateSecret = "PRIVATE-SUPER-SECRET"
	tests := []struct {
		name string
		run  func(*testing.T) error
	}{
		{
			name: "unknown field while loading",
			run: func(t *testing.T) error {
				path := writeStore(t, `{"entry":{"server_url":"`+serverURL+`","certificate_name":"`+certificateName+`","certificate_api_key":"`+certificateSecret+`","private_key_api_key":"`+privateSecret+`","`+certificateSecret+`":"`+privateSecret+`"}}`)
				_, err := Load(path)
				return err
			},
		},
		{
			name: "invalid value while saving",
			run: func(t *testing.T) error {
				return Save(filepath.Join(t.TempDir(), "secrets.json"), Data{
					"entry": credentialsWith(serverURL, certificateName, certificateSecret, ""),
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(t)
			if err == nil {
				t.Fatal("error = nil, want failure")
			}
			for _, secret := range []string{serverURL, certificateName, certificateSecret, privateSecret} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error exposed secret: %v", err)
				}
			}
		})
	}
}

func TestCloneAndGetDoNotShareMutableState(t *testing.T) {
	original := testData()
	clone := original.Clone()
	delete(clone, "first")
	clone["second"] = validCredentials()
	if _, ok := original["first"]; !ok {
		t.Fatal("mutating clone changed original")
	}
	if _, ok := original["second"]; ok {
		t.Fatal("adding to clone changed original")
	}

	credentials, ok := original.Get("first")
	if !ok {
		t.Fatal("Get() did not find entry")
	}
	credentials.CertificateAPIKey = "changed"
	if got, _ := original.Get("first"); got.CertificateAPIKey == "changed" {
		t.Fatal("mutating Get() result changed stored credentials")
	}
}

func testData() Data {
	return Data{"first": validCredentials()}
}

func validCredentials() Credentials {
	return credentialsWith("https://certwarden.example", "example-certificate", "certificate-secret", "private-secret")
}

func credentialsWith(serverURL, certificateName, certificateAPIKey, privateKeyAPIKey string) Credentials {
	return Credentials{
		ServerURL:         serverURL,
		CertificateName:   certificateName,
		CertificateAPIKey: certificateAPIKey,
		PrivateKeyAPIKey:  privateKeyAPIKey,
	}
}

func writeStore(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertNoTemporaryFiles(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".secretstore-*.tmp*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func marshalForTest(data Data) (string, error) {
	// Keep test fixture generation independent from Save's validation.
	encoded, err := json.Marshal(data)
	return string(encoded), err
}

type renameFailFileSystem struct {
	osFileSystem
	err error
}

func (fs renameFailFileSystem) Rename(string, string) error {
	return fs.err
}

type faultFileSystem struct {
	osFileSystem
	directorySyncCalls    int
	renameCalls           int
	failDirectorySyncCall int
	failRenameCall        int
	failBackupRemove      bool
	backupRemoveFailed    bool
	fault                 error
}

func (fs *faultFileSystem) Open(path string) (writableFile, error) {
	file, err := fs.osFileSystem.Open(path)
	if err != nil {
		return nil, err
	}
	return &faultWritableFile{writableFile: file, fs: fs}, nil
}

func (fs *faultFileSystem) Rename(oldPath, newPath string) error {
	fs.renameCalls++
	if fs.renameCalls == fs.failRenameCall {
		return fs.fault
	}
	return fs.osFileSystem.Rename(oldPath, newPath)
}

func (fs *faultFileSystem) Remove(path string) error {
	if fs.failBackupRemove && !fs.backupRemoveFailed && strings.HasSuffix(path, ".backup") {
		fs.backupRemoveFailed = true
		return fs.fault
	}
	return fs.osFileSystem.Remove(path)
}

type faultWritableFile struct {
	writableFile
	fs *faultFileSystem
}

func (file *faultWritableFile) Sync() error {
	file.fs.directorySyncCalls++
	if file.fs.directorySyncCalls == file.fs.failDirectorySyncCall {
		return file.fs.fault
	}
	return file.writableFile.Sync()
}
