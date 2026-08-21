package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
)

const maxRequestBodyBytes int64 = 64 << 10

var (
	errCertificateExists   = errors.New("certificate already exists")
	errCertificateNotFound = errors.New("certificate not found")
)

// ConfigMutation changes a manager-owned candidate while config application is
// serialized. The candidate is discarded if the mutation or apply fails.
type ConfigMutation func(*config.Config) error

// CredentialMutation updates the write-only credentials associated with an
// immutable certificate entry name. Nil API key values preserve existing keys.
type CredentialMutation struct {
	Name              string
	CertificateAPIKey *string
	PrivateKeyAPIKey  *string
	Delete            bool
}

// Manager is the sole owner of configuration and runtime state used by HTTP.
type Manager interface {
	SnapshotConfig() *config.Config
	SnapshotStatus() []status.CertificateStatus
	ApplyConfig(context.Context, *config.Config) error
	MutateConfig(context.Context, ConfigMutation) error
	MutateConfigAndCredentials(context.Context, ConfigMutation, *CredentialMutation) error
	CredentialsConfigured(string) (bool, bool)
	SyncCertificate(string) error
	ValidateCertificate(string) error
	TestCertWardenConnection(context.Context, string, string, string, string) error
	FallbackRestartPending() bool
	AcknowledgeFallbackRestart(context.Context) error
}

type credentialInput struct {
	CertificateAPIKey           *string `json:"certificate_api_key,omitempty"`
	PrivateKeyAPIKey            *string `json:"private_key_api_key,omitempty"`
	CertificateAPIKeyConfigured bool    `json:"certificate_api_key_configured,omitempty"`
	PrivateKeyAPIKeyConfigured  bool    `json:"private_key_api_key_configured,omitempty"`
}

type certificateRequest struct {
	config.CertificateConfig
	Credentials *credentialInput `json:"cert_warden_credentials,omitempty"`
}

type credentialState struct {
	CertificateAPIKey bool `json:"certificate_api_key_configured"`
	PrivateKeyAPIKey  bool `json:"private_key_api_key_configured"`
}

type certificateView struct {
	config.CertificateConfig
	Credentials *credentialState `json:"cert_warden_credentials,omitempty"`
}

type configView struct {
	Certificates []certificateView `json:"certificates"`
	LogLevel     string            `json:"log_level,omitempty"`
}

type configRequest struct {
	Certificates []certificateRequest `json:"certificates"`
	LogLevel     string               `json:"log_level,omitempty"`
}

type certWardenTestRequest struct {
	ServerURL         string `json:"server_url"`
	CertificateName   string `json:"certificate_name"`
	CertificateAPIKey string `json:"certificate_api_key"`
	PrivateKeyAPIKey  string `json:"private_key_api_key"`
}

// Server provides HTTP handlers for the plugin UI and API.
type Server struct {
	manager Manager
	logger  *slog.Logger
}

// NewServer creates a server backed only by manager service operations.
func NewServer(manager Manager, logger ...*slog.Logger) *Server {
	log := slog.Default()
	if len(logger) > 0 && logger[0] != nil {
		log = logger[0]
	}
	return &Server{manager: manager, logger: log}
}

// Handler rejects paths ServeMux would otherwise normalize and redirect.
func (s *Server) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := path.Clean(r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/") && cleanPath != "/" {
			cleanPath += "/"
		}
		if strings.Contains(r.URL.Path, "//") || cleanPath != r.URL.Path {
			s.sendError(w, "not found", http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RegisterRoutes registers all plugin API routes on the provided mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux, _ string) {
	s.registerRoutes(mux, "")
}

// RegisterRoutesUnderPrefix registers the same routes under the UI proxy path.
func (s *Server) RegisterRoutesUnderPrefix(mux *http.ServeMux, prefix string) {
	s.registerRoutes(mux, strings.TrimSuffix(prefix, "/"))
}

func (s *Server) registerRoutes(mux *http.ServeMux, prefix string) {
	health := prefix + "/health"
	api := prefix + "/api"
	certificates := api + "/certificates"

	mux.HandleFunc(health, s.allow([]string{http.MethodGet}, s.handleHealth))
	mux.HandleFunc(health+"/", s.handleNotFound)
	mux.HandleFunc(api+"/status", s.allow([]string{http.MethodGet}, s.handleStatus))
	mux.HandleFunc(api+"/config", s.allow([]string{http.MethodGet, http.MethodPost}, s.handleConfig))
	mux.HandleFunc(api+"/certwarden/test", s.allow([]string{http.MethodPost}, s.handleCertWardenTest))
	mux.HandleFunc(certificates, s.allow([]string{http.MethodGet, http.MethodPost}, s.handleCertificates))
	mux.HandleFunc(certificates+"/", func(w http.ResponseWriter, r *http.Request) {
		s.handleCertificatePath(w, r, certificates)
	})
	mux.HandleFunc(api+"/fallback/restart/acknowledge", s.allow([]string{http.MethodPost}, s.handleFallbackRestartAcknowledge))
	mux.HandleFunc(api+"/", s.handleNotFound)
}

func (s *Server) handleCertWardenTest(w http.ResponseWriter, r *http.Request) {
	var request certWardenTestRequest
	if !s.decodeJSON(w, r, &request) {
		return
	}
	if err := s.manager.TestCertWardenConnection(r.Context(), request.ServerURL, request.CertificateName, request.CertificateAPIKey, request.PrivateKeyAPIKey); err != nil {
		s.managerError(w, r, "test Cert Warden connection", err)
		return
	}
	sendOK(w)
}

func (s *Server) allow(methods []string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, method := range methods {
			if r.Method == method {
				next(w, r)
				return
			}
		}
		w.Header().Set("Allow", strings.Join(methods, ", "))
		s.sendError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	s.sendError(w, "not found", http.StatusNotFound)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	agg := s.aggregate()
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"status": agg.Status, "certificates": agg.Certificates,
		"healthy": agg.Healthy, "errors": agg.Errors,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.sendJSON(w, http.StatusOK, s.aggregate())
}

func (s *Server) aggregate() status.AggregatedStatus {
	return status.Aggregate(s.manager.SnapshotStatus(), s.manager.FallbackRestartPending())
}

func (s *Server) handleFallbackRestartAcknowledge(w http.ResponseWriter, r *http.Request) {
	if err := s.manager.AcknowledgeFallbackRestart(r.Context()); err != nil {
		s.internalError(w, r, "acknowledge fallback restart", err)
		return
	}
	sendOK(w)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.sendJSON(w, http.StatusOK, s.configView())
		return
	}
	var request configRequest
	if !s.decodeJSON(w, r, &request) {
		return
	}
	candidate := config.Config{LogLevel: request.LogLevel, Certificates: make([]config.CertificateConfig, 0, len(request.Certificates))}
	for _, certificate := range request.Certificates {
		if certificate.Credentials != nil && (certificate.Credentials.CertificateAPIKey != nil || certificate.Credentials.PrivateKeyAPIKey != nil) {
			s.sendError(w, "credentials must be updated through certificate endpoints", http.StatusBadRequest)
			return
		}
		candidate.Certificates = append(candidate.Certificates, certificate.CertificateConfig)
	}
	if err := s.manager.ApplyConfig(r.Context(), &candidate); err != nil {
		s.managerError(w, r, "apply config", err)
		return
	}
	sendOK(w)
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.sendJSON(w, http.StatusOK, s.configView().Certificates)
		return
	}
	var request certificateRequest
	if !s.decodeJSON(w, r, &request) {
		return
	}
	certificate := request.CertificateConfig
	mutation, err := credentialMutationFor(certificate, request.Credentials, true)
	if err != nil {
		s.sendError(w, "invalid request", http.StatusBadRequest)
		return
	}
	err = s.manager.MutateConfigAndCredentials(r.Context(), func(candidate *config.Config) error {
		for _, existing := range candidate.Certificates {
			if existing.Name == certificate.Name {
				return errCertificateExists
			}
		}
		candidate.Certificates = append(candidate.Certificates, certificate)
		return nil
	}, mutation)
	if errors.Is(err, errCertificateExists) {
		s.sendError(w, "configuration conflict", http.StatusConflict)
		return
	}
	if err != nil {
		s.managerError(w, r, "create certificate", err)
		return
	}
	sendOK(w)
}

func (s *Server) handleCertificatePath(w http.ResponseWriter, r *http.Request, collectionPath string) {
	suffix := strings.TrimPrefix(r.URL.Path, collectionPath+"/")
	parts := strings.Split(suffix, "/")
	if len(parts) == 1 && parts[0] != "" {
		s.allow([]string{http.MethodPut, http.MethodDelete}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				s.updateCertificate(w, r, parts[0])
			} else {
				s.deleteCertificate(w, r, parts[0])
			}
		})(w, r)
		return
	}
	if len(parts) == 2 && parts[0] != "" && (parts[1] == "sync" || parts[1] == "validate") {
		s.allow([]string{http.MethodPost}, func(w http.ResponseWriter, r *http.Request) {
			var err error
			if parts[1] == "sync" {
				err = s.manager.SyncCertificate(parts[0])
			} else {
				err = s.manager.ValidateCertificate(parts[0])
			}
			if err != nil {
				s.managerError(w, r, parts[1]+" certificate", err)
				return
			}
			sendOK(w)
		})(w, r)
		return
	}
	s.handleNotFound(w, r)
}

func (s *Server) updateCertificate(w http.ResponseWriter, r *http.Request, name string) {
	var request certificateRequest
	if !s.decodeJSON(w, r, &request) {
		return
	}
	updated := request.CertificateConfig
	if updated.Name != name {
		s.sendError(w, "invalid request", http.StatusBadRequest)
		return
	}
	mutation, err := credentialMutationFor(updated, request.Credentials, false)
	if err != nil {
		s.sendError(w, "invalid request", http.StatusBadRequest)
		return
	}
	err = s.manager.MutateConfigAndCredentials(r.Context(), func(candidate *config.Config) error {
		for i := range candidate.Certificates {
			if candidate.Certificates[i].Name == name {
				candidate.Certificates[i] = updated
				return nil
			}
		}
		return errCertificateNotFound
	}, mutation)
	if errors.Is(err, errCertificateNotFound) {
		s.sendError(w, "certificate not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.managerError(w, r, "update certificate", err)
		return
	}
	sendOK(w)
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request, name string) {
	err := s.manager.MutateConfigAndCredentials(r.Context(), func(candidate *config.Config) error {
		for i := range candidate.Certificates {
			if candidate.Certificates[i].Name == name {
				candidate.Certificates = append(candidate.Certificates[:i], candidate.Certificates[i+1:]...)
				return nil
			}
		}
		return errCertificateNotFound
	}, &CredentialMutation{Name: name, Delete: true})
	if errors.Is(err, errCertificateNotFound) {
		s.sendError(w, "certificate not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.managerError(w, r, "delete certificate", err)
		return
	}
	sendOK(w)
}

func credentialMutationFor(certificate config.CertificateConfig, input *credentialInput, creating bool) (*CredentialMutation, error) {
	if certificate.Source.Type == "" {
		certificate.Source.Type = config.SourceTypeLocal
	}
	if certificate.Source.Type != config.SourceTypeCertWarden {
		return &CredentialMutation{Name: certificate.Name, Delete: true}, nil
	}
	mutation := &CredentialMutation{Name: certificate.Name}
	if input != nil {
		mutation.CertificateAPIKey = input.CertificateAPIKey
		mutation.PrivateKeyAPIKey = input.PrivateKeyAPIKey
	}
	if creating && (mutation.CertificateAPIKey == nil || mutation.PrivateKeyAPIKey == nil || strings.TrimSpace(*mutation.CertificateAPIKey) == "" || strings.TrimSpace(*mutation.PrivateKeyAPIKey) == "") {
		return nil, errors.New("remote credentials are required")
	}
	if (mutation.CertificateAPIKey == nil) != (mutation.PrivateKeyAPIKey == nil) {
		return nil, errors.New("both Cert Warden credentials must be supplied together")
	}
	return mutation, nil
}

func (s *Server) configView() configView {
	cfg := s.manager.SnapshotConfig()
	view := configView{LogLevel: cfg.LogLevel, Certificates: make([]certificateView, 0, len(cfg.Certificates))}
	for _, certificate := range cfg.Certificates {
		item := certificateView{CertificateConfig: certificate}
		if certificate.Source.Type == config.SourceTypeCertWarden {
			certKey, privateKey := s.manager.CredentialsConfigured(certificate.Name)
			item.Credentials = &credentialState{CertificateAPIKey: certKey, PrivateKeyAPIKey: privateKey}
		}
		view.Certificates = append(view.Certificates, item)
	}
	return view
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, destination interface{}) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		s.sendError(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.sendError(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			s.sendError(w, "invalid request body", http.StatusBadRequest)
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.sendError(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			s.sendError(w, "invalid request body", http.StatusBadRequest)
		}
		return false
	}
	return true
}

type invalidConfigError interface{ InvalidConfig() bool }
type configConflictError interface{ ConfigConflict() bool }
type notFoundError interface{ NotFound() bool }
type sourceValidationError interface{ SourceValidation() bool }

func (s *Server) managerError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	s.logger.Error("API operation failed", "operation", operation, "method", r.Method, "path", r.URL.Path, "error", err)
	var invalid invalidConfigError
	var conflict configConflictError
	var missing notFoundError
	var sourceInvalid sourceValidationError
	switch {
	case errors.As(err, &missing) && missing.NotFound():
		s.sendError(w, "certificate not found", http.StatusNotFound)
	case errors.As(err, &conflict) && conflict.ConfigConflict():
		s.sendError(w, "configuration conflict", http.StatusConflict)
	case errors.As(err, &sourceInvalid) && sourceInvalid.SourceValidation():
		s.sendError(w, "certificate validation failed", http.StatusUnprocessableEntity)
	case errors.As(err, &invalid) && invalid.InvalidConfig():
		s.sendError(w, "invalid request", http.StatusBadRequest)
	default:
		s.sendError(w, "internal server error", http.StatusInternalServerError)
	}
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	s.logger.Error("API operation failed", "operation", operation, "method", r.Method, "path", r.URL.Path, "error", err)
	s.sendError(w, "internal server error", http.StatusInternalServerError)
}

func (s *Server) sendError(w http.ResponseWriter, message string, code int) {
	s.sendJSON(w, code, map[string]string{"error": message})
}

func (s *Server) sendJSON(w http.ResponseWriter, code int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func sendOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// MaskedConfig returns the supplied snapshot. Paths are operational metadata,
// not private key contents.
func MaskedConfig(cfg *config.Config) *config.Config { return cfg }
