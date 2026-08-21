package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
)

var (
	errCertificateExists   = errors.New("certificate already exists")
	errCertificateNotFound = errors.New("certificate not found")
)

// ConfigMutation changes a manager-owned candidate while config application is
// serialized. The candidate is discarded if the mutation or apply fails.
type ConfigMutation func(*config.Config) error

// Manager is the sole owner of configuration and runtime state used by HTTP.
type Manager interface {
	SnapshotConfig() *config.Config
	SnapshotStatus() []status.CertificateStatus
	ApplyConfig(context.Context, *config.Config) error
	MutateConfig(context.Context, ConfigMutation) error
	SyncCertificate(string) error
	ValidateCertificate(string) error
	FallbackRestartPending() bool
	AcknowledgeFallbackRestart(context.Context) error
}

// Server provides HTTP handlers for the plugin UI and API.
type Server struct {
	manager Manager
}

// NewServer creates a server backed only by manager service operations.
func NewServer(manager Manager) *Server {
	return &Server{manager: manager}
}

// RegisterRoutes registers all plugin API routes on the provided mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux, uiPath string) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/certificates", s.handleCertificates)
	mux.HandleFunc("/api/certificates/", s.handleCertificateDetail)
	mux.HandleFunc("/api/fallback/restart/acknowledge", s.handleFallbackRestartAcknowledge)
}

// RegisterRoutesUnderPrefix registers the same routes under the UI proxy path.
func (s *Server) RegisterRoutesUnderPrefix(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/health", s.handleHealth)
	mux.HandleFunc(prefix+"/api/status", s.handleStatus)
	mux.HandleFunc(prefix+"/api/config", s.handleConfig)
	mux.HandleFunc(prefix+"/api/certificates", s.handleCertificates)
	mux.HandleFunc(prefix+"/api/certificates/", s.handleCertificateDetail)
	mux.HandleFunc(prefix+"/api/fallback/restart/acknowledge", s.handleFallbackRestartAcknowledge)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agg := s.aggregate()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": agg.Status, "certificates": agg.Certificates,
		"healthy": agg.Healthy, "errors": agg.Errors,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.aggregate())
}

func (s *Server) aggregate() status.AggregatedStatus {
	return status.Aggregate(s.manager.SnapshotStatus(), s.manager.FallbackRestartPending())
}

func (s *Server) handleFallbackRestartAcknowledge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.manager.AcknowledgeFallbackRestart(r.Context()); err != nil {
		s.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendOK(w)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.manager.SnapshotConfig())
	case http.MethodPost:
		var candidate config.Config
		if err := json.NewDecoder(r.Body).Decode(&candidate); err != nil {
			s.sendError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := s.manager.ApplyConfig(r.Context(), &candidate); err != nil {
			code := http.StatusInternalServerError
			if isInvalidConfig(err) {
				code = http.StatusBadRequest
			}
			s.sendError(w, err.Error(), code)
			return
		}
		sendOK(w)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.manager.SnapshotConfig().Certificates)
	case http.MethodPost:
		var certificate config.CertificateConfig
		if err := json.NewDecoder(r.Body).Decode(&certificate); err != nil {
			s.sendError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		err := s.manager.MutateConfig(r.Context(), func(candidate *config.Config) error {
			for _, existing := range candidate.Certificates {
				if existing.Name == certificate.Name {
					return errCertificateExists
				}
			}
			candidate.Certificates = append(candidate.Certificates, certificate)
			return nil
		})
		if err != nil {
			code := http.StatusInternalServerError
			if errors.Is(err, errCertificateExists) {
				code = http.StatusConflict
			} else if isInvalidConfig(err) {
				code = http.StatusBadRequest
			}
			s.sendError(w, err.Error(), code)
			return
		}
		sendOK(w)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificateDetail(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	prefix := "/api/certificates/"
	if !strings.HasPrefix(path, prefix) {
		prefix = "/ui/api/certificates/"
		if !strings.HasPrefix(path, prefix) {
			s.sendError(w, "invalid path: "+path, http.StatusBadRequest)
			return
		}
	}
	parts := strings.SplitN(path[len(prefix):], "/", 2)
	name, action := parts[0], ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodPut:
		s.updateCertificate(w, r, name)
	case http.MethodDelete:
		s.deleteCertificate(w, r, name)
	case http.MethodPost:
		var err error
		switch action {
		case "sync":
			err = s.manager.SyncCertificate(name)
		case "validate":
			err = s.manager.ValidateCertificate(name)
		default:
			s.sendError(w, "unknown action", http.StatusBadRequest)
			return
		}
		if err != nil {
			s.sendError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sendOK(w)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) updateCertificate(w http.ResponseWriter, r *http.Request, name string) {
	var updated config.CertificateConfig
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		s.sendError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if updated.Name != name {
		s.sendError(w, "certificate name mismatch", http.StatusBadRequest)
		return
	}
	err := s.manager.MutateConfig(r.Context(), func(candidate *config.Config) error {
		for i := range candidate.Certificates {
			if candidate.Certificates[i].Name == name {
				candidate.Certificates[i] = updated
				return nil
			}
		}
		return errCertificateNotFound
	})
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errCertificateNotFound) {
			code = http.StatusNotFound
		} else if isInvalidConfig(err) {
			code = http.StatusBadRequest
		}
		s.sendError(w, err.Error(), code)
		return
	}
	sendOK(w)
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request, name string) {
	err := s.manager.MutateConfig(r.Context(), func(candidate *config.Config) error {
		for i := range candidate.Certificates {
			if candidate.Certificates[i].Name == name {
				candidate.Certificates = append(candidate.Certificates[:i], candidate.Certificates[i+1:]...)
				return nil
			}
		}
		return errCertificateNotFound
	})
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errCertificateNotFound) {
			code = http.StatusNotFound
		}
		s.sendError(w, err.Error(), code)
		return
	}
	sendOK(w)
}

type invalidConfigError interface{ InvalidConfig() bool }

func isInvalidConfig(err error) bool {
	var invalid invalidConfigError
	return errors.As(err, &invalid) && invalid.InvalidConfig()
}

func (s *Server) sendError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func sendOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// MaskedConfig returns the supplied snapshot. Paths are operational metadata,
// not private key contents.
func MaskedConfig(cfg *config.Config) *config.Config { return cfg }
