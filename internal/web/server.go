package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/status"
)

// Syncer is the interface implemented by the main sync runner.
type Syncer interface {
	SyncCertificate(name string) error
	ValidateCertificate(name string) error
	ReloadConfig(cfg *config.Config) error
}

// Server provides HTTP handlers for the plugin UI and API.
type Server struct {
	mu        sync.RWMutex
	cfg       *config.Config
	states    map[string]*status.State
	syncer    Syncer
	configPath string
}

// NewServer creates a new web server.
func NewServer(cfg *config.Config, states map[string]*status.State, syncer Syncer, configPath string) *Server {
	return &Server{
		cfg:        cfg,
		states:     states,
		syncer:     syncer,
		configPath: configPath,
	}
}

// RegisterRoutes registers all plugin API routes on the provided mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux, uiPath string) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/certificates", s.handleCertificates)
	mux.HandleFunc("/api/certificates/", s.handleCertificateDetail)
}

// RegisterRoutesUnderPrefix registers the same routes under a prefix (e.g. the
// UI path) so Zoraxy can proxy them together with the static files.
func (s *Server) RegisterRoutesUnderPrefix(mux *http.ServeMux, prefix string) {
	mux.HandleFunc(prefix+"/health", s.handleHealth)
	mux.HandleFunc(prefix+"/api/status", s.handleStatus)
	mux.HandleFunc(prefix+"/api/config", s.handleConfig)
	mux.HandleFunc(prefix+"/api/certificates", s.handleCertificates)
	mux.HandleFunc(prefix+"/api/certificates/", s.handleCertificateDetail)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agg := s.aggregate()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       agg.Status,
		"certificates": agg.Certificates,
		"healthy":      agg.Healthy,
		"errors":       agg.Errors,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agg := s.aggregate()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agg)
}

func (s *Server) aggregate() status.AggregatedStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]status.CertificateStatus, 0, len(s.states))
	for _, st := range s.states {
		items = append(items, st.ToCertificateStatus())
	}
	return status.Aggregate(items)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		cfg := *s.cfg
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	case http.MethodPost:
		var newCfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			s.sendError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := newCfg.Validate(false); err != nil {
			s.sendError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := newCfg.Save(s.configPath); err != nil {
			s.sendError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := s.syncer.ReloadConfig(&newCfg); err != nil {
			s.sendError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.mu.Lock()
		s.cfg = &newCfg
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		defer s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.cfg.Certificates)
	case http.MethodPost:
		var newCert config.CertificateConfig
		if err := json.NewDecoder(r.Body).Decode(&newCert); err != nil {
			s.sendError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if err := newCert.Validate(false); err != nil {
			s.sendError(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		for _, c := range s.cfg.Certificates {
			if c.Name == newCert.Name {
				s.mu.Unlock()
				s.sendError(w, "certificate already exists", http.StatusConflict)
				return
			}
		}
		s.cfg.Certificates = append(s.cfg.Certificates, newCert)
		if err := s.cfg.Save(s.configPath); err != nil {
			s.mu.Unlock()
			s.sendError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.mu.Unlock()
		if err := s.syncer.ReloadConfig(s.cfg); err != nil {
			s.sendError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificateDetail(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	prefix := "/api/certificates/"
	if !strings.HasPrefix(path, prefix) {
		// Also accept paths under the UI prefix when proxied by Zoraxy
		altPrefix := "/ui/api/certificates/"
		if strings.HasPrefix(path, altPrefix) {
			prefix = altPrefix
		} else {
			s.sendError(w, "invalid path: "+path, http.StatusBadRequest)
			return
		}
	}
	rest := path[len(prefix):]
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodPut:
		s.updateCertificate(w, r, name)
	case http.MethodDelete:
		s.deleteCertificate(w, r, name)
	case http.MethodPost:
		switch action {
		case "sync":
			if err := s.syncer.SyncCertificate(name); err != nil {
				s.sendError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.sendOK(w)
		case "validate":
			if err := s.syncer.ValidateCertificate(name); err != nil {
				s.sendError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			s.sendOK(w)
		default:
			s.sendError(w, "unknown action", http.StatusBadRequest)
		}
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
	if err := updated.Validate(false); err != nil {
		s.sendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	found := false
	for i := range s.cfg.Certificates {
		if s.cfg.Certificates[i].Name == name {
			s.cfg.Certificates[i] = updated
			found = true
			break
		}
	}
	if !found {
		s.mu.Unlock()
		s.sendError(w, "certificate not found", http.StatusNotFound)
		return
	}
	if err := s.cfg.Save(s.configPath); err != nil {
		s.mu.Unlock()
		s.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()
	if err := s.syncer.ReloadConfig(s.cfg); err != nil {
		s.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.sendOK(w)
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request, name string) {
	s.mu.Lock()
	found := false
	newCerts := make([]config.CertificateConfig, 0, len(s.cfg.Certificates))
	for _, c := range s.cfg.Certificates {
		if c.Name == name {
			found = true
			continue
		}
		newCerts = append(newCerts, c)
	}
	if !found {
		s.mu.Unlock()
		s.sendError(w, "certificate not found", http.StatusNotFound)
		return
	}
	s.cfg.Certificates = newCerts
	if err := s.cfg.Save(s.configPath); err != nil {
		s.mu.Unlock()
		s.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()
	if err := s.syncer.ReloadConfig(s.cfg); err != nil {
		s.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.sendOK(w)
}

func (s *Server) sendError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (s *Server) sendOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// MaskedConfig returns a copy of the config with private key paths only.
func MaskedConfig(cfg *config.Config) *config.Config {
	return cfg
}
