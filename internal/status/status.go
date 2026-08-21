package status

import (
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

// Status represents the overall health of a certificate entry.
type Status string

const (
	StatusHealthy  Status = "Healthy"
	StatusError    Status = "Error"
	StatusUnknown  Status = "Unknown"
	StatusDisabled Status = "Disabled"
)

// CertificateStatus is the immutable API representation of one certificate.
type CertificateStatus struct {
	Name                       string     `json:"name"`
	Status                     Status     `json:"status"`
	Message                    string     `json:"message"`
	Enabled                    bool       `json:"enabled"`
	CommonName                 string     `json:"common_name"`
	Issuer                     string     `json:"issuer"`
	Serial                     string     `json:"serial"`
	ValidFrom                  time.Time  `json:"valid_from"`
	Expires                    time.Time  `json:"expires"`
	DaysRemaining              int        `json:"days_remaining"`
	LastSourceModification     time.Time  `json:"last_source_modification"`
	LastSourceValidation       *time.Time `json:"last_source_validation,omitempty"`
	LastDestinationValidation  *time.Time `json:"last_destination_validation,omitempty"`
	LastSuccessfulSync         *time.Time `json:"last_successful_sync,omitempty"`
	LastAttemptedSync          *time.Time `json:"last_attempted_sync,omitempty"`
	LastWatcherError           *time.Time `json:"last_watcher_error,omitempty"`
	SourceFingerprint          string     `json:"source_fingerprint"`
	DestinationFingerprint     string     `json:"destination_fingerprint"`
	SourceBundleDigest         string     `json:"source_bundle_digest"`
	DestinationBundleDigest    string     `json:"destination_bundle_digest"`
	SourceValidationError      string     `json:"source_validation_error,omitempty"`
	DestinationValidationError string     `json:"destination_validation_error,omitempty"`
	SyncError                  string     `json:"sync_error,omitempty"`
	WatcherError               string     `json:"watcher_error,omitempty"`
	KeyMatch                   bool       `json:"key_match"`
	AutoSync                   bool       `json:"auto_sync"`
	Fallback                   bool       `json:"fallback"`
	FallbackPendingRestart     bool       `json:"fallback_pending_restart"`
}

// AggregatedStatus holds the overall plugin status.
type AggregatedStatus struct {
	Status       Status              `json:"status"`
	Certificates int                 `json:"certificates"`
	Healthy      int                 `json:"healthy"`
	Errors       int                 `json:"errors"`
	Unknown      int                 `json:"unknown"`
	Disabled     int                 `json:"disabled"`
	Items        []CertificateStatus `json:"items"`
}

// State tracks independent validation, synchronization, and watcher results.
// Access is serialized by the owning manager.
type State struct {
	Config                     config.CertificateConfig
	SourceInfo                 *certutil.CertInfo
	SourceFingerprint          string
	SourceDigest               string
	DestinationDigest          string
	DestinationFingerprint     string
	LastSourceModification     time.Time
	LastSourceValidation       *time.Time
	LastDestinationValidation  *time.Time
	LastSuccessfulSync         *time.Time
	LastAttemptedSync          *time.Time
	LastWatcherError           *time.Time
	SourceValidationError      error
	DestinationValidationError error
	SyncError                  error
	WatcherError               error
	FallbackPendingRestart     bool
}

// ToCertificateStatus converts internal state to an immutable API value.
func (s *State) ToCertificateStatus() CertificateStatus {
	cs := CertificateStatus{
		Name:                       s.Config.Name,
		Enabled:                    s.Config.Enabled,
		AutoSync:                   s.Config.Sync.AutoSync,
		Fallback:                   s.Config.Fallback,
		FallbackPendingRestart:     s.FallbackPendingRestart,
		LastSourceModification:     s.LastSourceModification,
		LastSourceValidation:       cloneTime(s.LastSourceValidation),
		LastDestinationValidation:  cloneTime(s.LastDestinationValidation),
		LastSuccessfulSync:         cloneTime(s.LastSuccessfulSync),
		LastAttemptedSync:          cloneTime(s.LastAttemptedSync),
		LastWatcherError:           cloneTime(s.LastWatcherError),
		SourceFingerprint:          s.SourceFingerprint,
		DestinationFingerprint:     s.DestinationFingerprint,
		SourceBundleDigest:         s.SourceDigest,
		DestinationBundleDigest:    s.DestinationDigest,
		SourceValidationError:      errorString(s.SourceValidationError),
		DestinationValidationError: errorString(s.DestinationValidationError),
		SyncError:                  errorString(s.SyncError),
		WatcherError:               errorString(s.WatcherError),
	}

	if s.SourceInfo != nil {
		cs.CommonName = s.SourceInfo.CommonName()
		cs.Issuer = s.SourceInfo.Issuer()
		cs.Serial = s.SourceInfo.Serial()
		cs.ValidFrom = s.SourceInfo.NotBefore()
		cs.Expires = s.SourceInfo.NotAfter()
		cs.DaysRemaining = s.SourceInfo.DaysRemaining()
		cs.KeyMatch = s.LastDestinationValidation != nil && s.DestinationValidationError == nil &&
			s.SourceDigest != "" && s.SourceDigest == s.DestinationDigest
		if cs.SourceFingerprint == "" {
			cs.SourceFingerprint = s.SourceInfo.Fingerprint
		}
		if cs.SourceBundleDigest == "" {
			cs.SourceBundleDigest = s.SourceInfo.BundleDigest
		}
	}

	switch {
	case !s.Config.Enabled:
		cs.Status = StatusDisabled
		cs.Message = "Certificate is disabled"
	case s.WatcherError != nil:
		cs.Status = StatusError
		cs.Message = s.WatcherError.Error()
	case s.SyncError != nil:
		cs.Status = StatusError
		cs.Message = s.SyncError.Error()
	case s.SourceValidationError != nil:
		cs.Status = StatusError
		cs.Message = s.SourceValidationError.Error()
	case s.DestinationValidationError != nil:
		cs.Status = StatusError
		cs.Message = s.DestinationValidationError.Error()
	case s.SourceInfo != nil && s.LastDestinationValidation != nil && s.SourceDigest == s.DestinationDigest:
		cs.Status = StatusHealthy
		cs.Message = "Certificate is valid and synchronized"
	default:
		cs.Status = StatusUnknown
		cs.Message = "No source certificate loaded"
	}
	return cs
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Aggregate computes overall health. Disabled entries remain visible but do
// not degrade the aggregate status.
func Aggregate(items []CertificateStatus) AggregatedStatus {
	agg := AggregatedStatus{Status: StatusHealthy, Items: items}
	for _, item := range items {
		agg.Certificates++
		switch item.Status {
		case StatusHealthy:
			agg.Healthy++
		case StatusError:
			agg.Errors++
		case StatusUnknown:
			agg.Unknown++
		case StatusDisabled:
			agg.Disabled++
		}
	}
	if agg.Errors > 0 {
		agg.Status = StatusError
	} else if agg.Unknown > 0 {
		agg.Status = StatusUnknown
	}
	return agg
}
