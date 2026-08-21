package status

import (
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/certutil"
	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

// Status represents the overall health of a certificate entry.
type Status string

const (
	StatusHealthy Status = "Healthy"
	StatusError   Status = "Error"
	StatusUnknown Status = "Unknown"
)

// CertificateStatus aggregates runtime status for one certificate entry.
type CertificateStatus struct {
	Name                   string     `json:"name"`
	Status                 Status     `json:"status"`
	Message                string     `json:"message"`
	Enabled                bool       `json:"enabled"`
	CommonName             string     `json:"common_name"`
	Issuer                 string     `json:"issuer"`
	Serial                 string     `json:"serial"`
	ValidFrom              time.Time  `json:"valid_from"`
	Expires                time.Time  `json:"expires"`
	DaysRemaining          int        `json:"days_remaining"`
	LastSourceModification time.Time  `json:"last_source_modification"`
	LastSuccessfulSync     *time.Time `json:"last_successful_sync,omitempty"`
	LastAttemptedSync      *time.Time `json:"last_attempted_sync,omitempty"`
	SourceFingerprint      string     `json:"source_fingerprint"`
	DestinationFingerprint string     `json:"destination_fingerprint"`
	KeyMatch               bool       `json:"key_match"`
	AutoSync               bool       `json:"auto_sync"`
	Fallback               bool       `json:"fallback"`
	FallbackPendingRestart bool       `json:"fallback_pending_restart"`
}

// AggregatedStatus holds the overall plugin status.
type AggregatedStatus struct {
	Status       Status              `json:"status"`
	Certificates int                 `json:"certificates"`
	Healthy      int                 `json:"healthy"`
	Errors       int                 `json:"errors"`
	Unknown      int                 `json:"unknown"`
	Items        []CertificateStatus `json:"items"`
}

// State tracks runtime status and sync results for a certificate.
type State struct {
	Config                 config.CertificateConfig
	SourceInfo             *certutil.CertInfo
	DestinationFingerprint string
	LastSourceModification time.Time
	LastSuccessfulSync     *time.Time
	LastAttemptedSync      *time.Time
	LastError              error
	FallbackPendingRestart bool
}

// ToCertificateStatus converts internal state to API-friendly status.
func (s *State) ToCertificateStatus() CertificateStatus {
	cs := CertificateStatus{
		Name:                   s.Config.Name,
		Enabled:                s.Config.Enabled,
		AutoSync:               s.Config.Sync.AutoSync,
		Fallback:               s.Config.Fallback,
		FallbackPendingRestart: s.FallbackPendingRestart,
		LastSourceModification: s.LastSourceModification,
		LastSuccessfulSync:     s.LastSuccessfulSync,
		LastAttemptedSync:      s.LastAttemptedSync,
		SourceFingerprint:      "",
		DestinationFingerprint: s.DestinationFingerprint,
		KeyMatch:               false,
	}

	if s.LastError != nil {
		cs.Status = StatusError
		cs.Message = s.LastError.Error()
	} else if s.SourceInfo != nil {
		cs.Status = StatusHealthy
		cs.Message = "Certificate is valid and synchronized"
		cs.CommonName = s.SourceInfo.CommonName()
		cs.Issuer = s.SourceInfo.Issuer()
		cs.Serial = s.SourceInfo.Serial()
		cs.ValidFrom = s.SourceInfo.NotBefore()
		cs.Expires = s.SourceInfo.NotAfter()
		cs.DaysRemaining = s.SourceInfo.DaysRemaining()
		cs.SourceFingerprint = s.SourceInfo.Fingerprint
		cs.KeyMatch = true
	} else {
		cs.Status = StatusUnknown
		cs.Message = "No source certificate loaded"
	}

	return cs
}

// Aggregate computes overall health from certificate statuses.
func Aggregate(items []CertificateStatus) AggregatedStatus {
	agg := AggregatedStatus{
		Status: StatusHealthy,
		Items:  items,
	}
	for _, item := range items {
		agg.Certificates++
		switch item.Status {
		case StatusHealthy:
			agg.Healthy++
		case StatusError:
			agg.Errors++
		case StatusUnknown:
			agg.Unknown++
		}
	}
	if agg.Errors > 0 {
		agg.Status = StatusError
	} else if agg.Unknown > 0 {
		agg.Status = StatusUnknown
	}
	return agg
}
