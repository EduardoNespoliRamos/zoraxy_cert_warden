package status

import (
	"errors"
	"testing"
	"time"

	"github.com/eduardoramos/zoraxy-cert-warden/internal/config"
)

func TestValidationSuccessDoesNotClearSyncError(t *testing.T) {
	state := State{
		Config:    config.CertificateConfig{Name: "cert", Enabled: true},
		SyncError: errors.New("write failed"),
	}
	got := state.ToCertificateStatus()
	if got.Status != StatusError || got.SyncError != "write failed" {
		t.Fatalf("sync error was not preserved: %+v", got)
	}
}

func TestDisabledDoesNotDegradeAggregate(t *testing.T) {
	agg := Aggregate([]CertificateStatus{{Status: StatusHealthy}, {Status: StatusDisabled}})
	if agg.Status != StatusHealthy || agg.Disabled != 1 || agg.Errors != 0 || agg.Unknown != 0 {
		t.Fatalf("unexpected aggregate: %+v", agg)
	}
}

func TestAggregateExposesPersistentFallbackRestart(t *testing.T) {
	agg := Aggregate(nil, true)
	if !agg.FallbackPendingRestart {
		t.Fatal("aggregate did not expose pending fallback restart")
	}
}

func TestLocalStatusOmitsCertWardenQuery(t *testing.T) {
	state := State{Config: config.CertificateConfig{
		Name:    "local",
		Enabled: true,
		Source:  config.CertificateSource{Type: config.SourceTypeLocal},
	}}
	if got := state.ToCertificateStatus(); got.CertWardenQuery != nil {
		t.Fatalf("local status included remote query state: %+v", got.CertWardenQuery)
	}
}

func TestCertWardenQueryTimestampsAreCloned(t *testing.T) {
	lastAttempt := time.Unix(100, 0)
	lastSuccess := time.Unix(200, 0)
	nextAttempt := time.Unix(300, 0)
	state := State{
		Config: config.CertificateConfig{
			Name:    "remote",
			Enabled: true,
			Source:  config.CertificateSource{Type: config.SourceTypeCertWarden},
		},
		CertWardenQuery: &CertWardenQueryStatus{
			Status:      StatusHealthy,
			LastAttempt: &lastAttempt,
			LastSuccess: &lastSuccess,
			NextAttempt: &nextAttempt,
		},
	}

	got := state.ToCertificateStatus().CertWardenQuery
	if got == nil {
		t.Fatal("remote query status was omitted")
	}
	if got == state.CertWardenQuery || got.LastAttempt == &lastAttempt || got.LastSuccess == &lastSuccess || got.NextAttempt == &nextAttempt {
		t.Fatal("remote query status retained mutable pointers")
	}
	if !got.LastAttempt.Equal(lastAttempt) || !got.LastSuccess.Equal(lastSuccess) || !got.NextAttempt.Equal(nextAttempt) {
		t.Fatalf("cloned timestamps changed values: %+v", got)
	}
}

func TestCertWardenQueryErrorTakesPrecedence(t *testing.T) {
	state := State{
		Config: config.CertificateConfig{
			Name:    "remote",
			Enabled: true,
			Source:  config.CertificateSource{Type: config.SourceTypeCertWarden},
		},
		WatcherError: errors.New("watch failed"),
		SyncError:    errors.New("sync failed"),
		CertWardenQuery: &CertWardenQueryStatus{
			Status:  StatusError,
			Message: "remote query failed",
		},
	}

	got := state.ToCertificateStatus()
	if got.Status != StatusError || got.Message != "remote query failed" {
		t.Fatalf("remote query error did not take precedence: %+v", got)
	}
}

func TestAggregateCertWardenQueryCounts(t *testing.T) {
	items := []CertificateStatus{
		{Name: "connected", Status: StatusHealthy, CertWardenQuery: &CertWardenQueryStatus{Status: StatusHealthy}},
		{Name: "checking", Status: StatusUnknown, CertWardenQuery: &CertWardenQueryStatus{Status: StatusError, InProgress: true}},
		{Name: "failed", Status: StatusError, CertWardenQuery: &CertWardenQueryStatus{Status: StatusError}},
		{Name: "local", Status: StatusHealthy},
	}

	agg := Aggregate(items)
	if agg.RemoteSources != 3 || agg.RemoteConnected != 1 || agg.RemoteChecking != 1 || agg.RemoteErrors != 1 {
		t.Fatalf("unexpected remote aggregate counts: %+v", agg)
	}
	if agg.Status != StatusError || agg.Errors != 1 || agg.Unknown != 1 || agg.Healthy != 2 {
		t.Fatalf("unexpected certificate aggregate counts: %+v", agg)
	}
}

func TestSuccessfulCertWardenQueryPreservesValidationErrors(t *testing.T) {
	state := State{
		Config: config.CertificateConfig{
			Name:    "remote",
			Enabled: true,
			Source:  config.CertificateSource{Type: config.SourceTypeCertWarden},
		},
		SourceValidationError:      errors.New("source invalid"),
		DestinationValidationError: errors.New("destination invalid"),
		CertWardenQuery:            &CertWardenQueryStatus{Status: StatusHealthy, Message: "API connected"},
	}

	got := state.ToCertificateStatus()
	if got.CertWardenQuery == nil || got.CertWardenQuery.Status != StatusHealthy {
		t.Fatalf("successful API query was not represented independently: %+v", got)
	}
	if got.Status != StatusError || got.Message != "source invalid" || got.SourceValidationError != "source invalid" || got.DestinationValidationError != "destination invalid" {
		t.Fatalf("validation errors were not independently represented: %+v", got)
	}
}
