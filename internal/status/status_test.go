package status

import (
	"errors"
	"testing"

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
