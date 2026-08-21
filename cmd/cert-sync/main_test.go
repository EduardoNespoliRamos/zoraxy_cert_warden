package main

import "testing"

func TestPluginSpecDoesNotRequestZoraxyAPIAccess(t *testing.T) {
	spec := pluginSpec()
	if len(spec.PermittedAPIEndpoints) != 0 {
		t.Fatalf("expected no permitted Zoraxy API endpoints, got %d", len(spec.PermittedAPIEndpoints))
	}
}
