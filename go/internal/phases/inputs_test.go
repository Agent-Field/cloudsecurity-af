package phases

import (
	"encoding/json"
	"os"
	"testing"
)

// TestPhaseInputDefaults pins every default argument in phases.py's five
// reasoner signatures, decoded from an EMPTY body the way a caller that omits
// the optional parameters produces.
func TestPhaseInputDefaults(t *testing.T) {
	var recon ReconPhaseInput
	mustUnmarshal(t, `{"repo_path":"/repo"}`, &recon)
	if recon.Depth != "standard" || recon.Tier != 1 || recon.CloudConfig != nil {
		t.Errorf("recon_phase defaults = %#v", recon)
	}

	var hunt HuntPhaseInput
	mustUnmarshal(t, `{"repo_path":"/repo"}`, &hunt)
	if hunt.Depth != "standard" || hunt.MaxConcurrentHunters != 3 {
		t.Errorf("hunt_phase defaults = %#v", hunt)
	}

	var chain ChainPhaseInput
	mustUnmarshal(t, `{"resource_graph_path":"/g.json"}`, &chain)
	if chain.Depth != "standard" || chain.MaxChildren != 3 || chain.DriftReport != nil {
		t.Errorf("chain_phase defaults = %#v", chain)
	}

	var prove ProvePhaseInput
	mustUnmarshal(t, `{"repo_path":"/repo"}`, &prove)
	if prove.Depth != "standard" || prove.Tier != 1 || prove.MaxConcurrentProvers != 3 {
		t.Errorf("prove_phase defaults = %#v", prove)
	}

	var remediation RemediationPhaseInput
	mustUnmarshal(t, `{"repo_path":"/repo"}`, &remediation)
	if remediation.MaxConcurrentRemediations != 3 {
		t.Errorf("remediation_phase defaults = %#v", remediation)
	}
}

// TestPhaseInputExplicitValuesWin makes sure the default seeding does not
// clobber a supplied value (including a deliberate zero).
func TestPhaseInputExplicitValuesWin(t *testing.T) {
	var hunt HuntPhaseInput
	mustUnmarshal(t, `{"repo_path":"/r","depth":"quick","max_concurrent_hunters":0}`, &hunt)
	if hunt.Depth != "quick" || hunt.MaxConcurrentHunters != 0 {
		t.Fatalf("hunt = %#v", hunt)
	}
}

// TestNodeID covers `os.getenv("NODE_ID", "cloudsecurity")`.
func TestNodeID(t *testing.T) {
	t.Setenv("NODE_ID", "cloudsecurity-go")
	if got := NodeID(); got != "cloudsecurity-go" {
		t.Fatalf("NodeID() = %q", got)
	}
	if err := os.Unsetenv("NODE_ID"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if got := NodeID(); got != DefaultNodeID {
		t.Fatalf("NodeID() = %q, want %q", got, DefaultNodeID)
	}
	// An EXPORTED-EMPTY NODE_ID resolves to the default, not to "".
	//
	// This is the port's one deliberate divergence from os.getenv, and it is
	// only safe because internal/node resolves the REGISTERED id with the same
	// helper. Python cannot desynchronise (app.py, phases.py and
	// orchestrator.py all spell `os.getenv("NODE_ID", "cloudsecurity")`), so
	// its registered id and its call-target prefix always agree; when Go read
	// this one with os.LookupEnv the node registered as "cloudsecurity" and
	// then called ".run_iac_reader", a target the SDK does not repair because
	// it already contains a dot.
	t.Setenv("NODE_ID", "")
	if got := NodeID(); got != DefaultNodeID {
		t.Fatalf("NodeID() = %q, want %q", got, DefaultNodeID)
	}
}

func mustUnmarshal(t *testing.T, body string, dest any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), dest); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
}
