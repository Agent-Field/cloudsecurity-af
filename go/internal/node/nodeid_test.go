package node

import (
	"os"
	"testing"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/config"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/orch"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/phases"
)

// TestNodeID_RegistrationAndCallTargetsAgree is the cross-package invariant the
// Python node gets for free.
//
// src/cloudsecurity_af/app.py:31, reasoners/phases.py:22 and
// orchestrator.py:73 each read the IDENTICAL
// `os.getenv("NODE_ID", "cloudsecurity")`, so the id the node registers under
// and the prefix of every `app.call(f"{NODE_ID}.<reasoner>")` DAG edge are the
// same string for every possible environment. The contract this test pins is
// therefore stated in Python terms, not Go terms:
//
//	for any NODE_ID environment, registered id == phase call prefix ==
//	orchestrator call prefix, and none of them is empty.
//
// The Go port satisfies it by routing all three through config.NodeID. When it
// did not — buildConfig used an empty-means-absent reader while phases/orch
// used os.LookupEnv — an exported-empty NODE_ID registered the node as
// "cloudsecurity" and then made it call ".recon_phase" / ".run_iac_reader".
// The SDK does not repair those: agent.Call only prefixes a target that
// contains no dot, and a leading-dot target already contains one, so every scan
// died at its first phase call after a clean registration.
func TestNodeID_RegistrationAndCallTargetsAgree(t *testing.T) {
	cases := []struct {
		name    string
		nodeID  string
		unset   bool
		wantID  string
		comment string
	}{
		{name: "unset", unset: true, wantID: config.DefaultNodeID},
		{name: "explicit", nodeID: "cloudsecurity-go", wantID: "cloudsecurity-go"},
		{name: "exported empty", nodeID: "", wantID: config.DefaultNodeID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearNodeEnv(t)
			if tc.unset {
				_ = os.Unsetenv("NODE_ID")
			} else {
				t.Setenv("NODE_ID", tc.nodeID)
			}

			cfg, err := buildConfig(config.DefaultNodeID, "8015", "d")
			if err != nil {
				t.Fatalf("buildConfig: %v", err)
			}
			registered := cfg.NodeID
			phasePrefix := phases.NodeID()
			orchPrefix := orch.NodeID()

			if registered != tc.wantID {
				t.Errorf("registered NodeID = %q, want %q", registered, tc.wantID)
			}
			if phasePrefix != registered {
				t.Errorf("phases.NodeID() = %q, registered = %q: DAG targets would be %q.run_iac_reader against a node registered as %q",
					phasePrefix, registered, phasePrefix, registered)
			}
			if orchPrefix != registered {
				t.Errorf("orch.NodeID() = %q, registered = %q: DAG targets would be %q.recon_phase against a node registered as %q",
					orchPrefix, registered, orchPrefix, registered)
			}
			if registered == "" {
				t.Errorf("registered NodeID is empty; every Call target would start with a bare dot")
			}
		})
	}
}

// TestNodeID_DefaultsAreOneConstant pins the second half of the same finding:
// the literal "cloudsecurity" must not exist independently in three packages,
// or the registered id and the call-target prefix can drift while every
// individual package's tests stay green.
func TestNodeID_DefaultsAreOneConstant(t *testing.T) {
	if phases.DefaultNodeID != config.DefaultNodeID {
		t.Errorf("phases.DefaultNodeID = %q, config.DefaultNodeID = %q", phases.DefaultNodeID, config.DefaultNodeID)
	}
	if orch.DefaultNodeID != config.DefaultNodeID {
		t.Errorf("orch.DefaultNodeID = %q, config.DefaultNodeID = %q", orch.DefaultNodeID, config.DefaultNodeID)
	}
	// cmd/cloudsecurity-af/main.go passes this same value into BuildAgent; the
	// default-path test above proves the value it passes and the value the
	// call-target resolvers use are the one constant.
	if config.DefaultNodeID != "cloudsecurity" {
		t.Errorf("config.DefaultNodeID = %q, want cloudsecurity (os.getenv(\"NODE_ID\", \"cloudsecurity\"))", config.DefaultNodeID)
	}
}
