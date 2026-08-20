package reasoners

// Control-plane registration names of the cloudsecurity-af reasoner surface.
//
// The 20 ROUTER reasoners are the ones src/cloudsecurity_af/reasoners/*.py
// decorate with @router.reasoner(); the two TOP-LEVEL reasoners (scan, prove)
// are decorated with @app.reasoner() in src/cloudsecurity_af/app.py and are
// registered by internal/node, not by this package.
//
// These constants are the single source of truth for the DAG's node names:
// internal/phases builds every `app.Call` target as `nodeID + "." + <name>`, so
// a rename here that is not mirrored there breaks the graph. Two test families
// guard that:
//
//   - reasoners_test.go pins the full ordered registration list
//     (TestRouterNames_MatchPythonRegistrationOrder) and asserts the targets the
//     phase handlers actually emit through appx.Fake.CallTargets().
//   - internal/phases/{recon,hunt,chain,prove,remediate}_test.go assert the same
//     targets from the phase side.
//
// Both families spell the targets as string LITERALS (e.g.
// testNodeID+".run_iac_reader"), never as these constants, so they catch a
// change to a constant's VALUE — the thing that breaks the DAG — but not a
// rename of the Go identifier, which the compiler catches instead.
const (
	// --- reasoners/recon.py -------------------------------------------------
	NameRunIaCReader            = "run_iac_reader"
	NameRunResourceGraphBuilder = "run_resource_graph_builder"
	NameRunCloudConnector       = "run_cloud_connector"
	NameRunDriftDetector        = "run_drift_detector"

	// --- reasoners/hunt.py --------------------------------------------------
	NameRunIAMHunter        = "run_iam_hunter"
	NameRunNetworkHunter    = "run_network_hunter"
	NameRunDataHunter       = "run_data_hunter"
	NameRunSecretsHunter    = "run_secrets_hunter"
	NameRunComputeHunter    = "run_compute_hunter"
	NameRunLoggingHunter    = "run_logging_hunter"
	NameRunComplianceHunter = "run_compliance_hunter"

	// --- reasoners/chain.py -------------------------------------------------
	NameRunPathConstructor = "run_path_constructor"

	// --- reasoners/prove.py -------------------------------------------------
	NameRunStaticProver = "run_static_prover"
	NameRunLiveProver   = "run_live_prover"

	// --- reasoners/remediate.py ---------------------------------------------
	NameRunFixGenerator = "run_fix_generator"

	// --- reasoners/phases.py ------------------------------------------------
	NameReconPhase       = "recon_phase"
	NameHuntPhase        = "hunt_phase"
	NameChainPhase       = "chain_phase"
	NameProvePhase       = "prove_phase"
	NameRemediationPhase = "remediation_phase"

	// --- app.py (registered by internal/node) --------------------------------
	NameScan  = "scan"
	NameProve = "prove"
)

// routerTags ports `AgentRouter(tags=["cloud", "security", "infrastructure"])`
// in src/cloudsecurity_af/reasoners/__init__.py.
//
// They are SEMANTIC domain tags, not node-identity tags: node identity is
// carried by node_id=cloudsecurity, so callers reach cloudsecurity.scan.
var routerTags = []string{"cloud", "security", "infrastructure"}

// Tags returns a fresh copy of the router's tag set, for
// agent.RouterOptions{Tags: reasoners.Tags()} at the IncludeRouter site (the Go
// SDK carries router tags on the mount, where Python carries them on the
// AgentRouter constructor).
func Tags() []string {
	return append([]string(nil), routerTags...)
}

// routerNames is the registration ORDER of the 20 router reasoners, which in
// Python is decided by the import order in reasoners/__init__.py
//
//	from . import recon, hunt, chain, prove, remediate, phases
//
// combined with the top-to-bottom decorator order inside each module.
var routerNames = []string{
	NameRunIaCReader,
	NameRunResourceGraphBuilder,
	NameRunCloudConnector,
	NameRunDriftDetector,

	NameRunIAMHunter,
	NameRunNetworkHunter,
	NameRunDataHunter,
	NameRunSecretsHunter,
	NameRunComputeHunter,
	NameRunLoggingHunter,
	NameRunComplianceHunter,

	NameRunPathConstructor,

	NameRunStaticProver,
	NameRunLiveProver,

	NameRunFixGenerator,

	NameReconPhase,
	NameHuntPhase,
	NameChainPhase,
	NameProvePhase,
	NameRemediationPhase,
}

// RouterNames returns a fresh copy of the ordered router-reasoner name list.
func RouterNames() []string {
	return append([]string(nil), routerNames...)
}
