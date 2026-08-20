package orch

import (
	"strings"

	"github.com/Agent-Field/cloudsecurity-af/go/internal/output"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/pyfmt"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/schemas"
	"github.com/Agent-Field/cloudsecurity-af/go/internal/scoring"
)

// ProofToEvidence ports orchestrator.py's module-level _PROOF_TO_EVIDENCE.
//
//	ProofMethod (LLM output) → EvidenceMethod (scoring input) mapping.
//	The two enums use different value strings, so direct casting fails.
//
// Note it is NOT total: ProofMethod has four members and all four are mapped,
// but the lookup still carries a HEURISTIC_MATCH fallback for a proof method
// that was never a member (impossible through the strict enum decoder, kept for
// parity).
var ProofToEvidence = map[schemas.ProofMethod]scoring.EvidenceMethod{
	schemas.ProofMethodStaticAnalysis:      scoring.EvidenceMethodStaticConfigMatch,
	schemas.ProofMethodLiveAPIVerification: scoring.EvidenceMethodLiveVerified,
	schemas.ProofMethodIAMSimulation:       scoring.EvidenceMethodIAMSimulated,
	schemas.ProofMethodDriftComparison:     scoring.EvidenceMethodDriftConfirmed,
}

// outputSeverityOrder ports the `severity_order` dict local to
// _generate_output. It is NOT scoring.severityOrder (which shares the same
// values but is keyed for the benchmark floor); the two happen to agree.
var outputSeverityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// GenerateOutput ports ScanOrchestrator._generate_output.
//
// Steps, in Python's order:
//
//  1. Drop findings below input.severity_threshold, but ONLY when the
//     threshold itself ranks above 0. The pydantic default "low" ranks 1, so
//     the default run DOES filter — it drops "info" findings. A threshold of
//     "info", or an unrecognized string, ranks 0 and filters nothing.
//  2. For every surviving finding: raise its severity to the benchmark floor of
//     its FIRST compliance mapping, recompute risk_score from
//     (severity, proof method, Exposure.VPC_INTERNAL, has attack path, has
//     drift), and mirror the score into sarif_security_severity.
//  3. Count verdicts and severities, compute the noise-reduction percentage
//     against hunt.total_raw, and count drift/shadow-IT resources.
//  4. Build the CloudSecurityScanResult, then fill in its `sarif` field from
//     generate_sarif(result) — which means the SARIF document is rendered from
//     the ALREADY-scored findings.
//
// Python parity: step 2 MUTATES the VerifiedFinding objects, and Python's list
// — filtered or not — holds the SAME objects as the caller's, so run()'s local
// `verified` sees the new severities and risk scores too. Go structs are values,
// so this function copies the slice up front and mutates only its own copy,
// making it side-effect free. run() never reads its `verified` again after
// calling this, so the difference is unobservable on the live path.
//
// Python parity: `compliance_gaps` is never populated — it keeps its
// default_factory=list value, i.e. an empty list.
func (o *ScanOrchestrator) GenerateOutput(
	recon schemas.ReconResult,
	hunt schemas.HuntResult,
	chain schemas.ChainResult,
	verified []schemas.VerifiedFinding,
) schemas.CloudSecurityScanResult {
	// --- 1. severity threshold --------------------------------------------
	thresholdValue := outputSeverityOrder[strings.ToLower(o.Input.SeverityThreshold)]
	if thresholdValue > 0 {
		kept := make([]schemas.VerifiedFinding, 0, len(verified))
		for _, finding := range verified {
			if outputSeverityOrder[strings.ToLower(finding.Severity.String())] >= thresholdValue {
				kept = append(kept, finding)
			}
		}
		verified = kept
	} else {
		// Keep the caller's slice from aliasing the result's Findings when no
		// filter ran, so the in-place scoring below cannot surprise a caller
		// that reuses its own list (Python's aliasing is harmless there for
		// the same reason: nothing reads it again).
		kept := make([]schemas.VerifiedFinding, len(verified))
		copy(kept, verified)
		verified = kept
	}

	// --- 2. benchmark floor + risk score ----------------------------------
	for i := range verified {
		finding := &verified[i]

		var benchmark *string
		if len(finding.ComplianceMappings) > 0 {
			benchmark = &finding.ComplianceMappings[0]
		}
		finding.Severity = scoring.ApplyBenchmarkSeverityFloor(benchmark, finding.Severity)

		evidence, mapped := ProofToEvidence[finding.Proof.Method]
		if !mapped {
			evidence = scoring.EvidenceMethodHeuristicMatch
		}
		finding.RiskScore = scoring.ComputeRiskScore(
			finding.Severity,
			evidence,
			// Python parity: exposure is HARD-CODED to VPC_INTERNAL here; the
			// scan never infers a real exposure level.
			scoring.ExposureVPCInternal,
			finding.AttackPath != nil,
			finding.Drift != nil,
		)
		finding.SARIFSecuritySeverity = finding.RiskScore
	}

	// --- 3. counts --------------------------------------------------------
	verdictCounts := make(map[schemas.Verdict]int, len(schemas.AllVerdicts))
	for _, verdict := range schemas.AllVerdicts {
		verdictCounts[verdict] = 0
	}
	severityCounts := make(map[string]int, len(scoring.AllSeverities))
	for _, severity := range scoring.AllSeverities {
		severityCounts[severity.String()] = 0
	}
	for _, finding := range verified {
		// Python parity: verdict_counts is subscript-assigned, so an
		// off-enum verdict would KeyError. schemas.Verdict's decoder rejects
		// those before they can get here.
		verdictCounts[finding.Verdict]++
		// Python parity: severity_counts uses .get(), so an off-enum severity
		// silently creates a new bucket — which a Go map increment also does.
		severityCounts[finding.Severity.String()]++
	}

	totalRaw := hunt.TotalRaw
	notExploitable := verdictCounts[schemas.VerdictNotExploitable]
	noiseReduction := 0.0
	if totalRaw > 0 {
		noiseReduction = float64(notExploitable) / float64(totalRaw) * 100.0
	}

	driftResources := 0
	shadowIT := 0
	if recon.DriftReport != nil {
		driftResources = len(recon.DriftReport.DriftedResources)
		shadowIT = len(recon.DriftReport.CloudOnlyResources)
	}

	// --- 4. result --------------------------------------------------------
	commitSHA := "HEAD"
	if o.Input.CommitSHA != nil && *o.Input.CommitSHA != "" {
		commitSHA = *o.Input.CommitSHA
	}
	branch := o.Input.Branch

	costBreakdown := make(map[string]float64, len(o.CostBreakdown))
	for phase, cost := range o.CostBreakdown {
		costBreakdown[phase] = pyfmt.Round(cost, 4)
	}

	result := schemas.NewCloudSecurityScanResult()
	result.Repository = o.Input.RepoURL
	result.CommitSHA = commitSHA
	result.Branch = &branch
	result.Timestamp = o.nowUTC()
	// Python parity: depth_profile is the RAW input string, not the normalized
	// ScanConfig.depth.
	result.DepthProfile = o.Input.Depth
	result.Tier = o.Config.Tier
	result.ProvidersDetected = recon.ProvidersDetected
	result.Findings = verified
	result.AttackPaths = chain.AttackPaths
	result.TotalResourcesScanned = recon.TotalResources
	result.TotalRawFindings = totalRaw
	result.Confirmed = verdictCounts[schemas.VerdictConfirmed]
	result.Likely = verdictCounts[schemas.VerdictLikely]
	result.Inconclusive = verdictCounts[schemas.VerdictInconclusive]
	result.NotExploitable = notExploitable
	result.NoiseReductionPct = pyfmt.Round(noiseReduction, 2)
	result.BySeverity = severityCounts
	result.DriftResources = driftResources
	result.ShadowITResources = shadowIT
	// Python parity: compliance_frameworks has default_factory=list, so it is
	// never None. A Go caller that built CloudSecurityInput as a literal could
	// leave it nil, which would render as JSON null instead of []; normalize.
	complianceFrameworks := o.Input.ComplianceFrameworks
	if complianceFrameworks == nil {
		complianceFrameworks = []string{}
	}
	result.ComplianceFrameworksChecked = complianceFrameworks
	result.StrategiesUsed = hunt.StrategiesRun
	result.DurationSeconds = o.elapsedSeconds()
	result.AgentInvocations = o.AgentInvocations
	result.CostUSD = pyfmt.Round(o.TotalCostUSD, 4)
	result.CostBreakdown = costBreakdown
	result.Metadata = map[string]any{"findings_not_verified": o.FindingsNotVerified}
	result.SARIF = ""

	result.SARIF = output.GenerateSarif(result)
	return result
}
