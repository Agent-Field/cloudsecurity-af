from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceMethod(str, Enum):
    LIVE_VERIFIED = "live_verified"
    IAM_SIMULATED = "iam_simulated"
    DRIFT_CONFIRMED = "drift_confirmed"
    STATIC_GRAPH_CONFIRMED = "static_graph_confirmed"
    STATIC_CONFIG_MATCH = "static_config_match"
    HEURISTIC_MATCH = "heuristic_match"


class Exposure(str, Enum):
    INTERNET_FACING = "internet_facing"
    VPC_INTERNAL = "vpc_internal"
    PRIVATE_SUBNET = "private_subnet"
    REQUIRES_IAM_AUTH = "requires_iam_auth"
    REQUIRES_ADMIN = "requires_admin"


SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

EVIDENCE_MULTIPLIERS: dict[EvidenceMethod, float] = {
    EvidenceMethod.LIVE_VERIFIED: 1.0,
    EvidenceMethod.IAM_SIMULATED: 0.9,
    EvidenceMethod.DRIFT_CONFIRMED: 0.85,
    EvidenceMethod.STATIC_GRAPH_CONFIRMED: 0.7,
    EvidenceMethod.STATIC_CONFIG_MATCH: 0.5,
    EvidenceMethod.HEURISTIC_MATCH: 0.2,
}

EXPOSURE_MULTIPLIERS: dict[Exposure, float] = {
    Exposure.INTERNET_FACING: 1.0,
    Exposure.VPC_INTERNAL: 0.7,
    Exposure.PRIVATE_SUBNET: 0.5,
    Exposure.REQUIRES_IAM_AUTH: 0.4,
    Exposure.REQUIRES_ADMIN: 0.2,
}

_BENCHMARK_SEVERITY_FLOORS: dict[str, str] = {
    # CIS AWS controls that should never be reported below certain severity
    "CIS-AWS-1.4": "critical",  # root account MFA
    "CIS-AWS-1.5": "critical",  # root account access keys
    "CIS-AWS-2.1.1": "high",  # S3 bucket public access
    "CIS-AWS-2.1.2": "high",  # S3 bucket encryption
    "CIS-AWS-2.2.1": "high",  # EBS encryption
    "CIS-AWS-3.1": "high",  # CloudTrail enabled
    "CIS-AWS-4.1": "high",  # security group ingress 0.0.0.0/0
    "CIS-AWS-5.1": "high",  # VPC flow logs
}

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def apply_benchmark_severity_floor(benchmark_id: str | None, current_severity: Severity) -> Severity:
    if benchmark_id is None:
        return current_severity
    floor_label = _BENCHMARK_SEVERITY_FLOORS.get(benchmark_id)
    if floor_label is None:
        return current_severity
    if _SEVERITY_ORDER.get(floor_label, 0) > _SEVERITY_ORDER.get(current_severity.value, 0):
        return Severity(floor_label)
    return current_severity


def compute_risk_score(
    severity: Severity,
    evidence_method: EvidenceMethod,
    exposure: Exposure,
    *,
    has_attack_path: bool = False,
    has_drift: bool = False,
) -> float:
    severity_weight = SEVERITY_WEIGHTS[severity.value]
    evidence_mult = EVIDENCE_MULTIPLIERS[evidence_method]
    exposure_mult = EXPOSURE_MULTIPLIERS[exposure]
    path_bonus = 2.0 if has_attack_path else 1.0
    drift_bonus = 1.3 if has_drift else 1.0

    score = severity_weight * evidence_mult * exposure_mult * path_bonus * drift_bonus
    return round(min(max(score, 0.0), 10.0), 2)


def severity_label_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"
