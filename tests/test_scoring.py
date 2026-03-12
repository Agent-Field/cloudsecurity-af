from __future__ import annotations

import pytest

from cloudsecurity_af.scoring import (
    EvidenceMethod,
    Exposure,
    Severity,
    apply_benchmark_severity_floor,
    compute_risk_score,
    severity_label_from_score,
)


class TestComputeRiskScore:
    def test_critical_live_internet(self) -> None:
        score = compute_risk_score(
            Severity.CRITICAL,
            EvidenceMethod.LIVE_VERIFIED,
            Exposure.INTERNET_FACING,
        )
        assert score == 10.0

    def test_info_heuristic_admin(self) -> None:
        score = compute_risk_score(
            Severity.INFO,
            EvidenceMethod.HEURISTIC_MATCH,
            Exposure.REQUIRES_ADMIN,
        )
        assert score == pytest.approx(0.04, abs=0.01)

    def test_attack_path_bonus(self) -> None:
        base = compute_risk_score(Severity.HIGH, EvidenceMethod.STATIC_CONFIG_MATCH, Exposure.VPC_INTERNAL)
        with_path = compute_risk_score(
            Severity.HIGH, EvidenceMethod.STATIC_CONFIG_MATCH, Exposure.VPC_INTERNAL, has_attack_path=True
        )
        assert with_path == pytest.approx(base * 2.0, abs=0.01)

    def test_drift_bonus(self) -> None:
        base = compute_risk_score(Severity.MEDIUM, EvidenceMethod.DRIFT_CONFIRMED, Exposure.PRIVATE_SUBNET)
        with_drift = compute_risk_score(
            Severity.MEDIUM, EvidenceMethod.DRIFT_CONFIRMED, Exposure.PRIVATE_SUBNET, has_drift=True
        )
        assert with_drift == pytest.approx(base * 1.3, abs=0.01)

    def test_score_clamped_at_10(self) -> None:
        score = compute_risk_score(
            Severity.CRITICAL,
            EvidenceMethod.LIVE_VERIFIED,
            Exposure.INTERNET_FACING,
            has_attack_path=True,
            has_drift=True,
        )
        assert score == 10.0

    def test_score_non_negative(self) -> None:
        score = compute_risk_score(
            Severity.INFO,
            EvidenceMethod.HEURISTIC_MATCH,
            Exposure.REQUIRES_ADMIN,
        )
        assert score >= 0.0


class TestBenchmarkSeverityFloor:
    def test_floor_upgrades_severity(self) -> None:
        result = apply_benchmark_severity_floor("CIS-AWS-1.4", Severity.LOW)
        assert result == Severity.CRITICAL

    def test_floor_no_downgrade(self) -> None:
        result = apply_benchmark_severity_floor("CIS-AWS-2.1.1", Severity.CRITICAL)
        assert result == Severity.CRITICAL

    def test_unknown_benchmark_passthrough(self) -> None:
        result = apply_benchmark_severity_floor("CIS-AWS-99.99", Severity.LOW)
        assert result == Severity.LOW

    def test_none_benchmark_passthrough(self) -> None:
        result = apply_benchmark_severity_floor(None, Severity.MEDIUM)
        assert result == Severity.MEDIUM


class TestSeverityLabelFromScore:
    @pytest.mark.parametrize(
        "score, expected",
        [
            (10.0, "critical"),
            (9.0, "critical"),
            (8.5, "high"),
            (7.0, "high"),
            (5.0, "medium"),
            (4.0, "medium"),
            (2.0, "low"),
            (1.0, "low"),
            (0.5, "info"),
            (0.0, "info"),
        ],
    )
    def test_label_mapping(self, score: float, expected: str) -> None:
        assert severity_label_from_score(score) == expected
