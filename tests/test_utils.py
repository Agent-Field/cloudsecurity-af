from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cloudsecurity_af.agents._utils import extract_harness_result
from cloudsecurity_af.schemas.hunt import HuntResult


class TestExtractHarnessResult:
    def test_parsed_is_correct_type(self) -> None:
        expected = HuntResult(findings=[], total_raw=0)
        mock_result = MagicMock()
        mock_result.is_error = False
        mock_result.parsed = expected
        assert extract_harness_result(mock_result, HuntResult, "test") is expected

    def test_parsed_is_dict_validates(self) -> None:
        mock_result = MagicMock()
        mock_result.is_error = False
        mock_result.parsed = {"findings": [], "total_raw": 5}
        result = extract_harness_result(mock_result, HuntResult, "test")
        assert isinstance(result, HuntResult)
        assert result.total_raw == 5

    def test_error_raises(self) -> None:
        mock_result = MagicMock()
        mock_result.is_error = True
        mock_result.error_message = "something broke"
        mock_result.result = None
        mock_result.num_turns = 3
        mock_result.duration_ms = 1000
        with pytest.raises(RuntimeError, match="test harness error"):
            extract_harness_result(mock_result, HuntResult, "test")

    def test_invalid_parsed_raises_type_error(self) -> None:
        mock_result = MagicMock()
        mock_result.is_error = False
        mock_result.parsed = "not a dict or HuntResult"
        with pytest.raises(TypeError, match="did not return a valid"):
            extract_harness_result(mock_result, HuntResult, "test")


class TestPromptTemplatesExist:
    PROMPT_ROOT = Path(__file__).resolve().parents[1] / "prompts"

    EXPECTED_TEMPLATES = [
        "recon/iac_reader.txt",
        "recon/resource_graph_builder.txt",
        "recon/cloud_connector.txt",
        "recon/drift_detector.txt",
        "hunt/iam.txt",
        "hunt/network.txt",
        "hunt/data.txt",
        "hunt/secrets.txt",
        "hunt/compute.txt",
        "hunt/logging.txt",
        "hunt/compliance.txt",
        "chain/path_constructor.txt",
        "prove/static_prover.txt",
        "prove/live_prover.txt",
        "remediate/fix_generator.txt",
    ]

    @pytest.mark.parametrize("template_path", EXPECTED_TEMPLATES)
    def test_template_exists(self, template_path: str) -> None:
        full_path = self.PROMPT_ROOT / template_path
        assert full_path.exists(), f"Missing prompt template: {full_path}"

    @pytest.mark.parametrize("template_path", EXPECTED_TEMPLATES)
    def test_template_not_empty(self, template_path: str) -> None:
        full_path = self.PROMPT_ROOT / template_path
        content = full_path.read_text(encoding="utf-8")
        assert len(content.strip()) > 50, f"Template suspiciously short: {full_path}"


class TestHuntPromptPlaceholders:
    PROMPT_ROOT = Path(__file__).resolve().parents[1] / "prompts" / "hunt"
    REQUIRED_PLACEHOLDERS = [
        "{{RESOURCE_GRAPH_SUMMARY}}",
        "{{INVENTORY_STATS}}",
        "{{RELEVANT_EDGES}}",
        "{{REPO_PATH}}",
        "{{DEPTH}}",
    ]
    HUNT_TEMPLATES = [
        "iam.txt",
        "network.txt",
        "data.txt",
        "secrets.txt",
        "compute.txt",
        "logging.txt",
        "compliance.txt",
    ]

    @pytest.mark.parametrize("template_name", HUNT_TEMPLATES)
    def test_hunt_prompt_has_required_placeholders(self, template_name: str) -> None:
        content = (self.PROMPT_ROOT / template_name).read_text(encoding="utf-8")
        for placeholder in self.REQUIRED_PLACEHOLDERS:
            assert placeholder in content, f"{template_name} missing placeholder: {placeholder}"
