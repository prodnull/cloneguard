"""Tests for CI/CD adapter and GitHub Actions composite action.

Validates CICDAdapter normalization of webhook events into ToolCallEvent,
response formatting, InputAdapter Protocol conformance, and action.yml
structural correctness.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from cloneguard.adapters import InputAdapter
from cloneguard.adapters.cicd import CICDAdapter
from cloneguard.detection.types import DetectionResult, ToolCallEvent

# ---------------------------------------------------------------------------
# CICDAdapter.normalize() tests
# ---------------------------------------------------------------------------


def test_normalize_pr_webhook_with_changed_files() -> None:
    """PR webhook with changed files normalizes to ToolCallEvent with content."""
    adapter = CICDAdapter()
    raw: dict[str, Any] = {
        "action": "opened",
        "pull_request": {"number": 42},
        "changed_files": [
            {"filename": "src/main.py", "patch": "print('hello')"},
        ],
    }
    event = adapter.normalize(raw)
    assert isinstance(event, ToolCallEvent)
    assert event.event_type == "PreToolUse"
    assert event.tool_name == "pr-scan"
    assert event.content == "print('hello')"
    assert event.source_path == "src/main.py"


def test_normalize_empty_payload_no_crash() -> None:
    """Empty payload does not crash; returns ToolCallEvent with safe defaults."""
    adapter = CICDAdapter()
    event = adapter.normalize({})
    assert isinstance(event, ToolCallEvent)
    assert event.event_type == "PreToolUse"
    assert event.tool_name == "pr-scan"
    assert event.content == ""


def test_normalize_synchronize_action() -> None:
    """PR synchronize action still produces PreToolUse event (pre-merge scan)."""
    adapter = CICDAdapter()
    raw: dict[str, Any] = {
        "action": "synchronize",
        "pull_request": {"number": 42},
    }
    event = adapter.normalize(raw)
    assert event.event_type == "PreToolUse"
    assert event.tool_name == "pr-scan"


def test_normalize_multiple_changed_files() -> None:
    """Multiple changed files: content concatenated, source_path comma-separated."""
    adapter = CICDAdapter()
    raw: dict[str, Any] = {
        "action": "opened",
        "pull_request": {"number": 7},
        "changed_files": [
            {"filename": "a.py", "patch": "aaa"},
            {"filename": "b.py", "patch": "bbb"},
        ],
    }
    event = adapter.normalize(raw)
    assert "aaa" in event.content
    assert "bbb" in event.content
    assert "a.py" in event.source_path
    assert "b.py" in event.source_path


# ---------------------------------------------------------------------------
# CICDAdapter.format_response() tests
# ---------------------------------------------------------------------------


def test_format_response_allow() -> None:
    """Exit code 0 -> not blocked, SARIF generated."""
    adapter = CICDAdapter()
    result = DetectionResult(verdict="clean", confidence=0.0, exit_code=0)
    resp = adapter.format_response(result, {})
    assert resp["blocked"] is False
    assert resp["sarif_generated"] is True


def test_format_response_block() -> None:
    """Exit code >= 2 -> blocked with reason."""
    adapter = CICDAdapter()
    result = DetectionResult(
        verdict="detected", confidence=0.95, exit_code=2, message="injection found"
    )
    resp = adapter.format_response(result, {})
    assert resp["blocked"] is True
    assert resp["reason"] == "injection found"


def test_format_response_warning() -> None:
    """Exit code 1 (warning) -> blocked with reason."""
    adapter = CICDAdapter()
    result = DetectionResult(
        verdict="suspicious", confidence=0.6, exit_code=1, message="suspicious content"
    )
    resp = adapter.format_response(result, {})
    assert resp["blocked"] is True
    assert resp["reason"] == "suspicious content"


# ---------------------------------------------------------------------------
# InputAdapter Protocol conformance
# ---------------------------------------------------------------------------


def test_cicd_adapter_satisfies_input_adapter_protocol() -> None:
    """CICDAdapter is an instance of InputAdapter Protocol."""
    adapter = CICDAdapter()
    assert isinstance(adapter, InputAdapter)


def test_cicd_adapter_agent_type() -> None:
    """CICDAdapter.agent_type returns 'cicd'."""
    adapter = CICDAdapter()
    assert adapter.agent_type == "cicd"


# ---------------------------------------------------------------------------
# action.yml structural tests
# ---------------------------------------------------------------------------

_ACTION_PATH = (
    Path(__file__).resolve().parent.parent
    / ".github"
    / "actions"
    / "cloneguard-scan"
    / "action.yml"
)


def test_action_yml_is_valid_yaml() -> None:
    """action.yml loads as valid YAML."""
    data = yaml.safe_load(_ACTION_PATH.read_text(encoding="utf-8"))
    assert data is not None


def test_action_yml_uses_composite_runner() -> None:
    """action.yml uses composite runner."""
    data = yaml.safe_load(_ACTION_PATH.read_text(encoding="utf-8"))
    assert data["runs"]["using"] == "composite"


def test_action_yml_has_expected_inputs() -> None:
    """action.yml has threshold, scan-paths, fail-on, python-version inputs."""
    data = yaml.safe_load(_ACTION_PATH.read_text(encoding="utf-8"))
    inputs = data["inputs"]
    assert "threshold" in inputs
    assert "scan-paths" in inputs
    assert "fail-on" in inputs
    assert "python-version" in inputs


def test_action_yml_input_defaults() -> None:
    """action.yml inputs have correct default values."""
    data = yaml.safe_load(_ACTION_PATH.read_text(encoding="utf-8"))
    inputs = data["inputs"]
    assert inputs["scan-paths"]["default"] == "."
    assert inputs["fail-on"]["default"] == "malicious"
    assert inputs["python-version"]["default"] == "3.12"


def test_action_yml_uses_setup_uv() -> None:
    """action.yml uses astral-sh/setup-uv@v5."""
    content = _ACTION_PATH.read_text(encoding="utf-8")
    assert "astral-sh/setup-uv@v5" in content


def test_action_yml_uses_upload_sarif() -> None:
    """action.yml uses github/codeql-action/upload-sarif@v4 with category cloneguard."""
    content = _ACTION_PATH.read_text(encoding="utf-8")
    assert "github/codeql-action/upload-sarif@v4" in content
    assert "cloneguard" in content


def test_action_yml_upload_sarif_always_runs() -> None:
    """Upload SARIF step has 'if: always()' condition."""
    data = yaml.safe_load(_ACTION_PATH.read_text(encoding="utf-8"))
    steps = data["runs"]["steps"]
    # Find the upload-sarif step
    upload_step = None
    for step in steps:
        uses = step.get("uses", "")
        if "upload-sarif" in uses:
            upload_step = step
            break
    assert upload_step is not None, "upload-sarif step not found"
    assert upload_step.get("if") == "always()"


def test_action_yml_runs_cloneguard_scan() -> None:
    """action.yml runs cloneguard scan with --sarif flag."""
    content = _ACTION_PATH.read_text(encoding="utf-8")
    assert "cloneguard scan" in content
    assert "--sarif" in content
