"""Phase 4 Nyquist validation -- behavioral tests for FPR Investigation.

Tests fill gaps identified by /gsd:validate-phase:
- INV-01: run_inv01() produces correct structure with tier separation
- INV-02: run_inv02() produces correct per-pattern structure
- INV-03: findings document contains required analytical sections
- DOC-02: Medium draft contains Campbell contextualization (skip if absent)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT / "scripts"))


# ---------------------------------------------------------------------------
# INV-01 behavioral: run_inv01() tier-separated output with paradox logic
# ---------------------------------------------------------------------------


def test_inv01_produces_tier_separated_output_with_paradox_detection():
    """INV-01: run_inv01() must report Tier 0 and Tier 1.5 FPR
    separately and detect authorization paradox correctly."""
    from fpr_investigation import run_inv01

    # Minimal synthetic benign samples -- 2 content types
    samples = [
        {
            "id": f"synth_{i}",
            "content_type": "readme",
            "text": f"Benign readme file number {i} with docs.",
        }
        for i in range(5)
    ] + [
        {
            "id": f"synth_wf_{i}",
            "content_type": "workflow",
            "text": (
                "name: CI\non:\n  push:\njobs:\n  build:\n"
                "    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4"
            ),
        }
        for i in range(5)
    ]

    from cloneguard.patterns import PatternEngine

    engine = PatternEngine()

    # Mock classifier to control paradox detection
    class MockClassifier:
        """Flag auth-preambled content to simulate paradox."""

        def classify(self, text: str):
            class Result:
                pass

            r = Result()
            upper = text.upper()
            has_auth = "AUTHORIZED" in upper
            r.verdict = "MALICIOUS" if has_auth else "BENIGN"
            return r

    result = run_inv01(samples, engine, MockClassifier())

    # Structure assertions
    assert "corpus_size" in result
    assert result["corpus_size"] == 10
    assert "preamble_variants" in result
    assert result["preamble_variants"] == 3
    assert "tier0" in result, "INV-01 must have tier0 subsection"
    assert "tier15" in result, "INV-01 must have tier15 subsection"

    # Tier 0 must have all required keys
    tier0 = result["tier0"]
    t0_keys = (
        "baseline_fpr_by_content_type",
        "auth_marker_fpr_by_content_type",
        "delta_by_content_type",
    )
    for key in t0_keys:
        assert key in tier0, f"tier0 missing {key}"

    # Tier 1.5 must have all required keys
    tier15 = result["tier15"]
    t15_keys = (
        "baseline_fpr",
        "baseline_fpr_by_content_type",
        "auth_marker_fpr",
        "auth_marker_fpr_by_content_type",
        "delta_by_content_type",
    )
    for key in t15_keys:
        assert key in tier15, f"tier15 missing {key}"

    # FPR values must be in [0.0, 1.0]
    assert 0.0 <= tier15["baseline_fpr"] <= 1.0
    assert 0.0 <= tier15["auth_marker_fpr"] <= 1.0

    # Paradox detection fields
    assert "authorization_paradox_detected" in result
    assert isinstance(result["authorization_paradox_detected"], bool)
    assert "paradox_summary" in result
    assert isinstance(result["paradox_summary"], str)
    assert len(result["paradox_summary"]) > 20


# ---------------------------------------------------------------------------
# INV-02 behavioral: run_inv02() produces per-pattern output
# ---------------------------------------------------------------------------


def test_inv02_produces_per_pattern_fpr_for_strict_patterns():
    """INV-02: run_inv02() must audit CI-004, CI-006, SC-001, MCP-005
    and report per-pattern fires, samples_tested, and FPR."""
    from fpr_investigation import run_inv02

    samples = [
        {
            "id": "ds_mcp_01",
            "content_type": "agent_instructions",
            "text": (
                "Configure the MCP server by editing .mcp.json "
                "in the project root. Add API keys and endpoints."
            ),
            "source_description": "MCP config guide",
            "category": "mcp_config",
        },
        {
            "id": "ds_ci_01",
            "content_type": "agent_instructions",
            "text": (
                "In your CI pipeline, ensure all actions use "
                "pinned SHA commits. Avoid mutable tags."
            ),
            "source_description": "CI hardening guide",
            "category": "cicd_in_instructions",
        },
        {
            "id": "ds_pen_01",
            "content_type": "agent_instructions",
            "text": ("Run nmap -sV -sC target_host to enumerate open services. Document findings."),
            "source_description": "Pentest runbook",
            "category": "pentest",
        },
        {
            "id": "ds_ir_01",
            "content_type": "agent_instructions",
            "text": (
                "During incident response, collect volatile memory artifacts first. Use dd or LiME."
            ),
            "source_description": "IR playbook",
            "category": "ir",
        },
        {
            "id": "ds_hard_01",
            "content_type": "agent_instructions",
            "text": (
                "Apply CIS benchmark level 1 hardening. "
                "Disable root SSH login. Set password policy."
            ),
            "source_description": "Hardening guide",
            "category": "hardening",
        },
    ]

    from cloneguard.patterns import PatternEngine

    engine = PatternEngine()
    result = run_inv02(samples, engine)

    # Structure
    assert result["corpus_size"] == 5
    assert "strict_patterns_audited" in result
    expected = {"CI-004", "CI-006", "SC-001", "MCP-005"}
    assert set(result["strict_patterns_audited"]) == expected

    # Per-pattern entries
    assert "per_pattern" in result
    per_pattern = result["per_pattern"]
    for pid in ("CI-004", "CI-006", "SC-001", "MCP-005"):
        assert pid in per_pattern, f"Missing pattern {pid}"
        entry = per_pattern[pid]
        assert "fires" in entry
        assert "samples_tested" in entry
        assert "fpr" in entry
        assert isinstance(entry["fires"], int)
        assert isinstance(entry["samples_tested"], int)
        assert entry["samples_tested"] == 5
        assert 0.0 <= entry["fpr"] <= 1.0
        assert entry["fires"] <= entry["samples_tested"]

    # Other fires tracking
    assert "other_pattern_fires" in result
    assert isinstance(result["other_pattern_fires"], list)

    # Audit summary
    assert "audit_summary" in result
    assert len(result["audit_summary"]) > 30


# ---------------------------------------------------------------------------
# INV-03: Findings document content validation
# ---------------------------------------------------------------------------

_FINDINGS_PATH = _ROOT / "docs" / "results" / "fpr-investigation-findings.md"


@pytest.mark.skipif(
    not _FINDINGS_PATH.exists(),
    reason="Findings doc not present (gitignored local file)",
)
def test_inv03_findings_doc_contains_required_sections():
    """INV-03: Findings document must contain structured analysis of
    INV-01, INV-02, structural FPR limits, and Campbell relevance."""
    text = _FINDINGS_PATH.read_text()

    # Must have executive summary
    assert "Executive Summary" in text

    # Must cover INV-01 with tier separation
    assert "INV-01" in text
    assert "Authorization Paradox" in text
    assert "Tier 0" in text
    assert "Tier 1.5" in text

    # Must cover INV-02
    assert "INV-02" in text
    assert "Strict" in text

    # Must include measured values
    assert "12.7" in text, "Missing +12.7pp delta"
    assert "9.25" in text or "9.2%" in text

    # Must discuss structural limits and Campbell
    assert "structural" in text.lower()
    assert "Campbell" in text
    assert "Phase 5" in text

    # Minimum substantive length (80 lines per plan)
    lines = text.strip().split("\n")
    assert len(lines) >= 80, f"Only {len(lines)} lines"


# ---------------------------------------------------------------------------
# DOC-02: Medium draft Campbell contextualization
# ---------------------------------------------------------------------------

_MEDIUM_PATH = _ROOT / "docs" / "publications" / "2026-03-10-medium-adversarial-hardening.md"


@pytest.mark.skipif(
    not _MEDIUM_PATH.exists(),
    reason="Medium draft not present (gitignored local file)",
)
def test_doc02_medium_draft_contains_campbell_contextualization():
    """DOC-02: Medium Part 2 draft must contain Campbell et al.
    contextualization with paradox discussion and measured data."""
    text = _MEDIUM_PATH.read_text()
    lower = text.lower()

    assert "campbell" in lower
    assert "paradox" in lower
    assert "structural" in lower or "embedding" in lower
    assert "12.7" in text, "Missing +12.7pp measurement"
    assert "validates cloneguard" not in lower
    assert "proves cloneguard" not in lower
