"""Verify SECURITY.md contains required citations and structural content.

DOC-01: SECURITY.md must cite Campbell et al. 2026 with honest framing.
The citation must describe the authorization paradox mechanism accurately and
must not over-claim that Campbell validates CloneGuard's specific approach.
"""

from pathlib import Path

SECURITY_MD = Path(__file__).parent.parent / "docs" / "SECURITY.md"


def test_campbell_citation():
    """DOC-01: SECURITY.md must cite Campbell et al. 2026."""
    text = SECURITY_MD.read_text()
    assert "Campbell et al." in text, "Missing Campbell et al. citation"
    assert "arXiv:2603.01246" in text or "2603.01246" in text, "Missing arXiv reference"
    assert "authorization paradox" in text.lower(), "Missing authorization paradox discussion"
    assert "embedding" in text.lower(), "Missing embedding-space mechanism discussion"


def test_security_doc_no_overclaim():
    """Campbell citation must not over-claim validation of CloneGuard."""
    text = SECURITY_MD.read_text()
    lower = text.lower()
    if "campbell" in lower:
        # Should NOT claim Campbell "validates" or "proves" CloneGuard's approach
        assert "validates cloneguard" not in lower, (
            "Over-claim: Campbell does not validate CloneGuard"
        )
        assert "proves cloneguard" not in lower, "Over-claim: Campbell does not prove CloneGuard"


def test_inv01_finding_present():
    """SECURITY.md must include the empirical INV-01 finding (FPR numbers)."""
    text = SECURITY_MD.read_text()
    # The measured paradox effect: +12.7pp increase
    assert "12.7" in text, (
        "Missing INV-01 measured delta (+12.7pp) — finding must be present, not just cited"
    )
    # Both baseline and auth-marker FPR should appear
    assert "9.25%" in text or "9.2%" in text, "Missing Tier 1.5 baseline FPR"
    assert "21.93%" in text or "21.9%" in text, "Missing Tier 1.5 auth-marker FPR"


def test_honest_framing_independent_test():
    """Citation must frame INV-01 as an independent test, not a replication."""
    text = SECURITY_MD.read_text()
    lower = text.lower()
    # The RESEARCH.md Pitfall 5 requirement: frame as independent test, not replication
    assert "independent" in lower or "our" in lower, (
        "Citation should distinguish CloneGuard's investigation from Campbell's study"
    )
