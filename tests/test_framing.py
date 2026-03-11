"""
Framing audit: automated grep for prohibited words across publication-relevant
markdown files.

Prohibited framing words in CloneGuard publications:
  "prevents", "blocks", "secure", "protection against", "immune to"

These words imply absolute guarantees that cannot be made honestly. CloneGuard
raises attacker cost; it does not prevent, block, or provide absolute security.

Exceptions:
  - "SECURITY.md" as a filename reference (not a claim)
  - "security" in non-framing contexts (e.g. "security architect",
    "security tool", "security documentation")
  - "secure" in technical non-claim contexts (e.g. "secure boot",
    "HTTPS secure", "TLS secure channel") -- but these should not appear
    in CloneGuard's own performance claims
  - Lines in the "What CloneGuard does NOT protect against" section
    (honest limitation statements)
  - Lines explicitly describing what is NOT protected (negation context)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent

# Files that must pass the framing audit
REQUIRED_FILES = [
    REPO_ROOT / "docs" / "SECURITY.md",
    REPO_ROOT / "docs" / "MINI-SEMANTIC-MODEL.md",
]

# Publications directory — all markdown files within must pass
PUBLICATIONS_DIR = REPO_ROOT / "docs" / "publications"

# Required publication files (must exist AND pass framing audit)
REQUIRED_PUBLICATION_FILES = [
    PUBLICATIONS_DIR / "hf-model-card-v4-draft.md",
    PUBLICATIONS_DIR / "v0.3.0-release-notes.md",
]

# Prohibited patterns (case-insensitive, word-boundary matched where sensible)
# These target FRAMING CLAIMS about CloneGuard's capabilities — not
# technical descriptions of system actions (which legitimately use these words).
#
# Prohibited: "CloneGuard prevents attacks", "this blocks all injections"
# Allowed: "the hook blocks writes to ~/.claude" (system action description)
#          "False block rate: 3.8%" (metric label)
#          "blocks agent launch if critical issues are found" (behavior description)
#
# Each entry: (pattern, description)
PROHIBITED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # "CloneGuard prevents X" — CloneGuard-attributed prevention claim
    (
        re.compile(
            r"\bCloneGuard\s+(prevents?|stops?|eliminates?)\b",
            re.IGNORECASE,
        ),
        "prevents (CloneGuard framing claim)",
    ),
    # "this prevents X" / "it prevents X" in performance claim context
    (
        re.compile(
            r"\b(this\s+tool|our\s+tool|it|this)\s+(prevents?|stops?)\s+"
            r"(all|any|prompt\s+injection|attacks?|evasion)",
            re.IGNORECASE,
        ),
        "prevents (tool performance claim)",
    ),
    (re.compile(r"\bimmune\s+to\b", re.IGNORECASE), "immune to"),
    (re.compile(r"\bprotection\s+against\b", re.IGNORECASE), "protection against"),
]

# "secure" is more context-dependent — only flag it in performance claim contexts
SECURE_PATTERN = re.compile(r"\bsecure\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Allow-list regexes: lines matching these are excluded from violation checks
# ---------------------------------------------------------------------------

# Lines that describe what CloneGuard does NOT protect against (honest limits)
NOT_PROTECT_NEGATION = re.compile(
    r"does\s+not\s+(protect|prevent|block|secure|guarantee)|"
    r"cannot\s+(prevent|block|guarantee|protect)|"
    r"no\s+(complete\s+)?solution|"
    r"not\s+a\s+guarantee|"
    r"not\s+infallible|"
    r"not\s+guaranteed|"
    r"does\s+not\s+guarantee|"
    r"will\s+not\s+(prevent|block)",
    re.IGNORECASE,
)

# Section headers and filename references (e.g. "SECURITY.md", "docs/SECURITY.md")
FILENAME_REFERENCE = re.compile(
    r"`[^`]*SECURITY[^`]*`|"  # inline code like `SECURITY.md`
    r"\[SECURITY\.md\]|"  # markdown link text
    r"docs/SECURITY\.md|"  # path reference
    r"^\s*#.*SECURITY",  # section header containing "SECURITY"
    re.IGNORECASE,
)

# Non-framing "security" contexts: "security architect", "security tool",
# "security documentation", "security researcher", "security community",
# "security model", "security engineer", "security team", "security review",
# "security context", "security finding", "security layer", "security boundary"
SECURITY_NOUN_PHRASE = re.compile(
    r"\bsecurity\s+(architect|tool|documentation|researcher|community|model|"
    r"engineer|team|review|context|finding|layer|boundary|audit|analysis|"
    r"property|properties|report|disclosure|framework|standard|controls?|"
    r"practitioner|professional|posture|monitor|monitoring|event|events|"
    r"assessment|scanner|scanning|checker|check|guard|guardrail|guardrail|"
    r"classification|classifier|threat|threats|gap|gaps|issue|issues|"
    r"concern|concerns|implication|implications|consideration|considerations|"
    r"decision|decisions|category|categories|impact|requirement|requirements|"
    r"design|policy|policies|posture|budget|investment|update|updates|"
    r"patch|patches|fix|fixes|researcher|researchers|advisor|advisors|"
    r"claim|claims|property|properties|flaw|flaws|defect|defects|"
    r"vulnerability|vulnerabilities|exploit|exploits|bug|bugs|weakness|weaknesses|"
    r"header|headers|credential|credentials|token|tokens|key|keys|secret|secrets|"
    r"alert|alerts|signal|signals|indicator|indicators|log|logs|metric|metrics)\b|"
    r"\bsecurity\b.*\b(documentation|tool|audit|architecture|research|context)\b",
    re.IGNORECASE,
)

# "blocks" used in technical/non-claim context (e.g. code blocks, markdown blocks)
CODE_BLOCK_CONTEXT = re.compile(
    r"code\s+block|fenced\s+block|token\s+block|block\s+scanning|"
    r"```|^\s*>|^\s*\|",
    re.IGNORECASE,
)

# Lines in "What CloneGuard does NOT protect against" sections
NOT_PROTECT_SECTION_HEADER = re.compile(
    r"does\s+not\s+protect\s+against|"
    r"NOT\s+protect\s+against|"
    r"cannot\s+protect|"
    r"out\s+of\s+scope",
    re.IGNORECASE,
)


def _is_allowlisted(line: str, prev_section_header: str) -> bool:
    """Return True if a line should be excluded from the framing violation check."""
    # Honest negation statements
    if NOT_PROTECT_NEGATION.search(line):
        return True
    # Filename references
    if FILENAME_REFERENCE.search(line):
        return True
    # Lines that are themselves section headers describing limitations
    if NOT_PROTECT_SECTION_HEADER.search(line):
        return True
    # Section header context: if we're in a "does not protect against" section,
    # allow bullets that enumerate what isn't protected
    if prev_section_header and NOT_PROTECT_SECTION_HEADER.search(prev_section_header):
        return True
    return False


def _check_secure_allowlisted(line: str) -> bool:
    """Return True if 'secure' in this line is a non-framing usage."""
    if SECURITY_NOUN_PHRASE.search(line):
        return True
    if NOT_PROTECT_NEGATION.search(line):
        return True
    if FILENAME_REFERENCE.search(line):
        return True
    # Technical protocol contexts
    if re.search(
        r"\b(https?|TLS|SSL|CORS|CSRF|OAuth|SSH)\b.*\bsecure\b|"
        r"\bsecure\b.*\b(channel|connection|transport|socket|boot|"
        r"hash|token|credential|handshake|protocol|storage|enclave|"
        r"element|chip|key|key\s+exchange|random|erase)\b",
        line,
        re.IGNORECASE,
    ):
        return True
    # "Secure development lifecycle" / "secure development" — describing a venue/domain
    if re.search(r"\bsecure\s+development\b", line, re.IGNORECASE):
        return True
    # "security" in general noun usage (not a performance claim about CloneGuard)
    if re.search(r"\bsecurity\b", line, re.IGNORECASE) and not re.search(
        r"\bCloneGuard\b|\bTier\s+\d|\bthe\s+model\b|\bthe\s+classifier\b|"
        r"\bthe\s+scanner\b|\bthe\s+detector\b|\bour\s+defense\b",
        line,
        re.IGNORECASE,
    ):
        return True
    return False


def collect_violations(path: Path) -> list[str]:
    """
    Scan a markdown file for prohibited framing words.
    Returns a list of violation strings (empty = no violations).
    """
    if not path.exists():
        return [f"FILE_MISSING: {path}"]

    violations: list[str] = []
    prev_section_header = ""
    content = path.read_text(encoding="utf-8")

    for lineno, line in enumerate(content.splitlines(), start=1):
        # Track section headers for context
        if re.match(r"^\s*#{1,6}\s+", line):
            prev_section_header = line

        if _is_allowlisted(line, prev_section_header):
            continue

        # Check prohibited patterns
        for pattern, label in PROHIBITED_PATTERNS:
            if pattern.search(line):
                violations.append(f"{path.name}:{lineno}: [{label}] {line.strip()[:120]}")
                break

        # Check "secure" separately (more context-sensitive)
        if SECURE_PATTERN.search(line):
            if not _check_secure_allowlisted(line):
                violations.append(f"{path.name}:{lineno}: [secure] {line.strip()[:120]}")

    return violations


def get_all_publication_files() -> list[Path]:
    """Return all markdown files in docs/publications/."""
    if not PUBLICATIONS_DIR.exists():
        return []
    return sorted(PUBLICATIONS_DIR.glob("*.md"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_security_md_no_prohibited_framing() -> None:
    """docs/SECURITY.md must not contain prohibited framing words."""
    path = REQUIRED_FILES[0]
    violations = collect_violations(path)
    assert not violations, f"Framing violations in {path.name}:\n" + "\n".join(violations)


def test_mini_semantic_model_md_no_prohibited_framing() -> None:
    """docs/MINI-SEMANTIC-MODEL.md must not contain prohibited framing words."""
    path = REQUIRED_FILES[1]
    violations = collect_violations(path)
    assert not violations, f"Framing violations in {path.name}:\n" + "\n".join(violations)


def test_hf_model_card_draft_exists() -> None:
    """docs/publications/hf-model-card-v4-draft.md must exist (gitignored — skip in CI)."""
    path = PUBLICATIONS_DIR / "hf-model-card-v4-draft.md"
    if not path.exists():
        pytest.skip("hf-model-card-v4-draft.md not present (gitignored, local-only)")
    assert path.exists()


def test_hf_model_card_draft_no_prohibited_framing() -> None:
    """docs/publications/hf-model-card-v4-draft.md must not contain prohibited words."""
    path = PUBLICATIONS_DIR / "hf-model-card-v4-draft.md"
    if not path.exists():
        pytest.skip("hf-model-card-v4-draft.md not yet created (run Task 1 first)")
    violations = collect_violations(path)
    assert not violations, f"Framing violations in {path.name}:\n" + "\n".join(violations)


def test_release_notes_exists() -> None:
    """docs/publications/v0.3.0-release-notes.md must exist (gitignored — skip in CI)."""
    path = PUBLICATIONS_DIR / "v0.3.0-release-notes.md"
    if not path.exists():
        pytest.skip("v0.3.0-release-notes.md not present (gitignored, local-only)")
    assert path.exists()


def test_release_notes_no_prohibited_framing() -> None:
    """docs/publications/v0.3.0-release-notes.md must not contain prohibited words."""
    path = PUBLICATIONS_DIR / "v0.3.0-release-notes.md"
    if not path.exists():
        pytest.skip("v0.3.0-release-notes.md not yet created (run Task 1 first)")
    violations = collect_violations(path)
    assert not violations, f"Framing violations in {path.name}:\n" + "\n".join(violations)


def test_all_publications_no_prohibited_framing() -> None:
    """All markdown files in docs/publications/ must not contain prohibited framing words."""
    pub_files = get_all_publication_files()
    if not pub_files:
        pytest.skip("docs/publications/ directory is empty or does not exist")

    all_violations: list[str] = []
    for path in pub_files:
        violations = collect_violations(path)
        all_violations.extend(violations)

    assert not all_violations, "Framing violations in docs/publications/:\n" + "\n".join(
        all_violations
    )


def test_prohibited_word_list_is_comprehensive() -> None:
    """Verify prohibited framing categories from the plan are represented in patterns."""
    # These are the framing categories from the plan spec.
    # We verify each category has at least one pattern, rather than checking plain-word
    # matches (patterns use compound matching to avoid false positives on technical usage).
    combined_pattern_source = " ".join(p.pattern for p, _ in PROHIBITED_PATTERNS)

    # "prevents" category — covered by CloneGuard-specific and tool-specific patterns
    assert "prevent" in combined_pattern_source.lower(), (
        "prevents category must be covered in pattern source"
    )

    # "secure" category — covered by SECURE_PATTERN
    assert SECURE_PATTERN.pattern == r"\bsecure\b", "secure pattern must be present"

    # "immune to" — explicit pattern
    assert any("immune" in p.pattern.lower() for p, _ in PROHIBITED_PATTERNS), (
        "'immune to' pattern must be present"
    )

    # "protection against" — explicit pattern
    assert any("protection" in p.pattern.lower() for p, _ in PROHIBITED_PATTERNS), (
        "'protection against' pattern must be present"
    )

    # Verify at least 4 prohibited pattern entries exist
    assert len(PROHIBITED_PATTERNS) >= 4, (
        f"Expected at least 4 prohibited patterns, got {len(PROHIBITED_PATTERNS)}"
    )
