"""Tests enforcing evidence standard (D-09) for agent-type pattern libraries.

Every pattern in agent-type subdirectories (browser/, autonomous/, financial/,
cicd/) MUST have a non-empty 'evidence' field citing a CVE, published incident,
research paper, or OWASP/MITRE taxonomy entry.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def _get_agent_type_rules_dir() -> Path:
    """Return the path to the rules directory."""
    return Path(__file__).parent.parent / "src" / "cloneguard" / "rules"


AGENT_TYPE_SUBDIRS = ["browser", "autonomous", "financial", "cicd"]


class TestPatternEvidence:
    """All agent-type patterns must have evidence citations per D-09."""

    def test_all_agent_type_patterns_have_evidence(self) -> None:
        """Every pattern in agent-type subdirectories has a non-empty evidence field."""
        rules_dir = _get_agent_type_rules_dir()
        missing: list[str] = []

        for subdir_name in AGENT_TYPE_SUBDIRS:
            subdir = rules_dir / subdir_name
            assert subdir.is_dir(), f"Missing agent-type directory: {subdir}"

            for yaml_file in sorted(subdir.glob("*.yaml")):
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)

                if not data or "patterns" not in data:
                    continue

                for pattern in data["patterns"]:
                    pattern_id = pattern.get("id", "UNKNOWN")
                    evidence = pattern.get("evidence", "")
                    if not evidence or not evidence.strip():
                        missing.append(f"{yaml_file.relative_to(rules_dir)}: {pattern_id}")

        assert not missing, "Patterns missing evidence field (D-09 violation):\n" + "\n".join(
            f"  - {m}" for m in missing
        )

    def test_agent_type_pattern_id_prefixes(self) -> None:
        """Agent-type patterns use correct prefixes (BRW-, AUT-, FIN-, CIC-)."""
        rules_dir = _get_agent_type_rules_dir()
        expected_prefixes = {
            "browser": "BRW-",
            "autonomous": "AUT-",
            "financial": "FIN-",
            "cicd": "CIC-",
        }
        violations: list[str] = []

        for subdir_name, expected_prefix in expected_prefixes.items():
            subdir = rules_dir / subdir_name
            if not subdir.is_dir():
                continue

            for yaml_file in sorted(subdir.glob("*.yaml")):
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)

                if not data or "patterns" not in data:
                    continue

                for pattern in data["patterns"]:
                    pattern_id = pattern.get("id", "UNKNOWN")
                    if not pattern_id.startswith(expected_prefix):
                        violations.append(
                            f"{subdir_name}/{yaml_file.name}: {pattern_id} "
                            f"(expected prefix {expected_prefix})"
                        )

        assert not violations, "Pattern ID prefix violations:\n" + "\n".join(
            f"  - {v}" for v in violations
        )

    def test_no_pattern_id_collisions_across_all_rules(self) -> None:
        """Pattern IDs are unique across root-level and subdirectory rules."""
        rules_dir = _get_agent_type_rules_dir()
        all_ids: dict[str, str] = {}  # id -> source file
        collisions: list[str] = []

        # Root-level rules
        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if not data or "patterns" not in data:
                continue
            for pattern in data["patterns"]:
                pid = pattern.get("id", "")
                source = str(yaml_file.relative_to(rules_dir))
                if pid in all_ids:
                    collisions.append(f"{pid}: {all_ids[pid]} AND {source}")
                all_ids[pid] = source

        # Subdirectory rules
        for subdir_name in AGENT_TYPE_SUBDIRS:
            subdir = rules_dir / subdir_name
            if not subdir.is_dir():
                continue
            for yaml_file in sorted(subdir.glob("*.yaml")):
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if not data or "patterns" not in data:
                    continue
                for pattern in data["patterns"]:
                    pid = pattern.get("id", "")
                    source = str(yaml_file.relative_to(rules_dir))
                    if pid in all_ids:
                        collisions.append(f"{pid}: {all_ids[pid]} AND {source}")
                    all_ids[pid] = source

        assert not collisions, "Pattern ID collisions (T-06-04):\n" + "\n".join(
            f"  - {c}" for c in collisions
        )

    def test_minimum_pattern_counts_per_agent_type(self) -> None:
        """Each agent type has at least 8 seed patterns."""
        rules_dir = _get_agent_type_rules_dir()

        for subdir_name in AGENT_TYPE_SUBDIRS:
            subdir = rules_dir / subdir_name
            assert subdir.is_dir(), f"Missing: {subdir}"

            count = 0
            for yaml_file in sorted(subdir.glob("*.yaml")):
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if data and "patterns" in data:
                    count += len(data["patterns"])

            assert count >= 8, f"{subdir_name}: only {count} patterns (need >= 8)"
