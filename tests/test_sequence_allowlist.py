"""Tests for sequence allowlist -- domain-level for SEQ-001/002, exact-path for SEQ-005."""

from __future__ import annotations

from pathlib import Path

from cloneguard.sequence_allowlist import SequenceAllowlist


class TestSequenceAllowlist:
    def test_domain_allowlist_suppresses(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_domain_rule("SEQ-001", "vault.company.com")
        assert al.is_allowed("SEQ-001", domain="vault.company.com")

    def test_domain_does_not_suppress_other_domains(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_domain_rule("SEQ-001", "vault.company.com")
        assert not al.is_allowed("SEQ-001", domain="evil.example.com")

    def test_domain_does_not_cross_rules(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_domain_rule("SEQ-001", "vault.company.com")
        assert not al.is_allowed("SEQ-002", domain="vault.company.com")

    def test_path_allowlist_suppresses(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_path_rule("SEQ-005", "/project/.vscode/settings.json")
        assert al.is_allowed("SEQ-005", path="/project/.vscode/settings.json")

    def test_path_exact_match_only(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_path_rule("SEQ-005", "/project/.vscode/settings.json")
        assert not al.is_allowed("SEQ-005", path="/other/.vscode/settings.json")

    def test_persistence_across_instances(self, tmp_path: Path) -> None:
        f = tmp_path / "seq_allowlist.json"
        al1 = SequenceAllowlist(allowlist_file=f)
        al1.add_domain_rule("SEQ-001", "internal.corp.com")
        al2 = SequenceAllowlist(allowlist_file=f)
        assert al2.is_allowed("SEQ-001", domain="internal.corp.com")

    def test_remove_domain_rule(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_domain_rule("SEQ-001", "vault.company.com")
        al.remove_domain_rule("SEQ-001", "vault.company.com")
        assert not al.is_allowed("SEQ-001", domain="vault.company.com")

    def test_remove_path_rule(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_path_rule("SEQ-005", "/project/.vscode/settings.json")
        al.remove_path_rule("SEQ-005", "/project/.vscode/settings.json")
        assert not al.is_allowed("SEQ-005", path="/project/.vscode/settings.json")

    def test_list_entries(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_domain_rule("SEQ-001", "vault.company.com")
        al.add_path_rule("SEQ-005", "/project/.vscode/settings.json")
        entries = al.list_entries()
        assert len(entries) == 2

    def test_case_insensitive_domain(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_domain_rule("SEQ-001", "Vault.Company.COM")
        assert al.is_allowed("SEQ-001", domain="vault.company.com")

    def test_remove_nonexistent_returns_false(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        assert not al.remove_domain_rule("SEQ-001", "nonexistent.com")
        assert not al.remove_path_rule("SEQ-005", "/nonexistent/path")

    def test_empty_allowlist_denies(self, tmp_path: Path) -> None:
        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        assert not al.is_allowed("SEQ-001", domain="anything.com")
        assert not al.is_allowed("SEQ-005", path="/any/path")

    def test_corrupt_json_recovers(self, tmp_path: Path) -> None:
        f = tmp_path / "seq_allowlist.json"
        f.write_text("not valid json{{{", encoding="utf-8")
        al = SequenceAllowlist(allowlist_file=f)
        assert not al.is_allowed("SEQ-001", domain="anything.com")
        assert al.list_entries() == []
