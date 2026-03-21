"""Sequence allowlist for CaMeL-lite enforcement rules.

Domain-level allowlist for SEQ-001/002 (trusted exfil destinations).
Exact-path (SHA-256) allowlist for SEQ-005 (approved config writes).
Stored in ~/.cloneguard/sequence_allowlist.json (user-local, outside repo).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_FILE = Path.home() / ".cloneguard" / "sequence_allowlist.json"


@dataclass
class SequenceAllowEntry:
    """Single entry in the sequence allowlist."""

    rule_id: str
    match_type: str  # "domain" or "path"
    value: str  # domain name or SHA-256 of normalized path
    raw_value: str  # original value for display
    added_at: float
    reason: str = ""


class SequenceAllowlist:
    """JSON-backed allowlist for CaMeL-lite enforcement escape hatch.

    Two match types:
    - Domain-level (SEQ-001/002): keyed by rule_id + lowercased domain.
    - Exact-path (SEQ-005): keyed by rule_id + SHA-256 of normalized path.
    """

    def __init__(self, allowlist_file: Path | None = None) -> None:
        self._file = allowlist_file or _DEFAULT_FILE
        self._entries: list[SequenceAllowEntry] = []
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._file.exists():
            return
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            for entry_data in data:
                self._entries.append(
                    SequenceAllowEntry(
                        rule_id=entry_data["rule_id"],
                        match_type=entry_data["match_type"],
                        value=entry_data["value"],
                        raw_value=entry_data.get("raw_value", entry_data["value"]),
                        added_at=entry_data.get("added_at", 0.0),
                        reason=entry_data.get("reason", ""),
                    )
                )
        except (json.JSONDecodeError, OSError, KeyError):
            self._entries = []

    def _save(self) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        data = [
            {
                "rule_id": e.rule_id,
                "match_type": e.match_type,
                "value": e.value,
                "raw_value": e.raw_value,
                "added_at": e.added_at,
                "reason": e.reason,
            }
            for e in self._entries
        ]
        self._file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _path_hash(path: str) -> str:
        """SHA-256 of backslash-normalized, lowercased path."""
        normalized = path.replace("\\", "/").lower()
        return hashlib.sha256(normalized.encode()).hexdigest()

    def add_domain_rule(self, rule_id: str, domain: str, reason: str = "") -> None:
        """Allow a domain for a network-exfil sequence rule (SEQ-001/002)."""
        self._load()
        self._entries.append(
            SequenceAllowEntry(
                rule_id=rule_id,
                match_type="domain",
                value=domain.lower(),
                raw_value=domain,
                added_at=time.time(),
                reason=reason,
            )
        )
        self._save()

    def add_path_rule(self, rule_id: str, path: str, reason: str = "") -> None:
        """Allow an exact config path for SEQ-005 (config write escalation)."""
        self._load()
        self._entries.append(
            SequenceAllowEntry(
                rule_id=rule_id,
                match_type="path",
                value=self._path_hash(path),
                raw_value=path,
                added_at=time.time(),
                reason=reason,
            )
        )
        self._save()

    def remove_domain_rule(self, rule_id: str, domain: str) -> bool:
        """Remove a domain allowlist entry. Returns True if an entry was removed."""
        self._load()
        before = len(self._entries)
        self._entries = [
            e
            for e in self._entries
            if not (e.rule_id == rule_id and e.match_type == "domain" and e.value == domain.lower())
        ]
        if len(self._entries) < before:
            self._save()
            return True
        return False

    def remove_path_rule(self, rule_id: str, path: str) -> bool:
        """Remove an exact-path allowlist entry. Returns True if an entry was removed."""
        self._load()
        h = self._path_hash(path)
        before = len(self._entries)
        self._entries = [
            e
            for e in self._entries
            if not (e.rule_id == rule_id and e.match_type == "path" and e.value == h)
        ]
        if len(self._entries) < before:
            self._save()
            return True
        return False

    def is_allowed(
        self, rule_id: str, *, domain: str | None = None, path: str | None = None
    ) -> bool:
        """Check whether a sequence rule firing should be suppressed."""
        self._load()
        for entry in self._entries:
            if entry.rule_id != rule_id:
                continue
            if entry.match_type == "domain" and domain and entry.value == domain.lower():
                return True
            if entry.match_type == "path" and path and entry.value == self._path_hash(path):
                return True
        return False

    def list_entries(self) -> list[SequenceAllowEntry]:
        """Return a copy of all allowlist entries."""
        self._load()
        return list(self._entries)
