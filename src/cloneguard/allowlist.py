"""Content-hash allowlist for known false positives.

Stores SHA-256 hashes of file contents that have been reviewed and
acknowledged as false positives. Stored in ~/.cloneguard/allowlist.json
(user-local, outside the repo) so repository content cannot tamper with it.

When the scanner encounters a file whose content hash is in the allowlist,
findings for that file are suppressed.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

_ALLOWLIST_DIR = Path.home() / ".cloneguard"
_ALLOWLIST_FILE = _ALLOWLIST_DIR / "allowlist.json"


def _content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@dataclass
class AllowlistEntry:
    content_hash: str
    path_hint: str  # informational — last path this was added from
    reason: str
    added_at: float  # epoch


class Allowlist:
    """SHA-256 content-hash allowlist for false positive suppression."""

    def __init__(self, allowlist_file: Path | None = None) -> None:
        self._file = allowlist_file or _ALLOWLIST_FILE
        self._entries: dict[str, AllowlistEntry] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._file.exists():
            return
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            for h, entry_data in data.items():
                self._entries[h] = AllowlistEntry(
                    content_hash=h,
                    path_hint=entry_data.get("path_hint", ""),
                    reason=entry_data.get("reason", ""),
                    added_at=entry_data.get("added_at", 0.0),
                )
        except (json.JSONDecodeError, OSError):
            self._entries = {}

    def _save(self) -> None:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for h, entry in self._entries.items():
            d = asdict(entry)
            d.pop("content_hash")  # key is already the hash
            data[h] = d
        self._file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def is_allowed(self, content: bytes) -> bool:
        """Check if file content is in the allowlist."""
        self._load()
        return _content_hash(content) in self._entries

    def add(self, file_path: Path, reason: str = "") -> str:
        """Add a file's current content to the allowlist. Returns the hash."""
        self._load()
        content = file_path.read_bytes()
        h = _content_hash(content)
        self._entries[h] = AllowlistEntry(
            content_hash=h,
            path_hint=str(file_path),
            reason=reason,
            added_at=time.time(),
        )
        self._save()
        return h

    def remove(self, hash_or_path: str) -> bool:
        """Remove by exact hash or by path basename match. Returns True if found."""
        self._load()
        # Direct hash match (full or prefix)
        if hash_or_path in self._entries:
            del self._entries[hash_or_path]
            self._save()
            return True
        # Resolve to absolute path for comparison
        resolved = str(Path(hash_or_path).resolve())
        to_remove = [
            h
            for h, e in self._entries.items()
            if e.path_hint == resolved or Path(e.path_hint).name == hash_or_path
        ]
        if to_remove:
            for h in to_remove:
                del self._entries[h]
            self._save()
            return True
        return False

    def list_entries(self) -> list[AllowlistEntry]:
        """Return all allowlist entries."""
        self._load()
        return list(self._entries.values())
