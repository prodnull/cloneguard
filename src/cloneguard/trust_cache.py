"""Trust Cache — SHA-256 file hashes for scan result caching.

Files that have been scanned and found clean are cached by content hash.
On subsequent scans, if the file hash matches the cached entry, the scan
is skipped. This amortizes Tier 2 cost across sessions.

Cache location: ~/.cloneguard/trust-cache.json
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_CACHE_DIR = Path.home() / ".cloneguard"


def _scanner_version() -> str:
    """Return a composite version string for cache invalidation on upgrades."""
    from cloneguard import __version__

    return __version__


def _sha256(content: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(content).hexdigest()


def _file_hash(path: Path) -> str | None:
    """Compute SHA-256 of a file, or None if unreadable."""
    try:
        return _sha256(path.read_bytes())
    except OSError:
        return None


@dataclass
class TrustEntry:
    file_hash: str
    scanned_at: float  # epoch timestamp
    tier2_clean: bool  # whether Tier 2 also cleared this file
    scanner_version: str = ""  # CloneGuard version when entry was created


class TrustCache:
    """SHA-256 hash-based trust cache for scan results."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = cache_dir or _CACHE_DIR
        self._cache_file = self._cache_dir / "trust-cache.json"
        self._entries: dict[str, TrustEntry] = {}
        self._loaded = False

    def _ensure_dir(self) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def _load_cache(self) -> None:
        """Load the trust cache entries from disk."""
        if self._loaded:
            return
        self._loaded = True

        if not self._cache_file.exists():
            return

        try:
            current_ver = _scanner_version()
            data = json.loads(self._cache_file.read_text(encoding="utf-8"))
            for path, entry_data in data.items():
                entry_ver = entry_data.get("scanner_version", "")
                if entry_ver != current_ver:
                    # Stale entry from older scanner version — discard
                    continue
                self._entries[path] = TrustEntry(
                    file_hash=entry_data["file_hash"],
                    scanned_at=entry_data.get("scanned_at", 0),
                    tier2_clean=entry_data.get("tier2_clean", False),
                    scanner_version=entry_ver,
                )
        except (json.JSONDecodeError, KeyError, OSError) as e:
            logger.warning("Corrupt trust cache — resetting: %s", e)
            self._entries = {}

    def _save_cache(self) -> None:
        """Persist cache entries to disk."""
        self._ensure_dir()
        data = {}
        for path, entry in self._entries.items():
            data[path] = {
                "file_hash": entry.file_hash,
                "scanned_at": entry.scanned_at,
                "tier2_clean": entry.tier2_clean,
                "scanner_version": entry.scanner_version,
            }
        self._cache_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def is_trusted(self, repo_path: Path, rel_path: str, require_tier2: bool = False) -> bool:
        """Check if a file is trusted (current hash matches cached entry)."""
        self._load_cache()

        cache_key = f"{repo_path}:{rel_path}"
        entry = self._entries.get(cache_key)
        if entry is None:
            return False

        if require_tier2 and not entry.tier2_clean:
            return False

        file_path = repo_path / rel_path
        current_hash = _file_hash(file_path)
        return current_hash is not None and current_hash == entry.file_hash

    def mark_trusted(
        self,
        repo_path: Path,
        rel_path: str,
        tier2_clean: bool = False,
    ) -> None:
        """Mark a file as trusted after successful scan."""
        self._load_cache()

        file_path = repo_path / rel_path
        current_hash = _file_hash(file_path)
        if current_hash is None:
            return

        cache_key = f"{repo_path}:{rel_path}"
        self._entries[cache_key] = TrustEntry(
            file_hash=current_hash,
            scanned_at=time.time(),
            tier2_clean=tier2_clean,
            scanner_version=_scanner_version(),
        )
        self._save_cache()

    def invalidate(self, repo_path: Path, rel_path: str) -> None:
        """Remove a file from the trust cache."""
        self._load_cache()
        cache_key = f"{repo_path}:{rel_path}"
        self._entries.pop(cache_key, None)
        self._save_cache()

    def clear(self) -> None:
        """Clear all trust cache entries."""
        self._entries = {}
        if self._cache_file.exists():
            self._cache_file.unlink()
