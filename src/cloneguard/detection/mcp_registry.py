"""MCP tool description fingerprinting registry (D-17).

Known-good registry of MCP tool descriptions with SHA-256 hash-based
fingerprinting. Flags descriptions that deviate from registered versions
as potential RADE attacks (tool description poisoning).

Registry ships as JSON build artifact in detection/mcp_registry.json.
Not loaded from network -- local package resource only.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_REGISTRY_PATH = Path(__file__).parent / "mcp_registry.json"


class MCPRegistry:
    """Known-good MCP tool description fingerprint registry.

    Compares live tool descriptions against registered SHA-256 hashes
    to detect RADE (Remote Agent Description Edit) attacks.
    """

    def __init__(self, tools: dict[str, dict[str, Any]], version: str) -> None:
        self._tools = tools
        self._version = version

    @property
    def version(self) -> str:
        """Registry schema version."""
        return self._version

    @classmethod
    def load(cls, path: Path | None = None) -> MCPRegistry:
        """Load registry from JSON file.

        Returns empty registry if file is missing or malformed (graceful degradation).
        """
        if path is None:
            path = _DEFAULT_REGISTRY_PATH

        if not path.is_file():
            logger.warning("MCP registry not found at %s; using empty registry", path)
            return cls(tools={}, version="0")

        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load MCP registry from %s: %s", path, exc)
            return cls(tools={}, version="0")

        version = data.get("version", "0")
        tools = data.get("tools", {})
        return cls(tools=tools, version=version)

    def get_registered_tools(self) -> list[str]:
        """Return list of registered tool names."""
        return sorted(self._tools.keys())

    def check_tool_fingerprint(
        self,
        tool_name: str,
        description: str,
        input_schema: str = "",
    ) -> bool | None:
        """Compare tool description against known-good fingerprint.

        Returns:
            True  -- description matches registered fingerprint
            False -- description does NOT match (potential RADE attack)
            None  -- tool not in registry (unknown tool)
        """
        entry = self._tools.get(tool_name)
        if entry is None:
            return None

        desc_hash = hashlib.sha256(description.encode()).hexdigest()

        # Primary check: compare SHA-256 hashes if registry has a non-empty hash
        registered_hash = entry.get("description_hash", "")
        if registered_hash:
            if desc_hash == registered_hash:
                # Optionally also check input_schema_hash
                schema_hash_registered = entry.get("input_schema_hash", "")
                if schema_hash_registered and input_schema:
                    schema_hash = hashlib.sha256(input_schema.encode()).hexdigest()
                    return bool(schema_hash == str(schema_hash_registered))
                return True
            return False

        # Fallback: description length range check when hash is empty (placeholder)
        length_range = entry.get("description_length_range")
        if length_range and len(length_range) == 2:
            min_len, max_len = length_range
            if not (min_len <= len(description) <= max_len):
                return False
            return True

        # No hash and no length range -- cannot verify, treat as unknown
        return None


def check_tool_fingerprint(
    tool_name: str,
    description: str,
    input_schema: str = "",
    registry: MCPRegistry | None = None,
) -> bool | None:
    """Module-level convenience function for fingerprint checking.

    Loads default registry on first call if no registry provided.
    """
    if registry is None:
        registry = MCPRegistry.load()
    return registry.check_tool_fingerprint(tool_name, description, input_schema)
