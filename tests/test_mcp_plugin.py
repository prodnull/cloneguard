"""Tests for CloneGuard MCP Gateway backward-compatible shim.

The original mcp_plugin.py has been refactored into cloneguard.adapters.mcp.
The mcp_plugin.py module is now a thin shim that re-exports from adapters.mcp
with a DeprecationWarning. These tests verify the backward-compatible shim.

Full MCP adapter tests are in test_mcp_adapter.py.
"""

from __future__ import annotations

import importlib
import sys
import warnings
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_mcp_plugin_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove cached mcp_plugin module to force fresh import each test."""
    mod_key = "cloneguard.mcp_plugin"
    if mod_key in sys.modules:
        monkeypatch.delitem(sys.modules, mod_key)


def _import_plugin() -> Any:
    """Import the mcp_plugin shim module, suppressing DeprecationWarning."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return importlib.import_module("cloneguard.mcp_plugin")


# ---------------------------------------------------------------------------
# Tests: Backward-compatible shim behavior
# ---------------------------------------------------------------------------


class TestShimImport:
    def test_shim_importable(self) -> None:
        """mcp_plugin module can still be imported."""
        mod = _import_plugin()
        assert mod is not None

    def test_shim_exports_cloneguard_plugin(self) -> None:
        """CloneGuardPlugin is accessible from mcp_plugin."""
        mod = _import_plugin()
        assert hasattr(mod, "CloneGuardPlugin")

    def test_shim_exports_mcp_adapter(self) -> None:
        """MCPAdapter is accessible from mcp_plugin."""
        mod = _import_plugin()
        assert hasattr(mod, "MCPAdapter")

    def test_shim_emits_deprecation_warning(self) -> None:
        """Importing mcp_plugin emits DeprecationWarning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            importlib.import_module("cloneguard.mcp_plugin")

        deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
        assert len(deprecation_warnings) >= 1
        assert "deprecated" in str(deprecation_warnings[0].message).lower()

    def test_cloneguard_plugin_is_mcp_plugin_class(self) -> None:
        """CloneGuardPlugin from shim is the CloneGuardMCPPlugin from adapters.mcp."""
        from cloneguard.adapters.mcp import CloneGuardMCPPlugin

        mod = _import_plugin()
        assert mod.CloneGuardPlugin is CloneGuardMCPPlugin


class TestShimFunctionality:
    """Verify the re-exported classes still work via the shim."""

    def test_mcp_adapter_normalize(self) -> None:
        """MCPAdapter imported via shim can normalize MCP requests."""
        mod = _import_plugin()
        adapter = mod.MCPAdapter()
        raw = {
            "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {"data": "hello"}},
        }
        event = adapter.normalize(raw)
        assert event.tool_name == "test_tool"

    def test_cloneguard_plugin_process_request(self) -> None:
        """CloneGuardPlugin imported via shim can process requests."""
        mod = _import_plugin()
        plugin = mod.CloneGuardPlugin()

        from cloneguard.detection.types import DetectionResult

        mock_result = DetectionResult(verdict="clean", confidence=1.0, exit_code=0)

        with patch("cloneguard.adapters.mcp.get_detection_engine") as mock_engine_fn:
            mock_engine = MagicMock()
            mock_engine.scan.return_value = mock_result
            mock_engine_fn.return_value = mock_engine

            result = plugin.process_request(
                server_name="test",
                capability_name="read_file",
                arguments={"path": "/tmp/test"},
            )

        assert result is not None
