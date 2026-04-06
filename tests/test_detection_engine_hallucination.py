"""Integration tests for package hallucination detection via DetectionEngine.

Verifies that DetectionEngine.scan_pre_tool_use correctly integrates
PackageRegistryClient to detect hallucinated packages in install commands.
"""

from __future__ import annotations

import urllib.error
from io import BytesIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cloneguard.detection.engine import DetectionEngine

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> DetectionEngine:
    """Fresh DetectionEngine per test."""
    return DetectionEngine()


def _make_pre_tool_data(command: str) -> dict[str, Any]:
    """Create a PreToolUse data dict for a Bash command."""
    return {
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


# ---------------------------------------------------------------------------
# Helper to mock registry responses
# ---------------------------------------------------------------------------


def _mock_response_200() -> MagicMock:
    """Mock a successful 200 HTTP response."""
    resp = MagicMock()
    resp.status = 200
    resp.read.return_value = b"{}"
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestDetectionEngineHallucination:
    """Test hallucination detection integrated into scan_pre_tool_use."""

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_hallucinated_package_blocked(
        self, mock_urlopen: MagicMock, engine: DetectionEngine
    ) -> None:
        """pip install of a 404 package should return detected with exit_code=2."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="",
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=BytesIO(b""),
        )
        data = _make_pre_tool_data("pip install definitely-fake-pkg-xyz")
        result = engine.scan_pre_tool_use(data)
        assert result.verdict == "detected"
        assert result.exit_code == 2
        assert "definitely-fake-pkg-xyz" in result.message
        assert any(s.signal_type == "package_hallucination" for s in result.signals)

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_real_package_allowed(self, mock_urlopen: MagicMock, engine: DetectionEngine) -> None:
        """npm install of a 200 package should not trigger hallucination detection."""
        mock_urlopen.return_value = _mock_response_200()
        data = _make_pre_tool_data("npm install express")
        result = engine.scan_pre_tool_use(data)
        # Should get the normal build command warning, not a hallucination block
        assert result.exit_code == 0
        assert not any(s.signal_type == "package_hallucination" for s in result.signals)

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_mixed_real_and_fake_detected(
        self, mock_urlopen: MagicMock, engine: DetectionEngine
    ) -> None:
        """Install with some real and some fake packages should detect the fake one."""

        def side_effect(req: Any, *, timeout: int = 3) -> MagicMock:
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "fake-pkg" in url:
                raise urllib.error.HTTPError(
                    url=url,
                    code=404,
                    msg="Not Found",
                    hdrs=None,  # type: ignore[arg-type]
                    fp=BytesIO(b""),
                )
            return _mock_response_200()

        mock_urlopen.side_effect = side_effect
        data = _make_pre_tool_data("pip install requests flask fake-pkg")
        result = engine.scan_pre_tool_use(data)
        assert result.verdict == "detected"
        assert result.exit_code == 2
        assert "fake-pkg" in result.message

    def test_non_install_command_skips_check(self, engine: DetectionEngine) -> None:
        """A non-install Bash command should not trigger hallucination checks."""
        data = _make_pre_tool_data("ls -la")
        result = engine.scan_pre_tool_use(data)
        assert result.exit_code == 0
        assert not any(s.signal_type == "package_hallucination" for s in result.signals)

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_network_error_allows_gracefully(
        self, mock_urlopen: MagicMock, engine: DetectionEngine
    ) -> None:
        """Network errors should degrade gracefully -- never block on failure."""
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        data = _make_pre_tool_data("pip install some-pkg")
        result = engine.scan_pre_tool_use(data)
        # Should not block -- network error means skip check
        assert result.exit_code == 0
        assert not any(s.signal_type == "package_hallucination" for s in result.signals)

    def test_write_tool_unaffected(self, engine: DetectionEngine) -> None:
        """Write tool should not trigger hallucination checks (only Bash)."""
        data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.txt", "content": "hello"},
        }
        result = engine.scan_pre_tool_use(data)
        assert result.exit_code == 0
        assert not any(s.signal_type == "package_hallucination" for s in result.signals)
