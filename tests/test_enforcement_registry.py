"""Tests for PackageRegistryClient -- package hallucination detection.

Verifies:
- Package name extraction from install commands (npm, pip, pip3, yarn)
- Registry existence checks with mocked HTTP responses
- Session caching behavior
- Graceful degradation on network failure
- SignalResult generation for hallucinated packages
"""

from __future__ import annotations

import urllib.error
import urllib.request
from http.client import HTTPResponse
from io import BytesIO
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cloneguard.enforcement.registry import PackageRegistryClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> PackageRegistryClient:
    """Fresh client per test (empty cache)."""
    return PackageRegistryClient()


# ---------------------------------------------------------------------------
# extract_packages tests
# ---------------------------------------------------------------------------


class TestExtractPackages:
    """Test package name extraction from install commands."""

    def test_npm_install_multiple(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("npm install express lodash")
        assert result == [("express", "npm"), ("lodash", "npm")]

    def test_pip_install_multiple(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install requests flask")
        assert result == [("requests", "pypi"), ("flask", "pypi")]

    def test_pip3_install(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip3 install numpy")
        assert result == [("numpy", "pypi")]

    def test_npm_install_skips_flags(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("npm install -D typescript")
        assert result == [("typescript", "npm")]

    def test_pip_install_requirements_file(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install -r requirements.txt")
        assert result == []

    def test_pip_install_local_dir(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install .")
        assert result == []

    def test_pip_install_vcs_url(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install git+https://github.com/user/repo.git")
        assert result == []

    def test_pip_install_strips_version(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install package==1.2.3")
        assert result == [("package", "pypi")]

    def test_pip_install_strips_gte_version(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install flask>=2.0")
        assert result == [("flask", "pypi")]

    def test_pip_install_strips_tilde_version(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install requests~=2.31.0")
        assert result == [("requests", "pypi")]

    def test_npm_ci_returns_empty(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("npm ci")
        assert result == []

    def test_cargo_build_returns_empty(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("cargo build")
        assert result == []

    def test_yarn_add(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("yarn add react react-dom")
        assert result == [("react", "npm"), ("react-dom", "npm")]

    def test_pip_install_long_requirement_flag(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install --requirement requirements.txt")
        assert result == []

    def test_pip_install_editable(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install -e ./mypackage")
        assert result == []

    def test_pip_install_svn_url(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install svn+svn://example.com/repo")
        assert result == []

    def test_empty_command(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("")
        assert result == []

    def test_non_install_command(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("ls -la")
        assert result == []

    def test_npm_install_with_save_dev(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("npm install --save-dev jest")
        assert result == [("jest", "npm")]

    def test_command_with_chained_operators(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install flask && python app.py")
        assert result == [("flask", "pypi")]

    def test_pip_install_absolute_path(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install /path/to/package")
        assert result == []

    def test_pip_install_relative_path(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install ./local-pkg")
        assert result == []

    def test_pip_install_parent_path(self, client: PackageRegistryClient) -> None:
        result = client.extract_packages("pip install ../sibling-pkg")
        assert result == []


# ---------------------------------------------------------------------------
# check_package tests (mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_response(status: int) -> MagicMock:
    """Create a mock urllib response with given status code."""
    resp = MagicMock(spec=HTTPResponse)
    resp.status = status
    resp.read.return_value = b"{}"
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestCheckPackage:
    """Test registry existence checks with mocked HTTP."""

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_existing_package_returns_true(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.return_value = _mock_response(200)
        result = client.check_package("requests", "pypi")
        assert result is True

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_nonexistent_package_returns_false(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://registry.npmjs.org/definitely-not-a-real-pkg-xyz",
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=BytesIO(b""),
        )
        result = client.check_package("definitely-not-a-real-pkg-xyz", "npm")
        assert result is False

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_timeout_returns_none(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.side_effect = TimeoutError("timed out")
        result = client.check_package("some-pkg", "npm")
        assert result is None

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_network_error_returns_none(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        result = client.check_package("some-pkg", "pypi")
        assert result is None

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_session_cache_skips_network(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.return_value = _mock_response(200)
        # First call hits network
        result1 = client.check_package("requests", "pypi")
        assert result1 is True
        assert mock_urlopen.call_count == 1

        # Second call uses cache
        result2 = client.check_package("requests", "pypi")
        assert result2 is True
        assert mock_urlopen.call_count == 1  # Still 1, no new network call


# ---------------------------------------------------------------------------
# check_packages_for_hallucination tests
# ---------------------------------------------------------------------------


class TestCheckPackagesForHallucination:
    """Test the combined extraction + check + SignalResult pipeline."""

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_hallucinated_packages_return_signals(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="",
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=BytesIO(b""),
        )
        signals = client.check_packages_for_hallucination("pip install fake-pkg-xyz")
        assert len(signals) == 1
        assert signals[0].signal_type == "package_hallucination"
        assert signals[0].verdict == "detected"
        assert signals[0].confidence == 0.95
        assert signals[0].details["package"] == "fake-pkg-xyz"
        assert signals[0].details["registry"] == "pypi"

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_all_real_packages_return_empty(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.return_value = _mock_response(200)
        signals = client.check_packages_for_hallucination("pip install requests flask")
        assert signals == []

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_network_failure_returns_empty(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        signals = client.check_packages_for_hallucination("pip install some-pkg")
        assert signals == []

    @patch("cloneguard.enforcement.registry.urllib.request.urlopen")
    def test_mixed_real_and_fake_packages(
        self, mock_urlopen: MagicMock, client: PackageRegistryClient
    ) -> None:
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
            return _mock_response(200)

        mock_urlopen.side_effect = side_effect
        signals = client.check_packages_for_hallucination("pip install requests flask fake-pkg")
        assert len(signals) == 1
        assert signals[0].details["package"] == "fake-pkg"

    def test_non_install_command_returns_empty(self, client: PackageRegistryClient) -> None:
        signals = client.check_packages_for_hallucination("ls -la")
        assert signals == []
