"""Tests for SeatbeltAdapter -- macOS Seatbelt sandbox enforcement.

Covers:
- SeatbeltAdapter satisfies SandboxAdapter Protocol (isinstance check)
- restrict_filesystem stores writable and readable paths
- restrict_network stores network allow rules
- _generate_profile produces valid SBPL with deny-default baseline
- _generate_profile includes always-allowed paths (T-02-13)
- apply_restrictions invokes sandbox_init_with_parameters via ctypes
- Path escaping for SBPL injection prevention (T-02-15)
- Graceful degradation if libSystem.dylib unavailable
- serialize_constraints returns JSON-serializable dict
"""

from __future__ import annotations

import json
from unittest import mock

from cloneguard.enforcement.adapter import SandboxAdapter


class TestSeatbeltAdapterProtocol:
    """SeatbeltAdapter satisfies SandboxAdapter Protocol."""

    def test_isinstance_check(self) -> None:
        """SeatbeltAdapter must satisfy isinstance(adapter, SandboxAdapter)."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        assert isinstance(adapter, SandboxAdapter)

    def test_name_returns_seatbelt(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        assert adapter.name == "seatbelt"


class TestSeatbeltRestrictFilesystem:
    """restrict_filesystem stores paths for profile generation."""

    def test_stores_writable_paths(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(
            writable=["/Users/dev/project"],
            readable=["/usr/lib"],
        )
        spec = adapter.serialize_constraints()
        assert "/Users/dev/project" in spec["writable"]

    def test_stores_readable_paths(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(
            writable=[],
            readable=["/opt/data"],
        )
        spec = adapter.serialize_constraints()
        assert "/opt/data" in spec["readable"]


class TestSeatbeltRestrictNetwork:
    """restrict_network stores rules for profile generation."""

    def test_stores_network_allow(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_network(allow=["registry.npmjs.org", "pypi.org"])
        spec = adapter.serialize_constraints()
        assert "registry.npmjs.org" in spec["network_allow"]
        assert "pypi.org" in spec["network_allow"]


class TestSeatbeltGenerateProfile:
    """_generate_profile produces valid SBPL string."""

    def test_has_version_header(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        profile = adapter._generate_profile()
        assert "(version 1)" in profile

    def test_has_deny_default_baseline(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        profile = adapter._generate_profile()
        assert "(deny default)" in profile

    def test_includes_always_allowed_temp_paths(self) -> None:
        """T-02-13: Always-allowed temp paths."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        profile = adapter._generate_profile()
        assert "/tmp" in profile
        assert "/private/tmp" in profile
        assert "/private/var/folders" in profile

    def test_includes_writable_as_read_write_rules(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(
            writable=["/Users/dev/project"],
            readable=[],
        )
        profile = adapter._generate_profile()
        assert "file-read*" in profile
        assert "file-write*" in profile
        assert "/Users/dev/project" in profile

    def test_includes_readable_as_read_only_rules(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(
            writable=[],
            readable=["/opt/data"],
        )
        profile = adapter._generate_profile()
        assert "file-read*" in profile
        assert "/opt/data" in profile

    def test_network_allow_produces_network_outbound(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        adapter.restrict_network(allow=["example.com"])
        profile = adapter._generate_profile()
        assert "network-outbound" in profile

    def test_no_network_allow_denies_by_default(self) -> None:
        """Empty network_allow: deny default blocks all network."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=[], readable=[])
        adapter.restrict_network(allow=[])
        profile = adapter._generate_profile()
        # network-outbound should NOT appear when no domains allowed
        # (deny default handles this)
        lines = [line.strip() for line in profile.split("\n")]
        network_lines = [ln for ln in lines if "network-outbound" in ln and "allow" in ln]
        assert len(network_lines) == 0


class TestSeatbeltPathEscaping:
    """T-02-15: Path escaping prevents SBPL injection."""

    def test_escapes_double_quotes(self) -> None:
        from cloneguard.enforcement.seatbelt import _escape_sbpl_path

        result = _escape_sbpl_path('/path/with"quotes')
        # Unescaped double-quote should not appear; only escaped form
        assert result == '/path/with\\"quotes'

    def test_escapes_backslashes(self) -> None:
        from cloneguard.enforcement.seatbelt import _escape_sbpl_path

        result = _escape_sbpl_path("/path/with\\backslash")
        assert "\\\\" in result


class TestSeatbeltApplyRestrictions:
    """apply_restrictions invokes sandbox_init_with_parameters."""

    def test_calls_sandbox_init(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(
            writable=["/Users/dev"],
            readable=["/usr/lib"],
        )

        with mock.patch("cloneguard.enforcement.seatbelt._get_libsystem") as mock_get_lib:
            mock_lib = mock.MagicMock()
            mock_lib.sandbox_init_with_parameters.return_value = 0
            mock_get_lib.return_value = mock_lib
            adapter.apply_restrictions()

        mock_lib.sandbox_init_with_parameters.assert_called_once()

    def test_graceful_degradation_no_libsystem(self) -> None:
        """If libSystem.dylib unavailable, apply_restrictions returns without error."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=["/Users/dev"], readable=[])

        with mock.patch(
            "cloneguard.enforcement.seatbelt._get_libsystem",
            return_value=None,
        ):
            # Should not raise
            adapter.apply_restrictions()

    def test_graceful_degradation_sandbox_init_fails(self) -> None:
        """If sandbox_init returns non-zero, apply_restrictions returns without error."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=["/Users/dev"], readable=[])

        with mock.patch("cloneguard.enforcement.seatbelt._get_libsystem") as mock_get_lib:
            mock_lib = mock.MagicMock()
            mock_lib.sandbox_init_with_parameters.return_value = -1
            mock_get_lib.return_value = mock_lib
            # Should not raise
            adapter.apply_restrictions()


class TestSeatbeltSerializeConstraints:
    """serialize_constraints returns JSON-serializable dict."""

    def test_returns_dict_with_adapter_name(self) -> None:
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=["/Users"], readable=["/usr"])
        spec = adapter.serialize_constraints()
        assert spec["adapter"] == "seatbelt"

    def test_serializable_round_trip(self) -> None:
        """The output must be JSON-serializable (for cross-process transport)."""
        from cloneguard.enforcement.seatbelt import SeatbeltAdapter

        adapter = SeatbeltAdapter()
        adapter.restrict_filesystem(writable=["/Users"], readable=["/usr"])
        adapter.restrict_network(allow=["example.com"])
        spec = adapter.serialize_constraints()
        json_str = json.dumps(spec)
        loaded = json.loads(json_str)
        assert loaded["adapter"] == "seatbelt"
        assert "/Users" in loaded["writable"]
        assert "example.com" in loaded["network_allow"]
