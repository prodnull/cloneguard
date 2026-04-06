"""Tests for cloneguard-sandbox-exec wrapper entry point.

Covers:
- main() with --policy deserializes base64-encoded JSON constraints
- main() with --policy selects correct adapter based on "adapter" field
- main() calls restrict_filesystem, restrict_network, apply_restrictions
- main() execs target command (everything after --)
- main() with missing --policy runs target without restrictions (passthrough)
- main() with --spec-file reads constraints from temp file
- main() with invalid constraints JSON degrades gracefully (passthrough)
- main() cleans up spec file after reading (one-shot enforcement)
- write_constraint_spec() creates temp file with serialized constraints
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from unittest import mock


class TestSandboxExecMainSpecFile:
    """main() with --spec-file reads constraints from a temp file."""

    def test_reads_constraints_from_spec_file(self) -> None:
        """main() deserializes constraints from --spec-file path."""
        from cloneguard.enforcement.sandbox_exec import main

        constraints = {
            "adapter": "noop",
            "writable": ["/home/user"],
            "readable": ["/usr/lib"],
            "network_allow": [],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="cg-enforce-"
        ) as f:
            json.dump(constraints, f)
            spec_path = f.name

        try:
            with (
                mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp"),
                mock.patch(
                    "cloneguard.enforcement.sandbox_exec.get_sandbox_adapter"
                ) as mock_get_adapter,
                mock.patch("sys.argv", ["sandbox-exec", "--spec-file", spec_path, "--", "bash"]),
            ):
                mock_adapter = mock.MagicMock()
                mock_get_adapter.return_value = mock_adapter
                main()

            mock_get_adapter.assert_called_once_with(preferred="noop")
            mock_adapter.restrict_filesystem.assert_called_once_with(
                writable=["/home/user"],
                readable=["/usr/lib"],
            )
            mock_adapter.restrict_network.assert_called_once_with(allow=[])
            mock_adapter.apply_restrictions.assert_called_once()
        finally:
            # Spec file should already be cleaned up by main()
            if os.path.exists(spec_path):
                os.unlink(spec_path)

    def test_selects_adapter_by_name(self) -> None:
        """main() selects adapter based on 'adapter' field in constraints."""
        from cloneguard.enforcement.sandbox_exec import main

        constraints = {
            "adapter": "landlock",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="cg-enforce-"
        ) as f:
            json.dump(constraints, f)
            spec_path = f.name

        try:
            with (
                mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp"),
                mock.patch(
                    "cloneguard.enforcement.sandbox_exec.get_sandbox_adapter"
                ) as mock_get_adapter,
                mock.patch("sys.argv", ["sandbox-exec", "--spec-file", spec_path, "--", "ls"]),
            ):
                mock_adapter = mock.MagicMock()
                mock_get_adapter.return_value = mock_adapter
                main()

            mock_get_adapter.assert_called_once_with(preferred="landlock")
        finally:
            if os.path.exists(spec_path):
                os.unlink(spec_path)

    def test_cleans_up_spec_file(self) -> None:
        """main() deletes the spec file after reading (one-shot enforcement)."""
        from cloneguard.enforcement.sandbox_exec import main

        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="cg-enforce-"
        ) as f:
            json.dump(constraints, f)
            spec_path = f.name

        with (
            mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp"),
            mock.patch("cloneguard.enforcement.sandbox_exec.get_sandbox_adapter") as mock_get,
            mock.patch("sys.argv", ["sandbox-exec", "--spec-file", spec_path, "--", "true"]),
        ):
            mock_get.return_value = mock.MagicMock()
            main()

        assert not os.path.exists(spec_path), "Spec file should be deleted after reading"


class TestSandboxExecMainPolicy:
    """main() with --policy flag deserializes base64-encoded JSON."""

    def test_deserializes_base64_policy(self) -> None:
        from cloneguard.enforcement.sandbox_exec import main

        constraints = {
            "adapter": "seatbelt",
            "writable": ["/Users/dev"],
            "readable": ["/usr"],
            "network_allow": ["example.com"],
        }
        encoded = base64.b64encode(json.dumps(constraints).encode()).decode()

        with (
            mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp"),
            mock.patch(
                "cloneguard.enforcement.sandbox_exec.get_sandbox_adapter"
            ) as mock_get_adapter,
            mock.patch("sys.argv", ["sandbox-exec", "--policy", encoded, "--", "npm", "install"]),
        ):
            mock_adapter = mock.MagicMock()
            mock_get_adapter.return_value = mock_adapter
            main()

        mock_get_adapter.assert_called_once_with(preferred="seatbelt")
        mock_adapter.restrict_filesystem.assert_called_once_with(
            writable=["/Users/dev"],
            readable=["/usr"],
        )
        mock_adapter.restrict_network.assert_called_once_with(allow=["example.com"])
        mock_adapter.apply_restrictions.assert_called_once()


class TestSandboxExecExec:
    """main() execs the target command after applying restrictions."""

    def test_execs_target_command(self) -> None:
        """Everything after -- is exec'd."""
        from cloneguard.enforcement.sandbox_exec import main

        constraints = {
            "adapter": "noop",
            "writable": [],
            "readable": [],
            "network_allow": [],
        }
        encoded = base64.b64encode(json.dumps(constraints).encode()).decode()

        with (
            mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp") as mock_exec,
            mock.patch("cloneguard.enforcement.sandbox_exec.get_sandbox_adapter") as mock_get,
            mock.patch(
                "sys.argv",
                ["sandbox-exec", "--policy", encoded, "--", "bash", "-c", "echo hello"],
            ),
        ):
            mock_get.return_value = mock.MagicMock()
            main()

        mock_exec.assert_called_once_with("bash", ["bash", "-c", "echo hello"])


class TestSandboxExecPassthrough:
    """main() with missing constraints runs target without restrictions."""

    def test_no_policy_passthrough(self) -> None:
        """Missing --policy and --spec-file: run target without restrictions."""
        from cloneguard.enforcement.sandbox_exec import main

        with (
            mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp") as mock_exec,
            mock.patch("sys.argv", ["sandbox-exec", "--", "ls", "-la"]),
        ):
            main()

        mock_exec.assert_called_once_with("ls", ["ls", "-la"])


class TestSandboxExecGracefulDegradation:
    """main() degrades gracefully on errors."""

    def test_invalid_json_passthrough(self) -> None:
        """Invalid base64/JSON in --policy: run target without restrictions."""
        from cloneguard.enforcement.sandbox_exec import main

        with (
            mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp") as mock_exec,
            mock.patch("sys.argv", ["sandbox-exec", "--policy", "not-valid-base64!", "--", "ls"]),
        ):
            main()

        mock_exec.assert_called_once_with("ls", ["ls"])

    def test_missing_spec_file_passthrough(self) -> None:
        """Missing --spec-file path: run target without restrictions."""
        from cloneguard.enforcement.sandbox_exec import main

        with (
            mock.patch("cloneguard.enforcement.sandbox_exec.os.execvp") as mock_exec,
            mock.patch(
                "sys.argv",
                ["sandbox-exec", "--spec-file", "/nonexistent/path.json", "--", "ls"],
            ),
        ):
            main()

        mock_exec.assert_called_once_with("ls", ["ls"])


class TestWriteConstraintSpec:
    """write_constraint_spec creates temp file with serialized constraints."""

    def test_creates_temp_file(self) -> None:
        from cloneguard.enforcement.sandbox_exec import write_constraint_spec

        constraints = {
            "adapter": "landlock",
            "writable": ["/home"],
            "readable": ["/usr"],
            "network_allow": [],
        }
        path = write_constraint_spec(constraints)
        try:
            assert os.path.exists(path)
            assert path.startswith(tempfile.gettempdir()) or "/tmp" in path
            with open(path) as f:
                loaded = json.load(f)
            assert loaded == constraints
        finally:
            os.unlink(path)

    def test_file_prefix(self) -> None:
        """Temp file uses cg-enforce- prefix for identification."""
        from cloneguard.enforcement.sandbox_exec import write_constraint_spec

        constraints = {"adapter": "noop", "writable": [], "readable": [], "network_allow": []}
        path = write_constraint_spec(constraints)
        try:
            assert "cg-enforce-" in os.path.basename(path)
        finally:
            os.unlink(path)
