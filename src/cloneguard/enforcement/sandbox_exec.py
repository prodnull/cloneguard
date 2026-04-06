"""cloneguard-sandbox-exec: wrapper binary that applies OS sandbox before exec.

Usage:
    cloneguard-sandbox-exec --spec-file /tmp/cg-enforce-XXXX.json -- bash -c "npm install"
    cloneguard-sandbox-exec --policy <base64-json> -- bash -c "npm install"

Architecture: The hook handler writes a constraint spec (JSON) to a temp file.
This wrapper reads the spec, selects the correct OS adapter (Landlock/Seatbelt),
applies restrictions to its OWN process via apply_restrictions(), deletes the
spec file, then exec's the target command. Since exec preserves Landlock and
Seatbelt restrictions, the target command inherits the sandbox.

Key design decisions:
- --spec-file preferred over --policy for production (avoids leaking in ps)
- Spec file deleted after read (prevents stale enforcement on retry, T-02-14)
- Any failure in constraint loading/applying logs warning and falls through
  to exec without restrictions (fail-open, matching NoopAdapter behavior)
- This is a standalone entry point registered in pyproject.toml [project.scripts]

The hook handler process NEVER calls apply_restrictions() -- it only writes
spec files. This wrapper is the ONLY process that applies OS-level sandbox.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import tempfile
from typing import Any

from cloneguard.enforcement.adapter import get_sandbox_adapter

logger = logging.getLogger(__name__)


def _parse_args(argv: list[str]) -> tuple[str | None, str | None, list[str]]:
    """Parse sandbox-exec arguments.

    Returns (spec_file_path, policy_base64, target_cmd).
    """
    spec_file: str | None = None
    policy: str | None = None
    target_cmd: list[str] = []

    i = 1  # skip argv[0]
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            target_cmd = argv[i + 1 :]
            break
        elif arg == "--spec-file" and i + 1 < len(argv):
            spec_file = argv[i + 1]
            i += 2
            continue
        elif arg == "--policy" and i + 1 < len(argv):
            policy = argv[i + 1]
            i += 2
            continue
        i += 1

    return spec_file, policy, target_cmd


def _load_constraints_from_file(spec_file: str) -> dict[str, Any] | None:
    """Read and parse constraints JSON from a spec file.

    Deletes the spec file after reading (one-shot enforcement, T-02-14).
    Returns None if file doesn't exist or contains invalid JSON.
    """
    try:
        with open(spec_file) as f:
            data: dict[str, Any] = json.load(f)
    except (OSError, json.JSONDecodeError):
        logger.warning("sandbox-exec: failed to read spec file %s", spec_file)
        return None
    finally:
        # Always attempt cleanup, even if read failed
        try:
            os.unlink(spec_file)
        except OSError:
            pass
    return data


def _load_constraints_from_policy(policy_b64: str) -> dict[str, Any] | None:
    """Decode and parse base64-encoded JSON constraints.

    Returns None if decoding or parsing fails.
    """
    try:
        decoded = base64.b64decode(policy_b64)
        data: dict[str, Any] = json.loads(decoded)
        return data
    except Exception:
        logger.warning("sandbox-exec: failed to decode --policy argument")
        return None


def _apply_constraints(constraints: dict[str, Any]) -> None:
    """Select adapter and apply constraints to current process."""
    adapter_name = constraints.get("adapter", "auto")
    writable = constraints.get("writable", [])
    readable = constraints.get("readable", [])
    network_allow = constraints.get("network_allow", [])

    adapter = get_sandbox_adapter(preferred=adapter_name)
    adapter.restrict_filesystem(writable=writable, readable=readable)
    adapter.restrict_network(allow=network_allow)
    adapter.apply_restrictions()


def main() -> None:
    """Entry point for cloneguard-sandbox-exec.

    1. Parse args: --spec-file <path> or --policy <base64>, then -- <target>
    2. Load constraint spec
    3. Apply OS sandbox restrictions to this process
    4. Delete spec file (if used)
    5. exec target command (inherits sandbox restrictions)
    """
    spec_file, policy, target_cmd = _parse_args(sys.argv)

    if not target_cmd:
        logger.error("sandbox-exec: no target command specified after --")
        sys.exit(1)

    # Load constraints from either source
    constraints: dict[str, Any] | None = None
    if spec_file:
        constraints = _load_constraints_from_file(spec_file)
    elif policy:
        constraints = _load_constraints_from_policy(policy)

    # Apply constraints if we have them
    if constraints is not None:
        try:
            _apply_constraints(constraints)
        except Exception:
            logger.warning(
                "sandbox-exec: failed to apply constraints, running unrestricted",
                exc_info=True,
            )

    # exec the target command -- replaces this process
    os.execvp(target_cmd[0], target_cmd)


def write_constraint_spec(constraints: dict[str, Any]) -> str:
    """Write serialized constraints to a temp file. Returns the file path.

    The spec file is used by cloneguard-sandbox-exec --spec-file.
    Caller is responsible for ensuring the spec file path reaches the
    sandbox-exec invocation (via environment variable or command prefix).

    File is created with mkstemp (unique name, 0600 permissions) per T-02-14.
    """
    fd, path = tempfile.mkstemp(prefix="cg-enforce-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(constraints, f)
    return path
