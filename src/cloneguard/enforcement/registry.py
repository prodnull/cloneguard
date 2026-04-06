"""Package hallucination detection via registry API checks (D-15, D-16, D-17).

Extracts package names from install commands (npm install, pip install) and
cross-references against registry APIs (registry.npmjs.org, pypi.org) to detect
hallucinated package names. Returns SignalResult objects that feed into the
standard detection pipeline.

Network failures always degrade gracefully -- skip check, log warning,
never block the agent (D-17).

Threat model T-02-18: Hard 3-second timeout on all urllib.request calls.
Threat model T-02-19: Regex extraction may miss crafted commands; this is
  detection-only, false negatives are acceptable.
Threat model T-02-20: Package names sent to public registries are themselves
  public (inherent to the install command).
"""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request

from cloneguard.detection.types import SignalResult

logger = logging.getLogger(__name__)

# Registry URL templates: package name inserted via .format()
_REGISTRY_URLS: dict[str, str] = {
    "npm": "https://registry.npmjs.org/{package}",
    "pypi": "https://pypi.org/pypi/{package}/json",
}

_TIMEOUT = 3  # seconds (D-17: never block agent on slow network)

# ---------------------------------------------------------------------------
# Package extraction regexes
# ---------------------------------------------------------------------------
# Match the install keyword and capture everything after it until a shell
# operator (;, &, |, &&, ||) or end of string.
_NPM_INSTALL_RE = re.compile(r"\bnpm\s+install\s+(.+?)(?:\s*[;&|]|$)")
_PIP_INSTALL_RE = re.compile(r"\b(?:pip3?)\s+install\s+(.+?)(?:\s*[;&|]|$)")
_YARN_ADD_RE = re.compile(r"\byarn\s+add\s+(.+?)(?:\s*[;&|]|$)")

# Version specifier separators: ==, >=, <=, ~=, !=, >, <
_VERSION_SPLIT_RE = re.compile(r"[><=!~]+")

# Flags that consume a following argument (the argument is NOT a package name)
_FLAGS_WITH_ARG = frozenset({"-r", "--requirement", "-c", "--constraint", "-e", "--editable",
                              "-f", "--find-links", "-i", "--index-url",
                              "--extra-index-url", "--no-index", "-t", "--target"})


def _is_flag(token: str) -> bool:
    """Check if token is a CLI flag (starts with -)."""
    return token.startswith("-")


def _is_path_or_url(token: str) -> bool:
    """Check if token looks like a local path or VCS URL, not a package name."""
    if token in (".", ".."):
        return True
    if token.startswith(("./", "../", "/", "~/")):
        return True
    # VCS installs: git+, svn+, hg+, bzr+
    if re.match(r"^(git|svn|hg|bzr)\+", token):
        return True
    return False


def _strip_version(token: str) -> str:
    """Strip version specifiers from a package name token (e.g., 'flask>=2.0' -> 'flask')."""
    return _VERSION_SPLIT_RE.split(token, maxsplit=1)[0]


class PackageRegistryClient:
    """Checks package names against npm/PyPI registries to detect hallucinations.

    Session-cached: each (package, registry) pair is checked at most once per
    process lifetime. Network failures return None (skip check, never block).
    """

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], bool | None] = {}

    def extract_packages(self, command: str) -> list[tuple[str, str]]:
        """Extract (package_name, registry) pairs from an install command.

        Handles npm install, pip install, pip3 install, yarn add.
        Skips flags, file installs (-r), local installs (.), VCS URLs (git+).
        Strips version specifiers (==, >=, ~=, etc.).
        Returns empty list for non-install commands.
        """
        packages: list[tuple[str, str]] = []

        # Try each pattern
        for pattern, registry in [
            (_NPM_INSTALL_RE, "npm"),
            (_PIP_INSTALL_RE, "pypi"),
            (_YARN_ADD_RE, "npm"),
        ]:
            match = pattern.search(command)
            if match:
                args_str = match.group(1)
                tokens = args_str.split()
                skip_next = False

                for token in tokens:
                    if skip_next:
                        skip_next = False
                        continue

                    # Check if this flag consumes the next argument
                    if token.lower() in _FLAGS_WITH_ARG:
                        skip_next = True
                        continue

                    # Skip flags
                    if _is_flag(token):
                        continue

                    # Skip paths and VCS URLs
                    if _is_path_or_url(token):
                        continue

                    # Strip version specifier and add
                    name = _strip_version(token)
                    if name:
                        packages.append((name, registry))

        return packages

    def check_package(self, package: str, registry: str) -> bool | None:
        """Check if package exists in registry.

        Returns:
            True  -- package exists (200 response)
            False -- package not found (404 response, likely hallucinated)
            None  -- network error or timeout (skip check gracefully)
        """
        cache_key = (package, registry)
        if cache_key in self._cache:
            return self._cache[cache_key]

        url_template = _REGISTRY_URLS.get(registry)
        if url_template is None:
            logger.warning("Unknown registry %r for package %r", registry, package)
            return None

        url = url_template.format(package=package)
        req = urllib.request.Request(url, headers={"Accept": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT):
                # Any 2xx is treated as "exists"
                result: bool | None = True
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                result = False
            else:
                logger.warning(
                    "Registry check for %s/%s returned HTTP %d",
                    registry, package, exc.code,
                )
                result = None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.warning(
                "Network error checking %s/%s: %s", registry, package, exc,
            )
            result = None

        self._cache[cache_key] = result
        return result

    def check_packages_for_hallucination(
        self, command: str,
    ) -> list[SignalResult]:
        """Extract packages from command and check registries.

        Returns SignalResult for each hallucinated (404) package. Network
        failures are silently skipped -- never block on network error (D-17).
        """
        packages = self.extract_packages(command)
        if not packages:
            return []

        signals: list[SignalResult] = []
        for name, registry in packages:
            exists = self.check_package(name, registry)
            if exists is False:
                signals.append(
                    SignalResult(
                        signal_type="package_hallucination",
                        verdict="detected",
                        confidence=0.95,
                        details={
                            "package": name,
                            "registry": registry,
                            "reason": f"Package not found in {registry} registry",
                        },
                    )
                )
            elif exists is None:
                logger.debug(
                    "Skipping hallucination check for %s/%s (network error)", registry, name,
                )

        return signals
