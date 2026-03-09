"""Shared fixtures and markers for CloneGuard tests."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from cloneguard.patterns import PatternEngine

# ---------------------------------------------------------------------------
# Environment detection helpers
# ---------------------------------------------------------------------------


def _ollama_available() -> bool:
    """Check if Ollama is running and qwen2.5:7b is pulled."""
    if not shutil.which("ollama"):
        return False
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "qwen2.5" in result.stdout
    except Exception:
        return False


def _docker_available() -> bool:
    """Check if Docker daemon is running."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Marker registration + auto-skip
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "ollama: requires Ollama with qwen2.5:7b")
    config.addinivalue_line("markers", "docker: requires Docker daemon")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    ollama_ok = _ollama_available()
    docker_ok = _docker_available()

    skip_ollama = pytest.mark.skip(reason="Ollama not available or qwen2.5:7b not pulled")
    skip_docker = pytest.mark.skip(reason="Docker not available")

    for item in items:
        if "ollama" in item.keywords and not ollama_ok:
            item.add_marker(skip_ollama)
        if "docker" in item.keywords and not docker_ok:
            item.add_marker(skip_docker)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine() -> PatternEngine:
    """Create a PatternEngine loaded with all default rules."""
    return PatternEngine()
