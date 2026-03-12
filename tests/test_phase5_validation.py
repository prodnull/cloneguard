"""Phase 5 FPR Tuning -- Nyquist validation gap tests.

Tests covering gaps identified in the Phase 5 validation map:
- FPR-01: _scan_lines() threads mode to classify()
- FPR-01: scanner.py passes ScanMode.STANDARD to classify_files()
- FPR-02: calibrate_thresholds.py script exists and is importable
- FPR-01: classify_files() threads mode to inner classify() and _scan_lines()
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from cloneguard.patterns import ScanMode

# ---------------------------------------------------------------------------
# Gap: _scan_lines() threads mode parameter to classify()
# ---------------------------------------------------------------------------


class TestScanLinesThreadsMode:
    """Verify _scan_lines() forwards mode to inner classify() calls."""

    def test_scan_lines_passes_mode_to_classify(self):
        """_scan_lines(content, mode=LENIENT) must call classify(line, mode=LENIENT)."""
        from cloneguard.mini_semantic import MiniSemanticClassifier

        classifier = MiniSemanticClassifier()
        if not classifier.available:
            pytest.skip("ONNX model not available")

        # Patch classify to record the mode argument
        original_classify = classifier.classify
        recorded_modes: list[ScanMode] = []

        def spy_classify(text, *, mode=ScanMode.STANDARD, _apply_mahalanobis=True):
            recorded_modes.append(mode)
            return original_classify(text, mode=mode, _apply_mahalanobis=_apply_mahalanobis)

        classifier.classify = spy_classify  # type: ignore[assignment]

        content = "This is a normal line of text for testing purposes.\nAnother line here."
        classifier._scan_lines(content, mode=ScanMode.LENIENT)

        # All classify calls from _scan_lines must use LENIENT
        assert len(recorded_modes) > 0, "_scan_lines must call classify at least once"
        for mode in recorded_modes:
            assert mode == ScanMode.LENIENT, (
                f"_scan_lines should thread mode=LENIENT to classify, got {mode}"
            )

    def test_scan_lines_signature_has_mode_parameter(self):
        """_scan_lines must accept a mode keyword argument."""
        from cloneguard.mini_semantic import MiniSemanticClassifier

        sig = inspect.signature(MiniSemanticClassifier._scan_lines)
        mode_param = sig.parameters.get("mode")
        assert mode_param is not None, "_scan_lines() must accept a 'mode' parameter"
        assert mode_param.default == ScanMode.STANDARD


# ---------------------------------------------------------------------------
# Gap: scanner.py threads ScanMode.STANDARD to classify_files()
# ---------------------------------------------------------------------------


class TestScannerThreadsMode:
    """Verify scanner.py _run_tier2() passes mode=ScanMode.STANDARD to classify_files()."""

    def test_run_tier2_passes_standard_mode(self):
        """_run_tier2 must call classify_files with mode=ScanMode.STANDARD.

        Verifies via source inspection that the _run_tier2 method explicitly
        passes mode=ScanMode.STANDARD to classify_files(). This avoids the
        heavyweight mock setup required to run _run_tier2 end-to-end.
        """
        import re

        from cloneguard.scanner import RepoScanner

        source = inspect.getsource(RepoScanner._run_tier2)
        # The source must contain classify_files(..., mode=ScanMode.STANDARD)
        assert re.search(r"classify_files\(.*mode\s*=\s*ScanMode\.STANDARD", source), (
            "_run_tier2 must call classify_files with mode=ScanMode.STANDARD. "
            "Source does not contain expected call pattern."
        )


# ---------------------------------------------------------------------------
# Gap: calibrate_thresholds.py exists and is a valid Python script
# ---------------------------------------------------------------------------


class TestCalibrationScriptExists:
    """Verify calibrate_thresholds.py exists and has required structure."""

    def test_calibration_script_exists(self):
        """scripts/calibrate_thresholds.py must exist."""
        script_path = Path(__file__).parent.parent / "scripts" / "calibrate_thresholds.py"
        assert script_path.exists(), f"Calibration script not found at {script_path}"

    def test_calibration_script_has_verify_flag(self):
        """calibrate_thresholds.py must contain --verify argument handling."""
        script_path = Path(__file__).parent.parent / "scripts" / "calibrate_thresholds.py"
        if not script_path.exists():
            pytest.skip("Calibration script not found")
        content = script_path.read_text()
        assert "--verify" in content, "Calibration script must support --verify flag"

    def test_calibration_script_is_valid_python(self):
        """calibrate_thresholds.py must be valid Python (compile without errors)."""
        script_path = Path(__file__).parent.parent / "scripts" / "calibrate_thresholds.py"
        if not script_path.exists():
            pytest.skip("Calibration script not found")
        source = script_path.read_text()
        # compile() raises SyntaxError if invalid
        compile(source, str(script_path), "exec")


# ---------------------------------------------------------------------------
# Gap: classify_files() threads mode to both classify() and _scan_lines()
# ---------------------------------------------------------------------------


class TestClassifyFilesModePropagation:
    """Verify classify_files() correctly propagates mode to inner calls."""

    def test_classify_files_threads_mode_to_classify_calls(self):
        """classify_files(files, mode=LENIENT) must call classify(content, mode=LENIENT)."""
        from cloneguard.mini_semantic import MiniSemanticClassifier

        classifier = MiniSemanticClassifier()
        if not classifier.available:
            pytest.skip("ONNX model not available")

        original_classify = classifier.classify
        recorded_modes: list[ScanMode] = []

        def spy_classify(text, *, mode=ScanMode.STANDARD, _apply_mahalanobis=True):
            recorded_modes.append(mode)
            return original_classify(text, mode=mode, _apply_mahalanobis=_apply_mahalanobis)

        classifier.classify = spy_classify  # type: ignore[assignment]

        files = [("test.md", "# Normal content\nThis is benign documentation.")]
        classifier.classify_files(files, mode=ScanMode.LENIENT)

        assert len(recorded_modes) > 0, "classify_files must call classify at least once"
        for m in recorded_modes:
            assert m == ScanMode.LENIENT, f"classify_files should thread mode=LENIENT, got {m}"

    def test_classify_files_threads_mode_to_scan_lines(self):
        """classify_files() source must thread mode to _scan_lines() calls.

        Verifies via source inspection that classify_files passes mode to
        _scan_lines. The behavioral spy approach is fragile because classify()
        may return non-SAFE for some benign content, so _scan_lines is never
        reached. Source inspection is a reliable alternative.
        """
        from cloneguard.mini_semantic import MiniSemanticClassifier

        source = inspect.getsource(MiniSemanticClassifier.classify_files)
        assert "self._scan_lines(content, mode=mode)" in source, (
            "classify_files must call _scan_lines with mode=mode parameter"
        )
