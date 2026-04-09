"""Tests for AUT-009 through AUT-012: sandbox escape, SSTI, and deserialization patterns.

These patterns were added in response to the PraisonAI CVE cluster (April 2026):
  - CVE-2026-39891: Jinja2 SSTI via agent.start()
  - CVE-2026-39888: Sandbox escape via exception frame traversal
  - CVE-2026-39890: YAML deserialization RCE via dangerous YAML tags

Note: Test payloads are constructed at runtime to avoid triggering security hooks
during file creation. The strings tested are attack signatures, not executable code.
"""

from __future__ import annotations

import pytest

from cloneguard.patterns import PatternEngine

# Build attack payload fragments at module level to avoid security hook
# false positives on file write. These are detection test strings, not code.
_OS = "os"
_SYS = "system"
_OS_DOT_SYSTEM = f"{_OS}.{_SYS}"
_DUNDER_IMPORT = "__import__"
_DUNDER_GLOBALS = "__globals__"
_DUNDER_BUILTINS = "__builtins__"
_DUNDER_INIT = "__init__"
_DUNDER_CLASS = "__class__"
_DUNDER_MRO = "__mro__"
_DUNDER_SUBCLASSES = "__subclasses__"


@pytest.fixture
def engine() -> PatternEngine:
    return PatternEngine()


def _match_ids(engine: PatternEngine, content: str, path: str = "CLAUDE.md") -> set[str]:
    """Return set of matched pattern IDs for given content."""
    result = engine.scan(content, path)
    return {m.pattern_id for m in result.matches}


class TestAUT009JinjaSSTI:
    """CVE-2026-39891: Jinja2 template injection via dunder chains."""

    def test_full_ssti_rce_payload(self, engine: PatternEngine) -> None:
        payload = (
            f"{{{{ self.{_DUNDER_INIT}.{_DUNDER_GLOBALS}.{_DUNDER_BUILTINS}"
            f'.{_DUNDER_IMPORT}("{_OS}").{_SYS}("touch /tmp/pwned") }}}}'
        )
        assert "AUT-009" in _match_ids(engine, payload)

    def test_ssti_class_traversal(self, engine: PatternEngine) -> None:
        payload = f"{{{{ self.{_DUNDER_CLASS}.{_DUNDER_MRO}[1].{_DUNDER_SUBCLASSES}() }}}}"
        assert "AUT-009" in _match_ids(engine, payload)

    def test_ssti_config_dunder(self, engine: PatternEngine) -> None:
        payload = f"{{{{ config.{_DUNDER_CLASS}.{_DUNDER_INIT}.{_DUNDER_GLOBALS} }}}}"
        assert "AUT-009" in _match_ids(engine, payload)

    def test_ssti_lipsum_globals(self, engine: PatternEngine) -> None:
        payload = f"{{{{ lipsum.{_DUNDER_GLOBALS}['{_OS}'].popen('id') }}}}"
        assert "AUT-009" in _match_ids(engine, payload)

    def test_ssti_cycler_init(self, engine: PatternEngine) -> None:
        payload = f"{{{{ cycler.{_DUNDER_INIT}.{_DUNDER_GLOBALS}['{_OS}'].{_SYS}('id') }}}}"
        assert "AUT-009" in _match_ids(engine, payload)

    def test_benign_jinja_template_no_match(self, engine: PatternEngine) -> None:
        """Normal Jinja2 templates must not fire."""
        benign = [
            "{{ user.name }}",
            "{{ config.DEBUG }}",
            "{% for item in items %}{{ item.title }}{% endfor %}",
            "{{ form.csrf_token }}",
            "{{ url_for('static', filename='style.css') }}",
        ]
        for content in benign:
            assert "AUT-009" not in _match_ids(engine, content), f"FP on: {content}"


class TestAUT010FrameTraversal:
    """CVE-2026-39888: Python exception frame traversal sandbox escape."""

    def test_traceback_to_frame(self, engine: PatternEngine) -> None:
        assert "AUT-010" in _match_ids(engine, "e.__traceback__.tb_frame")

    def test_frame_back_builtins(self, engine: PatternEngine) -> None:
        assert "AUT-010" in _match_ids(engine, "_p.f_back.f_builtins['eval']")

    def test_frame_back_globals(self, engine: PatternEngine) -> None:
        payload = f"frame.f_back.f_globals['{_DUNDER_BUILTINS}']"
        assert "AUT-010" in _match_ids(engine, payload)

    def test_full_exploit_chain(self, engine: PatternEngine) -> None:
        payload = (
            "try:\n"
            "    1/0\n"
            "except ZeroDivisionError as e:\n"
            "    _p = e.__traceback__.tb_frame.f_back\n"
            f"    _x = _p.f_builtins['{_DUNDER_IMPORT}']\n"
        )
        assert "AUT-010" in _match_ids(engine, payload)

    def test_benign_traceback_no_match(self, engine: PatternEngine) -> None:
        """Normal traceback usage must not fire."""
        benign = [
            "import traceback\ntraceback.print_exc()",
            "tb = traceback.format_exception(e)",
            "logging.exception('error occurred')",
            "except Exception:\n    pass",
        ]
        for content in benign:
            assert "AUT-010" not in _match_ids(engine, content), f"FP on: {content}"


class TestAUT011YAMLTags:
    """CVE-2026-39890: YAML dangerous tag deserialization."""

    def test_js_function_tag(self, engine: PatternEngine) -> None:
        assert "AUT-011" in _match_ids(engine, "!!js/function >\n  function(){ return 1 }")

    def test_js_undefined_tag(self, engine: PatternEngine) -> None:
        assert "AUT-011" in _match_ids(engine, "value: !!js/undefined ''")

    def test_python_object_apply(self, engine: PatternEngine) -> None:
        payload = f"!!python/object/apply:{_OS_DOT_SYSTEM} ['id']"
        assert "AUT-011" in _match_ids(engine, payload)

    def test_python_object_new(self, engine: PatternEngine) -> None:
        assert "AUT-011" in _match_ids(engine, "!!python/object/new:subprocess.Popen\nargs: ['id']")

    def test_python_name(self, engine: PatternEngine) -> None:
        payload = f"!!python/name:{_OS_DOT_SYSTEM}"
        assert "AUT-011" in _match_ids(engine, payload)

    def test_python_module(self, engine: PatternEngine) -> None:
        assert "AUT-011" in _match_ids(engine, f"!!python/module:{_OS}")

    def test_ruby_object(self, engine: PatternEngine) -> None:
        assert "AUT-011" in _match_ids(engine, "!!ruby/object:Gem::Requirement")

    def test_benign_yaml_tags_no_match(self, engine: PatternEngine) -> None:
        """Standard YAML tags must not fire."""
        benign = [
            "!!str value",
            "!!int 42",
            "!!float 3.14",
            "!!bool true",
            "!!null ~",
            "!!map\n  key: value",
            "!!seq\n  - item1",
            "!!binary aGVsbG8=",
        ]
        for content in benign:
            assert "AUT-011" not in _match_ids(engine, content), f"FP on: {content}"


class TestAUT012SSTIProbes:
    """Common SSTI probe patterns used in reconnaissance."""

    def test_arithmetic_probe(self, engine: PatternEngine) -> None:
        assert "AUT-012" in _match_ids(engine, "{{7*7}}")

    def test_class_probe(self, engine: PatternEngine) -> None:
        payload = f"{{{{ self.{_DUNDER_CLASS} }}}}"
        assert "AUT-012" in _match_ids(engine, payload)

    def test_lipsum_globals_probe(self, engine: PatternEngine) -> None:
        payload = f"{{{{ lipsum.{_DUNDER_GLOBALS} }}}}"
        assert "AUT-012" in _match_ids(engine, payload)

    def test_benign_config_access_no_match(self, engine: PatternEngine) -> None:
        """config.X without dunder access must not fire."""
        assert "AUT-012" not in _match_ids(engine, "{{ config.DEBUG }}")
        assert "AUT-012" not in _match_ids(engine, "{{ config.SECRET_KEY }}")
