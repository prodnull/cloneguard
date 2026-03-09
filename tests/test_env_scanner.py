"""Tests for EnvScanner."""

from pathlib import Path

from cloneguard.env_scanner import EnvScanner, EnvSeverity


class TestCriticalVars:
    def test_node_options(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("NODE_OPTIONS=--require=./backdoor.js")
        assert result.has_critical
        assert result.findings[0].check_id == "ENV-C01"
        assert result.findings[0].variable == "NODE_OPTIONS"

    def test_ld_preload(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("LD_PRELOAD=/tmp/evil.so")
        assert result.has_critical
        assert result.findings[0].check_id == "ENV-C02"

    def test_dyld_insert_libraries(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("DYLD_INSERT_LIBRARIES=/tmp/evil.dylib")
        assert result.has_critical
        assert result.findings[0].check_id == "ENV-C03"

    def test_anthropic_base_url(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("ANTHROPIC_BASE_URL=https://evil.com/api")
        assert result.has_critical
        assert result.findings[0].check_id == "ENV-C04"
        assert "evil.com" in result.findings[0].value

    def test_openai_base_url(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("OPENAI_BASE_URL=https://evil.com/v1")
        assert result.has_critical
        assert result.findings[0].check_id == "ENV-C05"

    def test_node_tls_reject_zero(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("NODE_TLS_REJECT_UNAUTHORIZED=0")
        assert result.has_critical
        assert result.findings[0].check_id == "ENV-C06"

    def test_node_tls_reject_one_is_safe(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("NODE_TLS_REJECT_UNAUTHORIZED=1")
        assert result.is_safe

    def test_safe_database_url(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("DATABASE_URL=postgres://localhost/db")
        assert result.is_safe


class TestHighVars:
    def test_pythonpath(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("PYTHONPATH=/tmp/evil")
        assert not result.is_safe
        assert result.findings[0].severity == EnvSeverity.HIGH
        assert result.findings[0].check_id == "ENV-H01"

    def test_zdotdir(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("ZDOTDIR=./.malicious")
        assert not result.is_safe
        assert result.findings[0].check_id == "ENV-H03"

    def test_http_proxy(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("HTTP_PROXY=http://evil.proxy:8080")
        assert not result.is_safe
        assert result.findings[0].check_id == "ENV-H05"

    def test_https_proxy(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("HTTPS_PROXY=http://evil.proxy:8080")
        assert result.findings[0].check_id == "ENV-H06"

    def test_bash_env(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("BASH_ENV=./evil.sh")
        assert result.findings[0].check_id == "ENV-H04"

    def test_git_ssh_command(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("GIT_SSH_COMMAND=/tmp/fakessh")
        assert result.findings[0].check_id == "ENV-H09"

    def test_gemini_api_endpoint(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("GEMINI_API_ENDPOINT=https://evil.com/gemini")
        assert result.findings[0].check_id == "ENV-H11"


class TestWarningPatterns:
    def test_api_key_warning(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("STRIPE_API_KEY=sk_live_abc123")
        assert not result.is_safe
        assert result.findings[0].severity == EnvSeverity.WARNING
        assert result.findings[0].check_id == "ENV-W01"
        assert result.findings[0].value == "[redacted]"

    def test_secret_warning(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("JWT_SECRET=supersecret")
        assert result.findings[0].check_id == "ENV-W02"

    def test_token_warning(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("GITHUB_TOKEN=ghp_abc123")
        assert result.findings[0].check_id == "ENV-W03"

    def test_plain_var_no_warning(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("DEBUG=true")
        assert result.is_safe

    def test_port_no_warning(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("PORT=3000")
        assert result.is_safe


class TestEnvFileParsing:
    def test_comments_ignored(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("# NODE_OPTIONS=--require=evil.js\nDEBUG=true")
        assert result.is_safe

    def test_export_prefix(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("export NODE_OPTIONS=--inspect")
        assert result.has_critical

    def test_quoted_values(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content('LD_PRELOAD="/tmp/evil.so"')
        assert result.has_critical
        assert result.findings[0].value == "/tmp/evil.so"

    def test_single_quoted_values(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("LD_PRELOAD='/tmp/evil.so'")
        assert result.has_critical
        assert result.findings[0].value == "/tmp/evil.so"

    def test_missing_file_safe(self, tmp_path: Path) -> None:
        scanner = EnvScanner()
        result = scanner.scan(tmp_path / "nonexistent.env")
        assert result.is_safe

    def test_empty_lines_and_blanks(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("\n\n   \n# comment\n\n")
        assert result.is_safe

    def test_file_scan(self, tmp_path: Path) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("NODE_OPTIONS=--inspect\n")
        scanner = EnvScanner()
        result = scanner.scan(env_file)
        assert result.has_critical

    def test_multiple_findings(self) -> None:
        scanner = EnvScanner()
        result = scanner.scan_content("NODE_OPTIONS=--require=evil.js\nLD_PRELOAD=/tmp/evil.so\n")
        assert len(result.findings) == 2
        assert all(f.severity == EnvSeverity.CRITICAL for f in result.findings)
