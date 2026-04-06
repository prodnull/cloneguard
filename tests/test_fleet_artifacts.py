"""Tests for fleet deployment artifacts (Ansible role + MDM profiles).

Validates YAML structure, content patterns, and XML well-formedness without
requiring Ansible or MDM tools to be installed.
"""

from __future__ import annotations

from pathlib import Path

import yaml

# Base paths
FLEET_DIR = Path("src/cloneguard/fleet")
ANSIBLE_ROLE_DIR = FLEET_DIR / "ansible" / "roles" / "cloneguard"


# ---------------------------------------------------------------------------
# Ansible role -- YAML parsing
# ---------------------------------------------------------------------------


class TestAnsibleYamlParsing:
    """All YAML files in fleet/ansible/ must parse without errors."""

    def _yaml_files(self) -> list[Path]:
        ansible_dir = FLEET_DIR / "ansible"
        return list(ansible_dir.rglob("*.yml"))

    def test_all_yaml_files_parse(self) -> None:
        yaml_files = self._yaml_files()
        assert len(yaml_files) > 0, "No YAML files found in fleet/ansible/"
        for path in yaml_files:
            content = path.read_text()
            parsed = yaml.safe_load(content)
            assert parsed is not None, f"{path} parsed to None"

    def test_yaml_file_count(self) -> None:
        """Expect at least 5 YAML files (tasks, defaults, handlers, meta, site)."""
        yaml_files = self._yaml_files()
        assert len(yaml_files) >= 5


# ---------------------------------------------------------------------------
# Ansible role -- tasks/main.yml
# ---------------------------------------------------------------------------


class TestAnsibleTasks:
    """Validate tasks/main.yml structure and content."""

    def test_tasks_uses_fqcn(self) -> None:
        """All module references must use ansible.builtin.* FQCN."""
        content = (ANSIBLE_ROLE_DIR / "tasks" / "main.yml").read_text()
        assert "ansible.builtin" in content

    def test_tasks_no_short_module_names(self) -> None:
        """Should not use short module names like 'command:' at top level."""
        content = (ANSIBLE_ROLE_DIR / "tasks" / "main.yml").read_text()
        parsed = yaml.safe_load(content)
        assert isinstance(parsed, list), "tasks/main.yml should be a list of tasks"
        for task in parsed:
            # Each task key should be either 'name', a FQCN module, or a
            # task keyword (when, register, become, etc.)
            for key in task:
                if key in (
                    "name", "when", "register", "changed_when", "failed_when",
                    "become", "notify", "vars",
                ):
                    continue
                # Module keys must be FQCN
                if "." not in key and key not in ("block", "rescue", "always"):
                    msg = f"Task uses short module name '{key}' instead of FQCN"
                    raise AssertionError(msg)

    def test_tasks_has_install_check(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "tasks" / "main.yml").read_text()
        assert "cloneguard --version" in content

    def test_tasks_has_become_false(self) -> None:
        """Policy file tasks must use become: false (T-05-14 mitigation)."""
        content = (ANSIBLE_ROLE_DIR / "tasks" / "main.yml").read_text()
        assert "become: false" in content

    def test_tasks_has_backup(self) -> None:
        """File deployments must use backup: true (T-05-13 mitigation)."""
        content = (ANSIBLE_ROLE_DIR / "tasks" / "main.yml").read_text()
        assert "backup: true" in content

    def test_tasks_mode_0600_for_policy(self) -> None:
        """Policy files must be deployed with mode 0600."""
        content = (ANSIBLE_ROLE_DIR / "tasks" / "main.yml").read_text()
        assert '"0600"' in content


# ---------------------------------------------------------------------------
# Ansible role -- defaults/main.yml
# ---------------------------------------------------------------------------


class TestAnsibleDefaults:
    """Validate defaults/main.yml variables."""

    def test_defaults_has_version(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "defaults" / "main.yml").read_text()
        assert "cloneguard_version:" in content

    def test_defaults_dry_run_true(self) -> None:
        """Safe default: dry_run must be true."""
        content = (ANSIBLE_ROLE_DIR / "defaults" / "main.yml").read_text()
        assert "cloneguard_dry_run: true" in content

    def test_defaults_has_install_method(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "defaults" / "main.yml").read_text()
        assert "cloneguard_install_method:" in content

    def test_defaults_has_policy_backend(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "defaults" / "main.yml").read_text()
        assert "cloneguard_policy_backend:" in content

    def test_defaults_has_extras(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "defaults" / "main.yml").read_text()
        assert "cloneguard_extras:" in content


# ---------------------------------------------------------------------------
# Ansible role -- templates
# ---------------------------------------------------------------------------


class TestAnsibleTemplates:
    """Validate Jinja2 templates contain expected variable references."""

    def test_policy_template_references_thresholds(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "templates" / "policy.yaml.j2").read_text()
        assert "cloneguard_suspicious_floor" in content
        assert "cloneguard_malicious_floor" in content

    def test_policy_template_references_sandbox(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "templates" / "policy.yaml.j2").read_text()
        assert "cloneguard_sandbox_preferred" in content
        assert "cloneguard_sandbox_fallback" in content

    def test_policy_template_references_dry_run(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "templates" / "policy.yaml.j2").read_text()
        assert "cloneguard_dry_run" in content

    def test_policy_template_has_lower_filter(self) -> None:
        """Boolean dry_run should use | lower filter for YAML output."""
        content = (ANSIBLE_ROLE_DIR / "templates" / "policy.yaml.j2").read_text()
        assert "| lower" in content

    def test_settings_template_references_events(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "templates" / "settings.json.j2").read_text()
        assert "event" in content
        assert "cloneguard_hook_events" in content

    def test_settings_template_has_hook_check(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "templates" / "settings.json.j2").read_text()
        assert "cloneguard hook-check --event" in content


# ---------------------------------------------------------------------------
# Ansible role -- meta and handlers
# ---------------------------------------------------------------------------


class TestAnsibleMeta:
    """Validate meta/main.yml Galaxy metadata."""

    def test_meta_has_min_ansible_version(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "meta" / "main.yml").read_text()
        assert "min_ansible_version" in content

    def test_meta_has_platforms(self) -> None:
        parsed = yaml.safe_load(
            (ANSIBLE_ROLE_DIR / "meta" / "main.yml").read_text()
        )
        platforms = parsed["galaxy_info"]["platforms"]
        assert len(platforms) >= 3

    def test_meta_has_galaxy_tags(self) -> None:
        parsed = yaml.safe_load(
            (ANSIBLE_ROLE_DIR / "meta" / "main.yml").read_text()
        )
        tags = parsed["galaxy_info"]["galaxy_tags"]
        assert "security" in tags
        assert "cloneguard" in tags


class TestAnsibleHandlers:
    """Validate handlers/main.yml."""

    def test_handler_exists(self) -> None:
        content = (ANSIBLE_ROLE_DIR / "handlers" / "main.yml").read_text()
        assert "Verify CloneGuard config" in content


# ---------------------------------------------------------------------------
# Ansible role -- site.yml
# ---------------------------------------------------------------------------


class TestAnsibleSitePlaybook:
    """Validate example site.yml playbook."""

    def test_site_has_roles(self) -> None:
        content = (FLEET_DIR / "ansible" / "site.yml").read_text()
        assert "roles:" in content

    def test_site_has_cloneguard_role(self) -> None:
        content = (FLEET_DIR / "ansible" / "site.yml").read_text()
        assert "role: cloneguard" in content

    def test_site_has_two_host_groups(self) -> None:
        parsed = yaml.safe_load(
            (FLEET_DIR / "ansible" / "site.yml").read_text()
        )
        assert isinstance(parsed, list), "site.yml should be a list of plays"
        assert len(parsed) >= 2
