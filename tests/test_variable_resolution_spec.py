"""Spec-derived tests for variable resolution.

Spec: specs/internal/variable_resolution.spec.yaml
"""

from __future__ import annotations

import textwrap

import pytest

from runner._config import (
    SAFE_SUBSTITUTION_FIELDS,
    RuleConfig,
    _get_effective_variables,
    load_config,
    parse_var_overrides,
    resolve_variables,
)


def _write_yaml(path, content: str) -> None:
    path.write_text(textwrap.dedent(content))


class TestVariableResolutionSpecDerived:
    """Spec-derived tests for variable resolution.

    See specs/internal/variable_resolution.spec.yaml for specification.
    """

    def test_ac1_defaults_loaded(self, tmp_path):
        """AC-1: Default variables loaded from defaults.yml variables section."""
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              ssh_max_auth_tries: 4
              login_defs_pass_max_days: 60
            """,
        )
        config = load_config(str(tmp_path))
        assert config.variables["ssh_max_auth_tries"] == 4
        assert config.variables["login_defs_pass_max_days"] == 60

    def test_ac2_conf_d_alphabetical_merge(self, tmp_path):
        """AC-2: conf.d/*.yml merge alphabetically; later files override earlier."""
        _write_yaml(tmp_path / "defaults.yml", "variables:\n  val: original\n")
        conf_d = tmp_path / "conf.d"
        conf_d.mkdir()
        _write_yaml(conf_d / "10-first.yml", "variables:\n  val: first\n")
        _write_yaml(conf_d / "90-last.yml", "variables:\n  val: last\n")

        config = load_config(str(tmp_path))
        assert config.variables["val"] == "last"

    def test_ac3_framework_overrides_loaded(self, tmp_path):
        """AC-3: Framework overrides from defaults.yml populate framework_overrides."""
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              x: 1
            frameworks:
              cis:
                x: 10
              stig:
                x: 15
            """,
        )
        config = load_config(str(tmp_path))
        assert config.framework_overrides["cis"]["x"] == 10
        assert config.framework_overrides["stig"]["x"] == 15

    def test_ac4_framework_base_name_extraction(self):
        """AC-4: Framework base name extracted via split('-')[0].lower()."""
        config = RuleConfig(
            variables={"x": 1},
            framework_overrides={"cis": {"x": 99}},
        )
        result = _get_effective_variables(config, framework="cis-rhel9")
        assert result["x"] == 99

    def test_ac5_group_overrides_last_wins(self):
        """AC-5: Group overrides applied in order; last group wins on conflict."""
        config = RuleConfig(
            variables={"x": 1},
            group_overrides={
                "web": {"x": 10},
                "pci": {"x": 20},
            },
        )
        # Last group in list wins
        result = _get_effective_variables(config, groups=["web", "pci"])
        assert result["x"] == 20

        # Reverse order: web is now last → web wins
        result2 = _get_effective_variables(config, groups=["pci", "web"])
        assert result2["x"] == 10

    def test_ac6_host_overrides_matching_hostname(self):
        """AC-6: Host overrides applied for matching hostname only."""
        config = RuleConfig(
            variables={"x": 1},
            host_overrides={"bastion-01": {"x": 99}},
        )
        result_match = _get_effective_variables(config, hostname="bastion-01")
        assert result_match["x"] == 99

        result_nomatch = _get_effective_variables(config, hostname="other-host")
        assert result_nomatch["x"] == 1

    def test_ac7_cli_overrides_highest_priority(self):
        """AC-7: CLI --var KEY=VALUE overrides have highest priority."""
        config = RuleConfig(
            variables={"x": 1},
            framework_overrides={"cis": {"x": 10}},
            group_overrides={"pci": {"x": 50}},
            host_overrides={"bastion": {"x": 99}},
        )
        result = _get_effective_variables(
            config,
            framework="cis-rhel9",
            groups=["pci"],
            hostname="bastion",
            cli_overrides={"x": 999},
        )
        assert result["x"] == 999

    def test_ac8_safe_fields_only(self):
        """AC-8: Only SAFE_SUBSTITUTION_FIELDS are substituted; unsafe fields unchanged."""
        config = RuleConfig(variables={"val": "injected"})
        rule = {
            "check": {
                "run": "{{ val }}",
                "path": "{{ val }}",
                "expected": "{{ val }}",
                "value": "{{ val }}",
            }
        }
        result = resolve_variables(rule, config)
        # Safe fields substituted
        assert result["check"]["expected"] == "injected"
        assert result["check"]["value"] == "injected"
        # Unsafe fields NOT substituted
        assert result["check"]["run"] == "{{ val }}"
        assert result["check"]["path"] == "{{ val }}"

    def test_ac8_safe_fields_set_correct(self):
        """AC-8: Verify SAFE_SUBSTITUTION_FIELDS contains exactly the documented set."""
        expected = {
            "content",
            "expected",
            "expected_content",
            "value",
            "mode",
            "owner",
            "group",
        }
        assert expected == SAFE_SUBSTITUTION_FIELDS

    def test_ac9_variable_pattern_matching(self):
        """AC-9: {{ variable_name }} with optional whitespace recognized and replaced."""
        config = RuleConfig(variables={"foo": "bar"})
        # Various whitespace patterns
        for template in ["{{foo}}", "{{ foo }}", "{{  foo  }}", "{{ foo}}"]:
            rule = {"check": {"expected": template}}
            result = resolve_variables(rule, config)
            assert (
                result["check"]["expected"] == "bar"
            ), f"Failed for template: {template}"

    def test_ac10_undefined_strict_raises(self):
        """AC-10: Strict mode raises ValueError on undefined variables."""
        config = RuleConfig(variables={})
        rule = {"check": {"expected": "{{ undefined_var }}"}}
        with pytest.raises(ValueError, match="Undefined variable: undefined_var"):
            resolve_variables(rule, config, strict=True)

    def test_ac11_undefined_non_strict_passthrough(self):
        """AC-11: Non-strict mode leaves undefined variables as-is."""
        config = RuleConfig(variables={})
        rule = {"check": {"expected": "{{ undefined_var }}"}}
        result = resolve_variables(rule, config, strict=False)
        assert result["check"]["expected"] == "{{ undefined_var }}"

    def test_ac12_empty_config_dir(self, tmp_path):
        """AC-12: Empty or missing config directory returns empty RuleConfig."""
        # Empty dir
        config = load_config(str(tmp_path))
        assert config.variables == {}
        assert config.framework_overrides == {}
        assert config.group_overrides == {}
        assert config.host_overrides == {}

        # Non-existent dir
        config2 = load_config("/nonexistent/path")
        assert config2.variables == {}

    def test_ac13_parse_var_overrides_validation(self):
        """AC-13: parse_var_overrides validates KEY=VALUE format."""
        # Valid
        assert parse_var_overrides(("key=value",)) == {"key": "value"}
        assert parse_var_overrides(("a=1", "b=2")) == {"a": "1", "b": "2"}
        assert parse_var_overrides(("key=a=b",)) == {"key": "a=b"}

        # Invalid: no equals
        with pytest.raises(ValueError, match="expected KEY=VALUE"):
            parse_var_overrides(("bad",))

        # Invalid: empty key
        with pytest.raises(ValueError, match="empty key"):
            parse_var_overrides(("=value",))

    def test_ac14_malformed_yaml_ignored(self, tmp_path):
        """AC-14: Malformed YAML in any config file is silently ignored."""
        # Malformed defaults
        (tmp_path / "defaults.yml").write_text("{{invalid yaml")
        conf_d = tmp_path / "conf.d"
        conf_d.mkdir()
        (conf_d / "bad.yml").write_text("{{invalid")
        groups_dir = tmp_path / "groups"
        groups_dir.mkdir()
        (groups_dir / "bad.yml").write_text("{{invalid")
        hosts_dir = tmp_path / "hosts"
        hosts_dir.mkdir()
        (hosts_dir / "bad.yml").write_text("{{invalid")

        config = load_config(str(tmp_path))
        assert config.variables == {}
        assert config.group_overrides == {}
        assert config.host_overrides == {}
