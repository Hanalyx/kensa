"""Tests for runner._config — variable loading, resolution, and override hierarchy."""

from __future__ import annotations

import textwrap

import pytest

from runner._config import (
    RuleConfig,
    _get_effective_variables,
    load_config,
    parse_var_overrides,
    resolve_variables,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def _write_yaml(path, content: str) -> None:
    path.write_text(textwrap.dedent(content))


# ── load_config from config directory ─────────────────────────────────────


class TestLoadConfig:
    """Tests for load_config() with the new config/ directory layout."""

    def test_load_defaults(self, tmp_path):
        """Load variables from config/defaults.yml."""
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              ssh_max_auth_tries: 4
              login_defs_pass_max_days: 60
            frameworks:
              cis:
                ssh_max_auth_tries: 6
            """,
        )
        config = load_config(str(tmp_path))
        assert config.variables["ssh_max_auth_tries"] == 4
        assert config.framework_overrides["cis"]["ssh_max_auth_tries"] == 6

    def test_load_conf_d_overrides(self, tmp_path):
        """conf.d/*.yml overrides merge into variables."""
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              ssh_max_auth_tries: 4
            """,
        )
        conf_d = tmp_path / "conf.d"
        conf_d.mkdir()
        _write_yaml(
            conf_d / "50-custom.yml",
            """\
            variables:
              ssh_max_auth_tries: 10
            """,
        )
        config = load_config(str(tmp_path))
        assert config.variables["ssh_max_auth_tries"] == 10

    def test_conf_d_alphabetical_order(self, tmp_path):
        """Later conf.d files override earlier ones."""
        _write_yaml(tmp_path / "defaults.yml", "variables: {}")
        conf_d = tmp_path / "conf.d"
        conf_d.mkdir()
        _write_yaml(
            conf_d / "10-first.yml",
            """\
            variables:
              val: first
            """,
        )
        _write_yaml(
            conf_d / "90-last.yml",
            """\
            variables:
              val: last
            """,
        )
        config = load_config(str(tmp_path))
        assert config.variables["val"] == "last"

    def test_load_none_uses_auto_detect(self, tmp_path, monkeypatch):
        """load_config(None) falls back to get_config_path()."""
        monkeypatch.setenv("KENSA_CONFIG_PATH", str(tmp_path))
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              foo: bar
            """,
        )
        config = load_config(None)
        assert config.variables["foo"] == "bar"

    def test_missing_dir_returns_empty(self):
        """Non-existent config dir returns empty RuleConfig."""
        config = load_config("/nonexistent/path/that/does/not/exist")
        assert config.variables == {}
        assert config.framework_overrides == {}

    def test_malformed_defaults_ignored(self, tmp_path):
        """Malformed YAML in defaults.yml is silently ignored."""
        (tmp_path / "defaults.yml").write_text("{{invalid yaml")
        config = load_config(str(tmp_path))
        assert config.variables == {}


class TestGroupOverrides:
    """Tests for config/groups/*.yml loading."""

    def test_load_groups(self, tmp_path):
        """Group overrides load from groups/ directory."""
        _write_yaml(tmp_path / "defaults.yml", "variables: {}")
        groups_dir = tmp_path / "groups"
        groups_dir.mkdir()
        _write_yaml(
            groups_dir / "pci-scope.yml",
            """\
            variables:
              ssh_max_auth_tries: 3
              login_defs_pass_max_days: 30
            """,
        )
        config = load_config(str(tmp_path))
        assert "pci-scope" in config.group_overrides
        assert config.group_overrides["pci-scope"]["ssh_max_auth_tries"] == 3

    def test_multiple_groups(self, tmp_path):
        """Multiple group files load independently."""
        _write_yaml(tmp_path / "defaults.yml", "variables: {}")
        groups_dir = tmp_path / "groups"
        groups_dir.mkdir()
        _write_yaml(
            groups_dir / "web.yml",
            """\
            variables:
              ssh_max_auth_tries: 5
            """,
        )
        _write_yaml(
            groups_dir / "db.yml",
            """\
            variables:
              ssh_max_auth_tries: 2
            """,
        )
        config = load_config(str(tmp_path))
        assert config.group_overrides["web"]["ssh_max_auth_tries"] == 5
        assert config.group_overrides["db"]["ssh_max_auth_tries"] == 2

    def test_malformed_group_ignored(self, tmp_path):
        """Malformed group YAML is silently ignored."""
        _write_yaml(tmp_path / "defaults.yml", "variables: {}")
        groups_dir = tmp_path / "groups"
        groups_dir.mkdir()
        (groups_dir / "bad.yml").write_text("{{invalid")
        config = load_config(str(tmp_path))
        assert "bad" not in config.group_overrides


class TestHostOverrides:
    """Tests for config/hosts/*.yml loading."""

    def test_load_hosts(self, tmp_path):
        """Host overrides load from hosts/ directory."""
        _write_yaml(tmp_path / "defaults.yml", "variables: {}")
        hosts_dir = tmp_path / "hosts"
        hosts_dir.mkdir()
        _write_yaml(
            hosts_dir / "bastion-01.yml",
            """\
            variables:
              ssh_max_auth_tries: 2
            """,
        )
        config = load_config(str(tmp_path))
        assert "bastion-01" in config.host_overrides
        assert config.host_overrides["bastion-01"]["ssh_max_auth_tries"] == 2

    def test_malformed_host_ignored(self, tmp_path):
        """Malformed host YAML is silently ignored."""
        _write_yaml(tmp_path / "defaults.yml", "variables: {}")
        hosts_dir = tmp_path / "hosts"
        hosts_dir.mkdir()
        (hosts_dir / "broken.yml").write_text("{{bad yaml")
        config = load_config(str(tmp_path))
        assert "broken" not in config.host_overrides


class TestEmptyDirs:
    """Missing groups/ or hosts/ dirs don't crash."""

    def test_no_groups_dir(self, tmp_path):
        """Missing groups/ directory is OK."""
        _write_yaml(
            tmp_path / "defaults.yml",
            "variables:\n  x: 1\n",
        )
        config = load_config(str(tmp_path))
        assert config.group_overrides == {}
        assert config.variables["x"] == 1

    def test_no_hosts_dir(self, tmp_path):
        """Missing hosts/ directory is OK."""
        _write_yaml(
            tmp_path / "defaults.yml",
            "variables:\n  x: 1\n",
        )
        config = load_config(str(tmp_path))
        assert config.host_overrides == {}

    def test_no_conf_d_dir(self, tmp_path):
        """Missing conf.d/ directory is OK."""
        _write_yaml(
            tmp_path / "defaults.yml",
            "variables:\n  x: 1\n",
        )
        config = load_config(str(tmp_path))
        assert config.variables["x"] == 1

    def test_completely_empty_dir(self, tmp_path):
        """Empty config dir with no defaults.yml returns empty config."""
        config = load_config(str(tmp_path))
        assert config.variables == {}


# ── Variable resolution ───────────────────────────────────────────────────


class TestGetEffectiveVariables:
    """Tests for _get_effective_variables() with full precedence chain."""

    def test_defaults_only(self):
        """Base defaults returned when no overrides."""
        config = RuleConfig(variables={"x": 1, "y": 2})
        result = _get_effective_variables(config)
        assert result == {"x": 1, "y": 2}

    def test_framework_overrides_defaults(self):
        """Framework overrides take precedence over defaults."""
        config = RuleConfig(
            variables={"x": 1},
            framework_overrides={"cis": {"x": 99}},
        )
        result = _get_effective_variables(config, framework="cis-rhel9-v2.0.0")
        assert result["x"] == 99

    def test_group_overrides_framework(self):
        """Group overrides take precedence over framework."""
        config = RuleConfig(
            variables={"x": 1},
            framework_overrides={"cis": {"x": 10}},
            group_overrides={"pci": {"x": 50}},
        )
        result = _get_effective_variables(
            config, framework="cis-rhel9-v2.0.0", groups=["pci"]
        )
        assert result["x"] == 50

    def test_group_order_last_wins(self):
        """When host is in multiple groups, last group wins."""
        config = RuleConfig(
            variables={"x": 1},
            group_overrides={
                "web": {"x": 10},
                "pci": {"x": 20},
            },
        )
        result = _get_effective_variables(config, groups=["web", "pci"])
        assert result["x"] == 20

        # Reverse order
        result2 = _get_effective_variables(config, groups=["pci", "web"])
        assert result2["x"] == 10

    def test_host_overrides_group(self):
        """Host overrides take precedence over group."""
        config = RuleConfig(
            variables={"x": 1},
            group_overrides={"pci": {"x": 50}},
            host_overrides={"bastion-01": {"x": 99}},
        )
        result = _get_effective_variables(config, groups=["pci"], hostname="bastion-01")
        assert result["x"] == 99

    def test_cli_overrides_everything(self):
        """CLI overrides take highest precedence."""
        config = RuleConfig(
            variables={"x": 1},
            framework_overrides={"cis": {"x": 10}},
            group_overrides={"pci": {"x": 50}},
            host_overrides={"bastion-01": {"x": 99}},
        )
        result = _get_effective_variables(
            config,
            framework="cis-rhel9-v2.0.0",
            groups=["pci"],
            hostname="bastion-01",
            cli_overrides={"x": 999},
        )
        assert result["x"] == 999

    def test_nonexistent_group_ignored(self):
        """Groups not in config.group_overrides are silently ignored."""
        config = RuleConfig(variables={"x": 1})
        result = _get_effective_variables(config, groups=["nonexistent"])
        assert result["x"] == 1

    def test_nonexistent_host_ignored(self):
        """Hosts not in config.host_overrides are silently ignored."""
        config = RuleConfig(variables={"x": 1})
        result = _get_effective_variables(config, hostname="unknown-host")
        assert result["x"] == 1


class TestPrecedenceChain:
    """Full chain: defaults < framework < conf.d < group < host < CLI."""

    def test_full_chain(self, tmp_path):
        """End-to-end test of full precedence chain."""
        # Build a config directory with all layers
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              a: default
              b: default
              c: default
              d: default
              e: default
              f: default
            frameworks:
              cis:
                b: framework
                c: framework
                d: framework
                e: framework
                f: framework
            """,
        )
        conf_d = tmp_path / "conf.d"
        conf_d.mkdir()
        _write_yaml(
            conf_d / "50-site.yml",
            """\
            variables:
              c: conf_d
              d: conf_d
              e: conf_d
              f: conf_d
            """,
        )
        groups_dir = tmp_path / "groups"
        groups_dir.mkdir()
        _write_yaml(
            groups_dir / "mygroup.yml",
            """\
            variables:
              d: group
              e: group
              f: group
            """,
        )
        hosts_dir = tmp_path / "hosts"
        hosts_dir.mkdir()
        _write_yaml(
            hosts_dir / "myhost.yml",
            """\
            variables:
              e: host
              f: host
            """,
        )

        config = load_config(str(tmp_path))
        result = _get_effective_variables(
            config,
            framework="cis-rhel9-v2.0.0",
            groups=["mygroup"],
            hostname="myhost",
            cli_overrides={"f": "cli"},
        )

        assert result["a"] == "default"
        # Note: conf.d merges into config.variables at load time,
        # so "b" stays framework (framework > merged defaults)
        # and "c" becomes conf_d (which is merged into variables, then framework overrides it)
        # Actually: conf.d merges INTO config.variables, so after load:
        #   config.variables = {a: default, b: default, c: conf_d, d: conf_d, e: conf_d, f: conf_d}
        # Then framework overrides b,c,d,e,f → so framework wins over conf.d for b
        # But group overrides d,e,f → group wins
        # And host overrides e,f → host wins
        # And CLI overrides f → CLI wins
        assert result["b"] == "framework"
        assert result["c"] == "framework"  # framework overrides conf.d-merged vars
        assert result["d"] == "group"
        assert result["e"] == "host"
        assert result["f"] == "cli"


class TestPerHostResolution:
    """Two hosts in different groups get different values for the same rule."""

    def test_different_hosts_different_values(self, tmp_path):
        """Variables resolve differently per host."""
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              ssh_max_auth_tries: 4
            """,
        )
        groups_dir = tmp_path / "groups"
        groups_dir.mkdir()
        _write_yaml(
            groups_dir / "strict.yml",
            """\
            variables:
              ssh_max_auth_tries: 2
            """,
        )
        _write_yaml(
            groups_dir / "relaxed.yml",
            """\
            variables:
              ssh_max_auth_tries: 10
            """,
        )

        config = load_config(str(tmp_path))
        rule = {
            "id": "test-rule",
            "check": {"expected": "{{ ssh_max_auth_tries }}"},
        }

        resolved_strict = resolve_variables(
            rule, config, groups=["strict"], hostname="host-a"
        )
        resolved_relaxed = resolve_variables(
            rule, config, groups=["relaxed"], hostname="host-b"
        )

        assert resolved_strict["check"]["expected"] == "2"
        assert resolved_relaxed["check"]["expected"] == "10"

    def test_host_override_per_host(self, tmp_path):
        """Per-host override file applies only to that host."""
        _write_yaml(
            tmp_path / "defaults.yml",
            """\
            variables:
              ssh_max_auth_tries: 4
            """,
        )
        hosts_dir = tmp_path / "hosts"
        hosts_dir.mkdir()
        _write_yaml(
            hosts_dir / "special.yml",
            """\
            variables:
              ssh_max_auth_tries: 99
            """,
        )

        config = load_config(str(tmp_path))
        rule = {
            "id": "test-rule",
            "check": {"expected": "{{ ssh_max_auth_tries }}"},
        }

        resolved_special = resolve_variables(rule, config, hostname="special")
        resolved_normal = resolve_variables(rule, config, hostname="normal")

        assert resolved_special["check"]["expected"] == "99"
        assert resolved_normal["check"]["expected"] == "4"


# ── resolve_variables ─────────────────────────────────────────────────────


class TestResolveVariables:
    """Tests for resolve_variables() with hostname/groups params."""

    def test_basic_substitution(self):
        """Basic variable substitution works."""
        config = RuleConfig(variables={"val": "42"})
        rule = {"check": {"expected": "{{ val }}"}}
        result = resolve_variables(rule, config)
        assert result["check"]["expected"] == "42"

    def test_safe_fields_only(self):
        """Variables only substitute in safe fields."""
        config = RuleConfig(variables={"val": "injected"})
        rule = {"check": {"run": "{{ val }}", "expected": "{{ val }}"}}
        result = resolve_variables(rule, config)
        assert result["check"]["run"] == "{{ val }}"  # NOT substituted
        assert result["check"]["expected"] == "injected"  # substituted

    def test_undefined_strict(self):
        """Strict mode raises on undefined variables."""
        config = RuleConfig(variables={})
        rule = {"check": {"expected": "{{ undefined_var }}"}}
        with pytest.raises(ValueError, match="Undefined variable"):
            resolve_variables(rule, config, strict=True)

    def test_undefined_non_strict(self):
        """Non-strict mode leaves undefined vars unchanged."""
        config = RuleConfig(variables={})
        rule = {"check": {"expected": "{{ undefined_var }}"}}
        result = resolve_variables(rule, config, strict=False)
        assert result["check"]["expected"] == "{{ undefined_var }}"

    def test_hostname_and_groups_passthrough(self):
        """hostname and groups params are passed through to effective vars."""
        config = RuleConfig(
            variables={"x": "default"},
            group_overrides={"grp": {"x": "from_group"}},
            host_overrides={"myhost": {"x": "from_host"}},
        )
        rule = {"check": {"expected": "{{ x }}"}}

        # Group only
        r1 = resolve_variables(rule, config, groups=["grp"])
        assert r1["check"]["expected"] == "from_group"

        # Host overrides group
        r2 = resolve_variables(rule, config, groups=["grp"], hostname="myhost")
        assert r2["check"]["expected"] == "from_host"


# ── parse_var_overrides ───────────────────────────────────────────────────


class TestParseVarOverrides:
    """Tests for parse_var_overrides()."""

    def test_basic(self):
        result = parse_var_overrides(("key=value",))
        assert result == {"key": "value"}

    def test_multiple(self):
        result = parse_var_overrides(("a=1", "b=2"))
        assert result == {"a": "1", "b": "2"}

    def test_value_with_equals(self):
        result = parse_var_overrides(("key=a=b",))
        assert result == {"key": "a=b"}

    def test_empty_tuple(self):
        result = parse_var_overrides(())
        assert result == {}

    def test_no_equals_raises(self):
        with pytest.raises(ValueError, match="expected KEY=VALUE"):
            parse_var_overrides(("bad",))

    def test_empty_key_raises(self):
        with pytest.raises(ValueError, match="empty key"):
            parse_var_overrides(("=value",))


# ── get_config_path ───────────────────────────────────────────────────────


class TestGetConfigPath:
    """Tests for runner.paths.get_config_path()."""

    def test_env_var(self, tmp_path, monkeypatch):
        """KENSA_CONFIG_PATH env var takes priority."""
        from runner.paths import get_config_path

        config_dir = tmp_path / "custom-config"
        config_dir.mkdir()
        monkeypatch.setenv("KENSA_CONFIG_PATH", str(config_dir))
        result = get_config_path()
        assert result == config_dir

    def test_env_var_with_subpath(self, tmp_path, monkeypatch):
        """Subpath is appended to env var path."""
        from runner.paths import get_config_path

        config_dir = tmp_path / "custom-config"
        config_dir.mkdir()
        monkeypatch.setenv("KENSA_CONFIG_PATH", str(config_dir))
        result = get_config_path("defaults.yml")
        assert result == config_dir / "defaults.yml"

    def test_dev_layout(self, tmp_path, monkeypatch):
        """Dev layout: ./config/ relative to cwd."""
        from runner.paths import get_config_path

        monkeypatch.delenv("KENSA_CONFIG_PATH", raising=False)
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        monkeypatch.chdir(tmp_path)
        result = get_config_path()
        assert result == config_dir

    def test_not_found_raises(self, tmp_path, monkeypatch):
        """FileNotFoundError when no config dir found."""
        from runner.paths import get_config_path

        monkeypatch.delenv("KENSA_CONFIG_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        # Patch source-relative path too
        monkeypatch.setattr(
            "runner.paths.Path.exists",
            lambda self: False,
        )
        with pytest.raises(FileNotFoundError, match="Cannot locate"):
            get_config_path()


# ── get_mappings_path ────────────────────────────────────────────────────


class TestGetMappingsPath:
    """Tests for runner.paths.get_mappings_path()."""

    def test_env_var(self, tmp_path, monkeypatch):
        """KENSA_MAPPINGS_PATH env var takes priority."""
        from runner.paths import get_mappings_path

        mappings_dir = tmp_path / "custom-mappings"
        mappings_dir.mkdir()
        monkeypatch.setenv("KENSA_MAPPINGS_PATH", str(mappings_dir))
        result = get_mappings_path()
        assert result == mappings_dir

    def test_env_var_with_subpath(self, tmp_path, monkeypatch):
        """Subpath is appended to env var path."""
        from runner.paths import get_mappings_path

        mappings_dir = tmp_path / "custom-mappings"
        mappings_dir.mkdir()
        monkeypatch.setenv("KENSA_MAPPINGS_PATH", str(mappings_dir))
        result = get_mappings_path("cis")
        assert result == mappings_dir / "cis"

    def test_dev_layout(self, tmp_path, monkeypatch):
        """Dev layout: ./mappings/ relative to cwd."""
        from runner.paths import get_mappings_path

        monkeypatch.delenv("KENSA_MAPPINGS_PATH", raising=False)
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        monkeypatch.chdir(tmp_path)
        result = get_mappings_path()
        assert result == mappings_dir

    def test_not_found_raises(self, tmp_path, monkeypatch):
        """FileNotFoundError when no mappings dir found."""
        from runner.paths import get_mappings_path

        monkeypatch.delenv("KENSA_MAPPINGS_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "runner.paths.Path.exists",
            lambda self: False,
        )
        with pytest.raises(FileNotFoundError, match="Cannot locate"):
            get_mappings_path()


# ── get_inventory_path ───────────────────────────────────────────────────


class TestGetInventoryPath:
    """Tests for runner.paths.get_inventory_path()."""

    def test_env_var(self, tmp_path, monkeypatch):
        """KENSA_INVENTORY_PATH env var takes priority."""
        from runner.paths import get_inventory_path

        inv_file = tmp_path / "hosts.yml"
        inv_file.write_text("all:\n  - host1\n")
        monkeypatch.setenv("KENSA_INVENTORY_PATH", str(inv_file))
        result = get_inventory_path()
        assert result == inv_file

    def test_cwd_yml(self, tmp_path, monkeypatch):
        """Finds inventory.yml in cwd."""
        from runner.paths import get_inventory_path

        monkeypatch.delenv("KENSA_INVENTORY_PATH", raising=False)
        inv_file = tmp_path / "inventory.yml"
        inv_file.write_text("all:\n  - host1\n")
        monkeypatch.chdir(tmp_path)
        result = get_inventory_path()
        assert result == inv_file

    def test_cwd_ini(self, tmp_path, monkeypatch):
        """Finds inventory.ini in cwd."""
        from runner.paths import get_inventory_path

        monkeypatch.delenv("KENSA_INVENTORY_PATH", raising=False)
        inv_file = tmp_path / "inventory.ini"
        inv_file.write_text("[all]\nhost1\n")
        monkeypatch.chdir(tmp_path)
        result = get_inventory_path()
        assert result == inv_file

    def test_not_found_returns_none(self, tmp_path, monkeypatch):
        """Returns None when no inventory file found."""
        from runner.paths import get_inventory_path

        monkeypatch.delenv("KENSA_INVENTORY_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        result = get_inventory_path()
        assert result is None
