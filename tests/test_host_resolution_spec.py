"""SpecDerived tests for host resolution module."""

from __future__ import annotations

import pytest

from runner.inventory import resolve_targets


class TestHostResolutionSpecDerived:
    """Spec-derived tests for host resolution.

    See specs/internal/host_resolution.spec.yaml for specification.
    """

    def test_ac1_host_flag_comma_separated_with_port(self):
        """AC-1: --host flag parses comma-separated hostnames with optional :port."""
        hosts = resolve_targets(host="web1,web2:2222,web3")
        assert len(hosts) == 3
        assert hosts[0].hostname == "web1"
        assert hosts[0].port == 22
        assert hosts[1].hostname == "web2"
        assert hosts[1].port == 2222
        assert hosts[2].hostname == "web3"
        assert hosts[2].port == 22

    def test_ac2_ini_inventory_with_groups_and_inline_vars(self, tmp_path):
        """AC-2: INI inventory detected by [group] headers, parsed with per-host inline variables."""
        inv = tmp_path / "inventory.ini"
        inv.write_text(
            "[webservers]\n"
            "web1 user=admin key_file=/keys/web1.pem\n"
            "web2 port=2222\n"
            "\n"
            "[dbservers]\n"
            "db1\n"
        )

        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 3

        by_name = {h.hostname: h for h in hosts}
        assert by_name["web1"].user == "admin"
        assert by_name["web1"].key_path == "/keys/web1.pem"
        assert by_name["web1"].groups == ["webservers"]
        assert by_name["web2"].port == 2222
        assert by_name["db1"].groups == ["dbservers"]

    def test_ac3_ini_legacy_ansible_variable_names(self, tmp_path):
        """AC-3: INI parser supports legacy Ansible variable names."""
        inv = tmp_path / "inventory.ini"
        inv.write_text(
            "[servers]\n"
            "host1 ansible_host=10.0.0.1 ansible_user=deploy ansible_port=2200 "
            "ansible_ssh_private_key_file=/keys/deploy.pem\n"
        )

        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 1
        h = hosts[0]
        assert h.hostname == "10.0.0.1"
        assert h.user == "deploy"
        assert h.port == 2200
        assert h.key_path == "/keys/deploy.pem"

    def test_ac4_yaml_inventory_recursive(self, tmp_path):
        """AC-4: YAML inventory files parsed recursively."""
        inv = tmp_path / "inventory.yaml"
        inv.write_text(
            "all:\n"
            "  hosts:\n"
            "    top-host:\n"
            "      user: root\n"
            "  children:\n"
            "    webservers:\n"
            "      hosts:\n"
            "        web1:\n"
            "          user: www\n"
            "        web2: {}\n"
        )

        hosts = resolve_targets(inventory=str(inv))
        by_name = {h.hostname: h for h in hosts}
        assert "top-host" in by_name
        assert "web1" in by_name
        assert "web2" in by_name
        assert by_name["web1"].user == "www"

    def test_ac5_plain_text_hostlist_fallback(self, tmp_path):
        """AC-5: Plain text host lists parsed as fallback."""
        inv = tmp_path / "hosts.txt"
        inv.write_text("server1\nserver2:2222\n# this is a comment\n\nserver3\n")

        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 3
        assert hosts[0].hostname == "server1"
        assert hosts[1].hostname == "server2"
        assert hosts[1].port == 2222
        assert hosts[2].hostname == "server3"

    def test_ac6_cli_defaults_applied_as_fallbacks(self, tmp_path):
        """AC-6: CLI defaults applied as fallbacks when inventory didn't set per-host values."""
        inv = tmp_path / "hosts.txt"
        inv.write_text("server1\nserver2\n")

        hosts = resolve_targets(
            inventory=str(inv),
            default_user="deploy",
            default_key="/keys/default.pem",
            default_port=2200,
        )

        for h in hosts:
            assert h.user == "deploy"
            assert h.key_path == "/keys/default.pem"
            assert h.port == 2200

    def test_ac7_limit_filters_by_group_or_glob(self, tmp_path):
        """AC-7: --limit filters by group membership or hostname glob; raises ValueError when no match."""
        inv = tmp_path / "inventory.ini"
        inv.write_text("[webservers]\nweb1\nweb2\n\n[dbservers]\ndb1\n")

        # Filter by group name
        hosts = resolve_targets(inventory=str(inv), limit="webservers")
        assert len(hosts) == 2
        assert {h.hostname for h in hosts} == {"web1", "web2"}

        # Filter by hostname glob
        hosts = resolve_targets(inventory=str(inv), limit="db*")
        assert len(hosts) == 1
        assert hosts[0].hostname == "db1"

        # No match raises ValueError
        with pytest.raises(ValueError, match="matched no hosts"):
            resolve_targets(inventory=str(inv), limit="nonexistent")

    def test_ac8_no_host_no_inventory_raises(self):
        """AC-8: When neither --host nor --inventory provided, raises ValueError."""
        with pytest.raises(ValueError, match="No target hosts specified"):
            resolve_targets()

    def test_ac9_multi_group_accumulates_without_duplication(self, tmp_path):
        """AC-9: Hosts in multiple INI groups accumulate all group names without duplication."""
        inv = tmp_path / "inventory.ini"
        inv.write_text("[webservers]\nshared-host\n\n[dbservers]\nshared-host\n")

        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 1
        h = hosts[0]
        assert "webservers" in h.groups
        assert "dbservers" in h.groups
        assert len(h.groups) == 2

    def test_ac10_inventory_file_not_found_raises(self, tmp_path):
        """AC-10: Inventory file not found raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            resolve_targets(inventory=str(tmp_path / "nonexistent.ini"))
