"""Tests for runner/inventory.py — target resolution."""

from __future__ import annotations

import pytest

from runner.inventory import resolve_targets


class TestHostFlag:
    def test_single_host(self):
        hosts = resolve_targets(host="192.168.1.10")
        assert len(hosts) == 1
        assert hosts[0].hostname == "192.168.1.10"
        assert hosts[0].port == 22

    def test_comma_separated(self):
        hosts = resolve_targets(host="10.0.0.1,10.0.0.2,10.0.0.3")
        assert len(hosts) == 3
        assert [h.hostname for h in hosts] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_host_with_port(self):
        hosts = resolve_targets(host="10.0.0.1:2222")
        assert hosts[0].hostname == "10.0.0.1"
        assert hosts[0].port == 2222

    def test_strips_whitespace(self):
        hosts = resolve_targets(host=" 10.0.0.1 , 10.0.0.2 ")
        assert len(hosts) == 2

    def test_ignores_empty_parts(self):
        hosts = resolve_targets(host="10.0.0.1,,10.0.0.2")
        assert len(hosts) == 2


class TestDefaults:
    def test_cli_defaults_applied(self):
        hosts = resolve_targets(
            host="10.0.0.1",
            default_user="admin",
            default_key="/tmp/key",
            default_port=2222,
        )
        assert hosts[0].user == "admin"
        assert hosts[0].key_path == "/tmp/key"
        assert hosts[0].port == 2222

    def test_no_hosts_raises(self):
        with pytest.raises(ValueError, match="No target hosts"):
            resolve_targets()


class TestINIInventory:
    def test_basic_ini(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text(
            "[webservers]\n"
            "web1.example.com\n"
            "web2.example.com\n"
            "\n"
            "[dbservers]\n"
            "db1.example.com\n"
        )
        hosts = resolve_targets(inventory=str(ini))
        assert len(hosts) == 3
        hostnames = {h.hostname for h in hosts}
        assert hostnames == {"web1.example.com", "web2.example.com", "db1.example.com"}

    def test_host_vars(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text(
            "[servers]\n"
            "server1 host=10.0.0.1 user=deploy port=2222 "
            "key_file=/keys/id_rsa\n"
        )
        hosts = resolve_targets(inventory=str(ini))
        assert hosts[0].hostname == "10.0.0.1"
        assert hosts[0].user == "deploy"
        assert hosts[0].port == 2222
        assert hosts[0].key_path == "/keys/id_rsa"

    def test_groups_tracked(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text("[web]\n" "server1\n" "\n" "[app]\n" "server1\n")
        hosts = resolve_targets(inventory=str(ini))
        assert len(hosts) == 1
        assert set(hosts[0].groups) == {"web", "app"}

    def test_comments_ignored(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text(
            "# This is a comment\n" "[servers]\n" "host1  # inline comment\n"
        )
        hosts = resolve_targets(inventory=str(ini))
        assert len(hosts) == 1

    def test_inventory_vars_override_defaults(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text("[servers]\n" "host1 user=deploy\n")
        hosts = resolve_targets(
            inventory=str(ini),
            default_user="admin",
        )
        # Inventory per-host var wins
        assert hosts[0].user == "deploy"

    def test_defaults_fill_gaps(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text("[servers]\n" "host1 user=deploy\n")
        hosts = resolve_targets(
            inventory=str(ini),
            default_user="admin",
            default_key="/tmp/key",
        )
        # user from inventory, key from default
        assert hosts[0].user == "deploy"
        assert hosts[0].key_path == "/tmp/key"


class TestYAMLInventory:
    def test_basic_yaml(self, tmp_path):
        inv = tmp_path / "inventory.yml"
        inv.write_text(
            "all:\n"
            "  children:\n"
            "    webservers:\n"
            "      hosts:\n"
            "        web1.example.com:\n"
            "        web2.example.com:\n"
            "    dbservers:\n"
            "      hosts:\n"
            "        db1.example.com:\n"
        )
        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 3

    def test_yaml_host_vars(self, tmp_path):
        inv = tmp_path / "inventory.yaml"
        inv.write_text(
            "all:\n"
            "  children:\n"
            "    servers:\n"
            "      hosts:\n"
            "        myhost:\n"
            "          host: 10.0.0.5\n"
            "          user: deploy\n"
            "          port: 2222\n"
        )
        hosts = resolve_targets(inventory=str(inv))
        assert hosts[0].hostname == "10.0.0.5"
        assert hosts[0].user == "deploy"
        assert hosts[0].port == 2222

    def test_yaml_groups(self, tmp_path):
        inv = tmp_path / "inventory.yml"
        inv.write_text(
            "all:\n" "  children:\n" "    web:\n" "      hosts:\n" "        server1:\n"
        )
        hosts = resolve_targets(inventory=str(inv))
        assert "web" in hosts[0].groups


class TestPlainTextHostList:
    def test_one_per_line(self, tmp_path):
        f = tmp_path / "hosts.txt"
        f.write_text("10.0.0.1\n10.0.0.2\n10.0.0.3\n")
        hosts = resolve_targets(inventory=str(f))
        assert len(hosts) == 3

    def test_blank_lines_and_comments(self, tmp_path):
        f = tmp_path / "hosts.txt"
        f.write_text("# Servers\n" "10.0.0.1\n" "\n" "10.0.0.2  # web\n" "\n")
        hosts = resolve_targets(inventory=str(f))
        assert len(hosts) == 2

    def test_host_with_port(self, tmp_path):
        f = tmp_path / "hosts.txt"
        f.write_text("10.0.0.1:2222\n")
        hosts = resolve_targets(inventory=str(f))
        assert hosts[0].port == 2222


class TestFormatAutoDetection:
    def test_yml_extension_uses_yaml(self, tmp_path):
        inv = tmp_path / "inv.yml"
        inv.write_text("all:\n  hosts:\n    host1:\n")
        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 1

    def test_ini_detected_by_brackets(self, tmp_path):
        inv = tmp_path / "inventory"
        inv.write_text("[servers]\nhost1\n")
        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 1
        assert "servers" in hosts[0].groups

    def test_plain_text_fallback(self, tmp_path):
        inv = tmp_path / "hosts"
        inv.write_text("10.0.0.1\n10.0.0.2\n")
        hosts = resolve_targets(inventory=str(inv))
        assert len(hosts) == 2


class TestLimit:
    def test_limit_by_group(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text("[web]\nweb1\nweb2\n\n[db]\ndb1\n")
        hosts = resolve_targets(inventory=str(ini), limit="web")
        assert len(hosts) == 2
        assert all("web" in h.groups for h in hosts)

    def test_limit_by_glob(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text("[servers]\nweb1\nweb2\ndb1\n")
        hosts = resolve_targets(inventory=str(ini), limit="web*")
        assert len(hosts) == 2

    def test_limit_no_match_raises(self, tmp_path):
        ini = tmp_path / "inventory.ini"
        ini.write_text("[servers]\nhost1\n")
        with pytest.raises(ValueError, match="matched no hosts"):
            resolve_targets(inventory=str(ini), limit="nonexistent")

    def test_inventory_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            resolve_targets(inventory="/nonexistent/path")
