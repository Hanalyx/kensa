"""Spec-derived tests for release/package-build.spec.yaml.

Tests validate that the package build infrastructure is correctly configured
as defined in specs/release/package-build.spec.yaml.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parents[3]


class TestPackageBuildSpecDerived:
    """Spec-derived tests for package build infrastructure (AC-1 through AC-5)."""

    def test_ac1_pyproject_is_version_source_of_truth(self):
        """AC-1: pyproject.toml contains a valid semver version string."""
        pyproject = REPO_ROOT / "pyproject.toml"
        assert pyproject.exists(), "pyproject.toml must exist"
        content = pyproject.read_text()
        match = re.search(r'^version\s*=\s*"(\d+\.\d+\.\d+)"', content, re.MULTILINE)
        assert match, 'pyproject.toml must contain version = "X.Y.Z"'

    def test_ac2_hatchling_build_backend(self):
        """AC-2: pyproject.toml uses hatchling as the build backend."""
        pyproject = REPO_ROOT / "pyproject.toml"
        content = pyproject.read_text()
        assert (
            "hatchling" in content
        ), "pyproject.toml must use hatchling as build backend"
        # Verify shared-data sections for rules, schema, mappings
        for data_dir in ["rules", "schema", "mappings"]:
            assert (
                data_dir in content
            ), f"pyproject.toml wheel shared-data must include {data_dir}/"

    def test_ac3_rpm_spec_exists_with_pyproject_macros(self):
        """AC-3/AC-4: kensa.spec exists and uses pyproject-rpm-macros."""
        spec_file = REPO_ROOT / "kensa.spec"
        assert spec_file.exists(), "kensa.spec must exist in repo root"
        content = spec_file.read_text()
        assert (
            "%pyproject_wheel" in content
        ), "kensa.spec must use %pyproject_wheel macro"
        assert (
            "%pyproject_install" in content
        ), "kensa.spec must use %pyproject_install macro"
        assert (
            "pyproject-rpm-macros" in content
        ), "kensa.spec must list pyproject-rpm-macros as BuildRequires"

    def test_ac5_rpm_data_directories_installed(self):
        """AC-5/AC-6: kensa.spec installs rules/, schema/, mappings/ and config with noreplace."""
        spec_file = REPO_ROOT / "kensa.spec"
        content = spec_file.read_text()
        for data_dir in ["rules", "schema", "mappings"]:
            assert (
                data_dir in content
            ), f"kensa.spec must install {data_dir}/ to datadir"
        assert (
            "%config(noreplace)" in content
        ), "kensa.spec must mark config files as %config(noreplace)"
        assert "defaults.yml" in content, "kensa.spec must install defaults.yml"

    def test_ac7_release_workflow_builds_rpms(self):
        """AC-7/AC-8: CI and release workflows contain RPM build jobs."""
        ci_yml = REPO_ROOT / ".github" / "workflows" / "ci.yml"
        release_yml = REPO_ROOT / ".github" / "workflows" / "release.yml"
        assert ci_yml.exists(), ".github/workflows/ci.yml must exist"
        assert release_yml.exists(), ".github/workflows/release.yml must exist"
        ci_content = ci_yml.read_text()
        release_content = release_yml.read_text()
        assert (
            "rpmbuild" in ci_content or "rpm" in ci_content
        ), "ci.yml must contain RPM build configuration"
        assert (
            "rpmbuild" in release_content
        ), "release.yml must contain rpmbuild commands"
