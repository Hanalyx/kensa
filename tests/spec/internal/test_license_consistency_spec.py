"""SpecDerived tests for license consistency.

See specs/internal/license_consistency.spec.yaml for specification.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestLicenseConsistencySpecDerived:
    """Spec-derived tests for license consistency."""

    def test_ac1_pyproject_license_is_bsl(self):
        """AC-1: pyproject.toml license field is BSL-1.1."""
        pyproject = (REPO_ROOT / "pyproject.toml").read_text()
        # Match the TOML line: license = "BSL-1.1"
        assert 'license = "BSL-1.1"' in pyproject

    def test_ac2_pyproject_classifiers_no_mit(self):
        """AC-2: pyproject.toml classifiers do not contain any MIT license classifier."""
        pyproject = (REPO_ROOT / "pyproject.toml").read_text()
        assert "MIT License" not in pyproject

    def test_ac3_license_file_contains_bsl(self):
        """AC-3: LICENSE file contains Business Source License 1.1."""
        license_text = (REPO_ROOT / "LICENSE").read_text()
        assert "Business Source License 1.1" in license_text
