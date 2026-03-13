"""SpecDerived tests for rule validator CLI.

See specs/internal/rule_validator_cli.spec.yaml for specification.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


class TestRuleValidatorCLISpecDerived:
    """Spec-derived tests for rule validator CLI."""

    def test_ac1_importable_as_module(self):
        """AC-1: schema.validate is importable as a module from the repo root."""
        result = subprocess.run(
            [sys.executable, "-m", "schema.validate", "--help"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0

    def test_ac2_executable_as_direct_script(self):
        """AC-2: schema/validate.py is executable as a direct script from the repo root."""
        result = subprocess.run(
            [sys.executable, "schema/validate.py", "--help"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_ac3_docstring_documents_invocation(self):
        """AC-3: The docstring documents both invocation methods correctly."""
        validate_py = (REPO_ROOT / "schema" / "validate.py").read_text()
        assert (
            "python3 schema/validate.py" in validate_py
            or "python schema/validate.py" in validate_py
        )
        assert (
            "python3 -m schema.validate" in validate_py
            or "python -m schema.validate" in validate_py
        )
