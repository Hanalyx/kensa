"""Spec-derived tests for rule capability validation.

See specs/internal/rule_capability_validation.spec.yaml for specification.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from schema.validators.rule import validate_rule_business


def _make_rule(when_value, rule_id="test-rule"):
    """Build a minimal rule dict with a when: field."""
    impls = [
        {
            "when": when_value,
            "check": {"method": "command"},
            "remediation": {"mechanism": "manual"},
        },
        {
            "default": True,
            "check": {"method": "command"},
            "remediation": {"mechanism": "manual"},
        },
    ]
    return {
        "id": rule_id,
        "category": "test",
        "implementations": impls,
    }


def _validate_with_caps(rule, caps):
    """Run validate_rule_business with mocked capabilities."""
    import schema.validators.rule as mod

    # Reset cache so our mock takes effect
    mod._KNOWN_CAPABILITIES = None
    mod._CAPABILITIES_LOADED = False

    with patch.object(mod, "_get_known_capabilities", return_value=caps):
        filepath = Path(f"rules/test/{rule['id']}.yml")
        return validate_rule_business(rule, filepath)


class TestCapabilityValidationSpecDerived:
    """Spec-derived tests for rule capability validation.

    Source spec: specs/internal/rule_capability_validation.spec.yaml (5 ACs)
    """

    def test_ac1_undefined_capability_detected(self):
        """AC-1: Undefined capability in `when: capname` is detected as a warning."""
        rule = _make_rule("nonexistent_cap")
        errors = _validate_with_caps(rule, {"sshd_config_d", "gdm"})

        cap_warnings = [e for e in errors if e.code == "unknown-capability"]
        assert len(cap_warnings) == 1
        assert "nonexistent_cap" in cap_warnings[0].message
        assert cap_warnings[0].severity == "warning"

    def test_ac2_valid_capability_no_warning(self):
        """AC-2: Valid capability in `when: capname` produces no warning."""
        rule = _make_rule("sshd_config_d")
        errors = _validate_with_caps(rule, {"sshd_config_d", "gdm"})

        cap_warnings = [e for e in errors if e.code == "unknown-capability"]
        assert len(cap_warnings) == 0

    def test_ac3_all_condition_validates_items(self):
        """AC-3: Complex `when: {all: [...]}` validates all items."""
        rule = _make_rule({"all": ["sshd_config_d", "bogus_cap"]})
        errors = _validate_with_caps(rule, {"sshd_config_d", "gdm"})

        cap_warnings = [e for e in errors if e.code == "unknown-capability"]
        assert len(cap_warnings) == 1
        assert "bogus_cap" in cap_warnings[0].message

    def test_ac4_any_condition_validates_items(self):
        """AC-4: Complex `when: {any: [...]}` validates all items."""
        rule = _make_rule({"any": ["missing_a", "missing_b"]})
        errors = _validate_with_caps(rule, {"sshd_config_d"})

        cap_warnings = [e for e in errors if e.code == "unknown-capability"]
        assert len(cap_warnings) == 2

    def test_ac5_capabilities_loaded_from_registry(self):
        """AC-5: Known capabilities are loaded from runner.detect.CAPABILITY_PROBES and cached."""
        from schema.validators.rule import _get_known_capabilities

        caps = _get_known_capabilities()
        assert caps is not None
        assert "sshd_config_d" in caps
        assert "gdm" in caps
        assert "authselect" in caps
