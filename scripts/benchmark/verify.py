"""Ground truth verification helpers (Phase 4 placeholder)."""

from __future__ import annotations


def generate_verification_commands(
    control_id: str,
    tool_results: dict,
) -> list[str]:
    """Generate SSH commands to verify ground truth for a control.

    This is a Phase 4 feature placeholder. In Phase 4 this will
    generate targeted commands based on disagreements.

    Args:
        control_id: Framework control identifier.
        tool_results: Map of tool_name -> ToolControlResult.

    Returns:
        List of shell commands to run on the target host.

    """
    return []
