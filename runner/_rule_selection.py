"""Rule selection pipeline — loading, filtering, ordering, and framework resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rich.console import Console

from runner._host_runner import ControlContext
from runner.engine import load_rules
from runner.ordering import format_ordering_issues, order_rules

if TYPE_CHECKING:
    from runner._config import RuleConfig
    from runner.ordering import OrderingResult


@dataclass
class RuleSelection:
    """Result of the rule selection pipeline."""

    rules: list[dict]
    ordering: OrderingResult
    rule_to_section: dict[str, str]
    control_ctx: ControlContext | None
    config: RuleConfig | None = None
    cli_overrides: dict[str, Any] = field(default_factory=dict)
    framework: str | None = None


def _resolve_control(
    control: str,
    rule_list: list[dict],
    rule_path_is_single: bool,
    *,
    out: Console | None = None,
) -> tuple[list[dict], str | None, ControlContext | None]:
    """Resolve --control to a filtered rule list.

    Args:
        control: Control spec (e.g., "cis:1.1.2.4" or "1.1.2.4").
        rule_list: Full rule list to filter.
        rule_path_is_single: True if --rule was used (mutually exclusive).
        out: Console for output messages (None = suppress).

    Returns:
        Tuple of (filtered_rules, inferred_framework_id, control_ctx_or_none).

    Raises:
        ValueError: On invalid control spec or mutual exclusivity violation.

    """
    if rule_path_is_single:
        raise ValueError("--control and --rule are mutually exclusive")

    from runner.mappings import FrameworkIndex, load_all_mappings

    ctrl_mappings = load_all_mappings()
    index = FrameworkIndex.build(ctrl_mappings)

    resolved_rule_ids: list[str] = []
    expanded_mapping_id: str | None = None
    ambiguous = False

    if ":" in control:
        prefix, section_id = control.split(":", 1)
        if prefix in ctrl_mappings:
            resolved_rule_ids = index.query_by_control(control)
            expanded_mapping_id = prefix
        else:
            matching_ids = [mid for mid in ctrl_mappings if mid.startswith(prefix)]
            if not matching_ids:
                available = ", ".join(sorted(ctrl_mappings.keys()))
                raise ValueError(
                    f"No mapping matches prefix: {prefix}\nAvailable: {available}"
                )
            for mid in matching_ids:
                full_spec = f"{mid}:{section_id}"
                resolved_rule_ids.extend(index.query_by_control(full_spec))
            resolved_rule_ids = list(set(resolved_rule_ids))
            if len(matching_ids) == 1:
                expanded_mapping_id = matching_ids[0]
            else:
                ambiguous = True
    else:
        resolved_rule_ids = index.query_by_control(control)
        ambiguous = True

    if not resolved_rule_ids:
        # Build suggestion message
        msg = f"No rules found for control: {control}"
        section = control.split(":", 1)[-1]
        parts = section.split(".")
        for depth in range(len(parts) - 1, 0, -1):
            prefix_section = ".".join(parts[:depth])
            nearby = index.query_by_control(
                f"{expanded_mapping_id}:{prefix_section}"
                if expanded_mapping_id
                else prefix_section,
                prefix_match=True,
            )
            if nearby:
                nearby_controls = []
                for key in sorted(index.controls_to_rules):
                    _, sid = key.split(":", 1)
                    if sid.startswith(prefix_section + ".") or sid == prefix_section:
                        if expanded_mapping_id:
                            mid = key.split(":", 1)[0]
                            if mid == expanded_mapping_id:
                                nearby_controls.append(sid)
                        else:
                            nearby_controls.append(sid)
                if nearby_controls:
                    sample = nearby_controls[:5]
                    hint = ", ".join(sample)
                    if len(nearby_controls) > 5:
                        hint += f", ... ({len(nearby_controls)} total)"
                    msg += f"\nNearby: {hint}"
                break
        raise ValueError(msg)

    resolved_set = set(resolved_rule_ids)
    filtered = [r for r in rule_list if r["id"] in resolved_set]

    if not filtered:
        raise ValueError(
            f"Control {control} resolved to rules {resolved_rule_ids}, "
            "but none found in rules directory."
        )

    control_ctx: ControlContext | None = None
    if ambiguous:
        control_ctx = ControlContext(
            control=control, mappings=ctrl_mappings, index=index
        )

    if out:
        out.print(f"[dim]Control: {control} → {len(filtered)} rule(s)[/dim]")

    return filtered, expanded_mapping_id, control_ctx


def _apply_framework_filter(
    framework: str,
    rule_list: list[dict],
    *,
    out: Console | None = None,
) -> tuple[list[dict], dict[str, str]]:
    """Filter rules to those in a specific framework mapping.

    Args:
        framework: Framework mapping ID (e.g., "cis-rhel9-v2.0.0").
        rule_list: Rules to filter.
        out: Console for output messages (None = suppress).

    Returns:
        Tuple of (filtered_rules, rule_to_section mapping).

    Raises:
        ValueError: If framework is unknown or no rules match.

    """
    from runner.mappings import (
        build_rule_to_section_map,
        load_all_mappings,
        rules_for_framework,
    )

    mappings = load_all_mappings()
    if framework not in mappings:
        available = ", ".join(sorted(mappings.keys()))
        raise ValueError(
            f"Unknown framework: {framework}\nAvailable: {available}, auto"
        )

    mapping = mappings[framework]
    filtered = rules_for_framework(mapping, rule_list)
    rule_to_section = build_rule_to_section_map(mapping)

    if out:
        out.print(f"[dim]Framework: {mapping.title}[/dim]")
        out.print(f"[dim]Sections: {mapping.implemented_count} implemented[/dim]")

    if not filtered:
        raise ValueError(f"No rules from {framework} matched the given filters.")

    return filtered, rule_to_section


def select_rules(
    rules_path: str | None,
    rule_path: str | None,
    severity: tuple[str, ...],
    tag: tuple[str, ...],
    category: str | None,
    *,
    framework: str | None = None,
    var: tuple[str, ...] = (),
    control: str | None = None,
    config_dir: str | None = None,
    out: Console | None = None,
) -> RuleSelection:
    """Top-level rule selection pipeline.

    Replaces _load_rule_list(). Loads rules, applies filters, resolves
    controls and frameworks, and orders by dependencies.

    Variable resolution is deferred to per-host execution time so
    different hosts can receive different variable values based on
    group/host overrides.

    Args:
        rules_path: Path to rules directory (--rules).
        rule_path: Path to single rule file (--rule).
        severity: Severity filters.
        tag: Tag filters.
        category: Category filter.
        framework: Framework ID for filtering/ordering ("auto" deferred).
        var: Variable overrides ("key=value" strings).
        control: Control spec (e.g., "cis:1.1.2.4").
        config_dir: Path to config directory (--config-dir).
        out: Console for output (None = suppress).

    Returns:
        RuleSelection with ordered rules, ordering info, section mapping,
        config, and optional ControlContext.

    Raises:
        ValueError: On invalid arguments or empty results.
        FileNotFoundError: If rules path doesn't exist.

    """
    from runner._config import load_config, parse_var_overrides

    path = rule_path or rules_path
    if not path:
        from runner.paths import get_rules_path

        path = str(get_rules_path())

    # Parse CLI variable overrides
    cli_overrides = parse_var_overrides(var)

    # Load variable configuration from config directory
    config = load_config(config_dir)

    # Load and filter rules
    rule_list = load_rules(
        path,
        severity=list(severity) if severity else None,
        tags=list(tag) if tag else None,
        category=category,
    )

    # NOTE: Variable resolution is deferred to per-host execution time.
    # The config and cli_overrides are stored on RuleSelection and
    # applied in execute_on_host() / the sequential CLI loop so that
    # per-group and per-host overrides can take effect.

    if not rule_list:
        raise ValueError("No rules matched the given filters.")

    # Resolve --control
    control_ctx: ControlContext | None = None
    inferred_framework: str | None = None
    if control:
        rule_list, inferred_framework, control_ctx = _resolve_control(
            control, rule_list, rule_path_is_single=bool(rule_path), out=out
        )
        # Infer framework from control spec if not explicitly set
        if inferred_framework and not framework:
            framework = inferred_framework

    # Apply framework filter
    rule_to_section: dict[str, str] = {}
    if framework and framework != "auto":
        rule_list, rule_to_section = _apply_framework_filter(
            framework, rule_list, out=out
        )
    elif framework == "auto" and out:
        out.print("[dim]Framework: auto (will detect from platform)[/dim]")

    # Order by dependencies
    ordering_result = order_rules(rule_list)

    # Report ordering issues
    if out:
        for msg in format_ordering_issues(ordering_result):
            if msg.startswith("[ERROR]"):
                out.print(f"[red]{msg}[/red]")
            elif msg.startswith("[WARNING]"):
                out.print(f"[yellow]{msg}[/yellow]")
            else:
                out.print(f"[dim]{msg}[/dim]")

    # Abort on cycles
    if ordering_result.cycles:
        raise ValueError("Circular dependencies detected. Cannot proceed.")

    return RuleSelection(
        rules=ordering_result.ordered,
        ordering=ordering_result,
        rule_to_section=rule_to_section,
        control_ctx=control_ctx,
        config=config,
        cli_overrides=cli_overrides,
        framework=framework if framework != "auto" else None,
    )


def apply_auto_framework(
    rule_list: list[dict],
    platform,
    *,
    out: Console | None = None,
) -> tuple[list[dict], dict[str, str]]:
    """Apply automatic framework selection based on detected platform.

    Args:
        rule_list: Full list of rules (unfiltered by framework).
        platform: Detected PlatformInfo from host.
        out: Console for output (None = suppress).

    Returns:
        Tuple of (filtered_rules, rule_to_section mapping).
        If no applicable frameworks found, returns original rules with empty mapping.

    """
    from runner.mappings import get_applicable_mappings, load_all_mappings
    from runner.ordering import order_rules

    if platform is None:
        if out:
            out.print(
                "[yellow]Warning: Could not detect platform, running all rules[/yellow]"
            )
        return rule_list, {}

    mappings = load_all_mappings()
    applicable = get_applicable_mappings(
        mappings,
        family=platform.family,
        version=platform.version,
    )

    if not applicable:
        if out:
            out.print(
                f"[yellow]Warning: No frameworks found for "
                f"{platform.family} {platform.version}[/yellow]"
            )
        return rule_list, {}

    # Collect rules from all applicable frameworks (union, deduplicated)
    framework_rule_ids: set[str] = set()
    rule_to_section: dict[str, str] = {}

    for mapping in applicable:
        for section_id, entry in mapping.sections.items():
            for rid in entry.metadata.get("rules", []):
                framework_rule_ids.add(rid)
                if rid not in rule_to_section:
                    rule_to_section[rid] = section_id

    filtered_rules = [r for r in rule_list if r["id"] in framework_rule_ids]

    if out:
        framework_names = ", ".join(m.id for m in applicable)
        out.print(f"[dim]Auto-selected frameworks: {framework_names}[/dim]")
        out.print(f"[dim]Matched {len(filtered_rules)} rules[/dim]")

    if not filtered_rules:
        if out:
            out.print(
                "[yellow]Warning: No rules matched auto-selected frameworks[/yellow]"
            )
        return rule_list, {}

    ordering_result = order_rules(filtered_rules)
    return ordering_result.ordered, rule_to_section
