"""Host execution lifecycle — connect, detect, filter, run, collect."""

from __future__ import annotations

from dataclasses import dataclass, field
from io import StringIO
from typing import TYPE_CHECKING, Any, Literal

from rich.console import Console

from runner.detect import detect_capabilities, detect_platform
from runner.engine import (
    evaluate_rule,
    remediate_rule,
    rule_applies_to_platform,
    select_implementation,
)
from runner.ordering import should_skip_rule
from runner.ssh import SSHSession

if TYPE_CHECKING:
    from runner._config import RuleConfig
    from runner.inventory import HostInfo
    from runner.mappings import FrameworkIndex


# ── Data types ─────────────────────────────────────────────────────────────


@dataclass
class HostCheckResult:
    """Results from checking a single host."""

    hostname: str
    success: bool
    error: str | None = None
    platform: object | None = None
    capabilities: dict = field(default_factory=dict)
    pass_count: int = 0
    fail_count: int = 0
    skip_count: int = 0
    rule_results: list = field(default_factory=list)
    output: str = ""


@dataclass
class HostRemediateResult:
    """Results from remediating a single host."""

    hostname: str
    success: bool
    error: str | None = None
    platform: object | None = None
    capabilities: dict = field(default_factory=dict)
    pass_count: int = 0
    fail_count: int = 0
    fixed_count: int = 0
    skip_count: int = 0
    rolled_back_count: int = 0
    rule_results: list = field(default_factory=list)
    output: str = ""


@dataclass
class HostDetectResult:
    """Results from detecting capabilities on a single host."""

    hostname: str
    success: bool
    error: str | None = None
    platform: object | None = None
    capabilities: dict = field(default_factory=dict)
    output: str = ""


@dataclass
class ControlContext:
    """Metadata from --control resolution for per-host platform filtering."""

    control: str
    mappings: dict  # mapping_id -> FrameworkMapping
    index: FrameworkIndex


@dataclass
class HostRunConfig:
    """Configuration for a host execution run."""

    mode: Literal["check", "remediate"]
    verbose: bool = False
    dry_run: bool = False
    rollback_on_failure: bool = False
    rule_to_section: dict[str, str] | None = None
    control_ctx: ControlContext | None = None
    capability_overrides: dict[str, bool] = field(default_factory=dict)
    rule_config: RuleConfig | None = None
    cli_overrides: dict[str, Any] = field(default_factory=dict)
    framework: str | None = None


# ── SSH connection ─────────────────────────────────────────────────────────


def connect(
    hi: HostInfo,
    password: str | None,
    *,
    sudo: bool = False,
    strict_host_keys: bool = False,
) -> SSHSession:
    """Create an SSHSession from a HostInfo."""
    return SSHSession(
        hostname=hi.hostname,
        port=hi.port,
        user=hi.user,
        key_path=hi.key_path,
        password=password,
        sudo=sudo,
        strict_host_keys=strict_host_keys,
    )


# ── Output helpers ─────────────────────────────────────────────────────────


def print_platform(platform, out: Console) -> None:
    """Print detected platform info."""
    if platform is None:
        out.print(
            "  [yellow]Platform: unknown (could not read /etc/os-release)[/yellow]"
        )
    else:
        out.print(f"  Platform: {platform.family.upper()} {platform.version}")


def print_caps_verbose(caps: dict[str, bool], out: Console, verbose: bool) -> None:
    """In verbose mode, print which capabilities were detected."""
    if not verbose:
        return
    active = sorted(k for k, v in caps.items() if v)
    if active:
        out.print(f"  [dim]capabilities: {', '.join(active)}[/dim]")
    else:
        out.print("  [dim]capabilities: (none detected)[/dim]")


def print_impl_verbose(
    rule: dict, caps: dict[str, bool], out: Console, verbose: bool
) -> None:
    """In verbose mode, print which implementation was selected for a rule."""
    if not verbose:
        return
    impl = select_implementation(rule, caps)
    rule_id = rule["id"]
    if impl is None:
        out.print(f"  [dim]  {rule_id}: no matching implementation[/dim]")
    elif impl.get("default"):
        out.print(f"  [dim]  {rule_id}: using default implementation[/dim]")
    else:
        gate = impl.get("when", "?")
        out.print(f"  [dim]  {rule_id}: matched gate [bold]{gate}[/bold][/dim]")


def format_section_prefix(section: str | None) -> str:
    """Format section prefix for terminal output."""
    if section:
        return f"[dim]{section:<10s}[/dim]"
    return ""


def platform_constraint_str(rule: dict) -> str:
    """Format a rule's platforms: field for display in skip messages."""
    platforms = rule.get("platforms", [])
    parts = []
    for p in platforms:
        fam = p.get("family", "?")
        min_v = p.get("min_version")
        max_v = p.get("max_version")
        if min_v is not None and max_v is not None:
            parts.append(f"{fam} {min_v}-{max_v}")
        elif min_v is not None:
            parts.append(f"{fam} >={min_v}")
        elif max_v is not None:
            parts.append(f"{fam} <={max_v}")
        else:
            parts.append(fam)
    return ", ".join(parts) if parts else "unknown"


# ── Capability overrides ──────────────────────────────────────────────────


def apply_capability_overrides(
    detected: dict[str, bool],
    overrides: dict[str, bool],
    out: Console,
    verbose: bool,
) -> dict[str, bool]:
    """Apply manual overrides to detected capabilities."""
    if not overrides:
        return detected

    result = detected.copy()
    for key, value in overrides.items():
        if key not in detected:
            out.print(f"[yellow]Warning:[/yellow] Unknown capability '{key}'")
        if verbose and detected.get(key) != value:
            out.print(
                f"    [magenta]override:[/magenta] {key} = {value} (detected: {detected.get(key)})"
            )
        result[key] = value
    return result


# ── Platform filtering ────────────────────────────────────────────────────


def platform_filter_control_rules(
    rule_list: list[dict],
    control_ctx: ControlContext,
    platform,
) -> list[dict]:
    """Narrow control-resolved rules to platform-applicable mappings."""
    from runner.mappings import get_applicable_mappings

    applicable = get_applicable_mappings(
        control_ctx.mappings, platform.family, platform.version
    )
    applicable_ids = {m.id for m in applicable}

    # Re-resolve control against only applicable mappings
    control = control_ctx.control
    resolved_ids: set[str] = set()
    if ":" in control:
        prefix, section_id = control.split(":", 1)
        for mid in applicable_ids:
            if mid == prefix or mid.startswith(prefix):
                full_spec = f"{mid}:{section_id}"
                resolved_ids.update(control_ctx.index.query_by_control(full_spec))
    else:
        for mid in applicable_ids:
            full_spec = f"{mid}:{control}"
            resolved_ids.update(control_ctx.index.query_by_control(full_spec))

    if not resolved_ids:
        return rule_list  # fall back to unfiltered if no platform match

    return [r for r in rule_list if r["id"] in resolved_ids]


# ── Check execution ──────────────────────────────────────────────────────


def run_checks(
    ssh,
    rule_list,
    caps,
    platform,
    *,
    out: Console,
    verbose: bool,
    rule_to_section: dict[str, str] | None = None,
):
    """Run checks for a single host. Returns (pass, fail, skip, rule_results)."""
    from runner._types import RuleResult

    host_pass = host_fail = host_skip = 0
    rule_results = []
    failed_rules: set[str] = set()
    rule_to_section = rule_to_section or {}

    for r in rule_list:
        rule_id = r["id"]

        section = rule_to_section.get(rule_id)
        section_prefix = format_section_prefix(section)

        skip, skip_reason = should_skip_rule(rule_id, rule_list, failed_rules)
        if skip:
            host_skip += 1
            out.print(
                f"  {section_prefix}[dim]SKIP[/dim]  {rule_id:<40s} {r.get('title', rule_id)}  "
                f"[dim]({skip_reason})[/dim]"
            )
            rule_results.append(
                RuleResult(
                    rule_id=rule_id,
                    title=r.get("title", rule_id),
                    severity=r.get("severity", "medium"),
                    passed=False,
                    skipped=True,
                    skip_reason=skip_reason,
                    framework_section=section,
                )
            )
            failed_rules.add(rule_id)
            continue

        if platform and not rule_applies_to_platform(
            r, platform.family, platform.version
        ):
            host_skip += 1
            out.print(
                f"  {section_prefix}[dim]SKIP[/dim]  {rule_id:<40s} {r.get('title', rule_id)}  "
                f"[dim](platform: requires {platform_constraint_str(r)})[/dim]"
            )
            rule_results.append(
                RuleResult(
                    rule_id=rule_id,
                    title=r.get("title", rule_id),
                    severity=r.get("severity", "medium"),
                    passed=False,
                    skipped=True,
                    skip_reason=f"platform: requires {platform_constraint_str(r)}",
                    framework_section=section,
                )
            )
            continue

        print_impl_verbose(r, caps, out, verbose)
        result = evaluate_rule(ssh, r, caps)
        result.framework_section = section
        rule_results.append(result)
        if result.skipped:
            host_skip += 1
            out.print(
                f"  {section_prefix}[dim]SKIP[/dim]  {result.rule_id:<40s} {result.title}  [dim]({result.skip_reason})[/dim]"
            )
        elif result.passed:
            host_pass += 1
            out.print(
                f"  {section_prefix}[green]PASS[/green]  {result.rule_id:<40s} {result.title}"
            )
        else:
            host_fail += 1
            failed_rules.add(rule_id)
            detail = f"  [dim]{result.detail}[/dim]" if result.detail else ""
            out.print(
                f"  {section_prefix}[red]FAIL[/red]  {result.rule_id:<40s} {result.title}{detail}"
            )
    return host_pass, host_fail, host_skip, rule_results


# ── Remediation execution ────────────────────────────────────────────────


def run_remediation(
    ssh,
    rule_list,
    caps,
    platform,
    *,
    out: Console,
    verbose: bool,
    dry_run,
    rollback_on_failure=False,
    rule_to_section: dict[str, str] | None = None,
):
    """Run remediation for a single host. Returns (pass, fail, fixed, skip, rolled_back, rule_results)."""
    from runner._types import RuleResult

    host_pass = host_fail = host_fixed = host_skip = host_rolled_back = 0
    rule_results = []
    failed_rules: set[str] = set()
    rule_to_section = rule_to_section or {}

    for r in rule_list:
        rule_id = r["id"]

        section = rule_to_section.get(rule_id)
        section_prefix = format_section_prefix(section)

        skip, skip_reason = should_skip_rule(rule_id, rule_list, failed_rules)
        if skip:
            host_skip += 1
            out.print(
                f"  {section_prefix}[dim]SKIP[/dim]  {rule_id:<40s} {r.get('title', rule_id)}  "
                f"[dim]({skip_reason})[/dim]"
            )
            rule_results.append(
                RuleResult(
                    rule_id=rule_id,
                    title=r.get("title", rule_id),
                    severity=r.get("severity", "medium"),
                    passed=False,
                    skipped=True,
                    skip_reason=skip_reason,
                    framework_section=section,
                )
            )
            failed_rules.add(rule_id)
            continue

        if platform and not rule_applies_to_platform(
            r, platform.family, platform.version
        ):
            host_skip += 1
            out.print(
                f"  {section_prefix}[dim]SKIP[/dim]  {rule_id:<40s} {r.get('title', rule_id)}  "
                f"[dim](platform: requires {platform_constraint_str(r)})[/dim]"
            )
            rule_results.append(
                RuleResult(
                    rule_id=rule_id,
                    title=r.get("title", rule_id),
                    severity=r.get("severity", "medium"),
                    passed=False,
                    skipped=True,
                    skip_reason=f"platform: requires {platform_constraint_str(r)}",
                    framework_section=section,
                )
            )
            continue

        print_impl_verbose(r, caps, out, verbose)
        result = remediate_rule(
            ssh,
            r,
            caps,
            dry_run=dry_run,
            rollback_on_failure=rollback_on_failure,
        )
        result.framework_section = section
        rule_results.append(result)
        if result.skipped:
            host_skip += 1
            out.print(
                f"  {section_prefix}[dim]SKIP[/dim]  {result.rule_id:<40s} {result.title}  [dim]({result.skip_reason})[/dim]"
            )
        elif result.passed and not result.remediated:
            host_pass += 1
            out.print(
                f"  {section_prefix}[green]PASS[/green]  {result.rule_id:<40s} {result.title}"
            )
        elif result.passed and result.remediated:
            host_fixed += 1
            detail = (
                f"  [dim]{result.remediation_detail}[/dim]"
                if result.remediation_detail
                else ""
            )
            tag = "[yellow]DRY [/yellow]" if dry_run else "[yellow]FIXED[/yellow]"
            out.print(
                f"  {section_prefix}{tag} {result.rule_id:<40s} {result.title}{detail}"
            )
        else:
            host_fail += 1
            failed_rules.add(rule_id)
            suffix = "  [magenta](rolled back)[/magenta]" if result.rolled_back else ""
            detail = (
                f"  [dim]{result.remediation_detail or result.detail}[/dim]"
                if (result.remediation_detail or result.detail)
                else ""
            )
            out.print(
                f"  {section_prefix}[red]FAIL[/red]  {result.rule_id:<40s} {result.title}{detail}{suffix}"
            )
            if result.rolled_back:
                host_rolled_back += 1
            if verbose and result.step_results:
                total_steps = len(result.step_results)
                for sr in result.step_results:
                    status = "[green]ok[/green]" if sr.success else "[red]FAIL[/red]"
                    out.print(
                        f"    step {sr.step_index + 1}/{total_steps}: {sr.mechanism}  [{status}]  {sr.detail[:80]}"
                    )
                if result.rollback_results:
                    for rb in result.rollback_results:
                        status = (
                            "[green]ok[/green]" if rb.success else "[dim]skipped[/dim]"
                        )
                        out.print(
                            f"    rollback step {rb.step_index}: {rb.mechanism}  [{status}]  {rb.detail[:80]}"
                        )
    return host_pass, host_fail, host_fixed, host_skip, host_rolled_back, rule_results


# ── Unified host execution ───────────────────────────────────────────────


def execute_on_host(
    hi: HostInfo,
    password: str | None,
    sudo: bool,
    strict_host_keys: bool,
    rule_list: list[dict],
    config: HostRunConfig,
    out: Console,
) -> HostCheckResult | HostRemediateResult:
    """Execute check or remediation on a single host.

    Replaces _check_host() and _remediate_host(). Handles connection,
    detection, filtering, execution, and result collection.
    """
    out.print()
    out.rule(f"[bold]Host: {hi.hostname}[/bold]")

    try:
        with connect(hi, password, sudo=sudo, strict_host_keys=strict_host_keys) as ssh:
            platform = detect_platform(ssh)
            detected_caps = detect_capabilities(ssh, verbose=config.verbose)
            caps = apply_capability_overrides(
                detected_caps, config.capability_overrides, out, config.verbose
            )
            print_platform(platform, out)
            print_caps_verbose(caps, out, config.verbose)

            # Platform-aware control filtering
            host_rules = rule_list
            if config.control_ctx and platform:
                host_rules = platform_filter_control_rules(
                    rule_list, config.control_ctx, platform
                )

            # Per-host variable resolution
            if config.rule_config:
                from runner._config import resolve_variables

                host_rules = [
                    resolve_variables(
                        r,
                        config.rule_config,
                        framework=config.framework,
                        cli_overrides=config.cli_overrides,
                        hostname=hi.hostname,
                        groups=hi.groups,
                        strict=True,
                    )
                    for r in host_rules
                ]

            if config.mode == "check":
                host_pass, host_fail, host_skip, rule_results = run_checks(
                    ssh,
                    host_rules,
                    caps,
                    platform,
                    out=out,
                    verbose=config.verbose,
                    rule_to_section=config.rule_to_section,
                )
            else:
                (
                    host_pass,
                    host_fail,
                    host_fixed,
                    host_skip,
                    host_rolled_back,
                    rule_results,
                ) = run_remediation(
                    ssh,
                    host_rules,
                    caps,
                    platform,
                    out=out,
                    verbose=config.verbose,
                    dry_run=config.dry_run,
                    rollback_on_failure=config.rollback_on_failure,
                    rule_to_section=config.rule_to_section,
                )
    except Exception as exc:
        out.print(f"  [red]Connection failed:[/red] {exc}")
        if config.mode == "check":
            return HostCheckResult(
                hostname=hi.hostname,
                success=False,
                error=str(exc),
                output=out.file.getvalue() if isinstance(out.file, StringIO) else "",
            )
        return HostRemediateResult(
            hostname=hi.hostname,
            success=False,
            error=str(exc),
            output=out.file.getvalue() if isinstance(out.file, StringIO) else "",
        )

    if config.mode == "check":
        total = host_pass + host_fail + host_skip
        out.print(
            f"  [bold]{total} rules[/bold] | "
            f"[green]{host_pass} pass[/green] | "
            f"[red]{host_fail} fail[/red]"
            + (f" | [dim]{host_skip} skip[/dim]" if host_skip else "")
        )
        return HostCheckResult(
            hostname=hi.hostname,
            success=True,
            platform=platform,
            capabilities=caps,
            pass_count=host_pass,
            fail_count=host_fail,
            skip_count=host_skip,
            rule_results=rule_results,
            output=out.file.getvalue() if isinstance(out.file, StringIO) else "",
        )

    # Remediate summary
    total = host_pass + host_fail + host_fixed + host_skip
    summary = (
        f"  [bold]{total} rules[/bold] | "
        f"[green]{host_pass} pass[/green] | "
        f"[yellow]{host_fixed} fixed[/yellow] | "
        f"[red]{host_fail} fail[/red]"
    )
    if host_skip:
        summary += f" | [dim]{host_skip} skip[/dim]"
    if host_rolled_back:
        summary += f" | [magenta]{host_rolled_back} rolled back[/magenta]"
    out.print(summary)

    return HostRemediateResult(
        hostname=hi.hostname,
        success=True,
        platform=platform,
        capabilities=caps,
        pass_count=host_pass,
        fail_count=host_fail,
        fixed_count=host_fixed,
        skip_count=host_skip,
        rolled_back_count=host_rolled_back,
        rule_results=rule_results,
        output=out.file.getvalue() if isinstance(out.file, StringIO) else "",
    )
