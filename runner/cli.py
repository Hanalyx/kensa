"""Aegis CLI — detect, check, and remediate compliance rules over SSH."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from io import StringIO
from threading import Lock

import click
from rich.console import Console
from rich.table import Table

from runner.detect import detect_capabilities, detect_platform
from runner.engine import evaluate_rule, load_rules, remediate_rule, rule_applies_to_platform, select_implementation
from runner.inventory import HostInfo, resolve_targets
from runner.ssh import SSHSession

console = Console()
verbose_mode = False
print_lock = Lock()  # Ensures atomic host output in parallel mode


# ── Host result containers ─────────────────────────────────────────────────


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
    output: str = ""  # Buffered console output


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
    output: str = ""  # Buffered console output


@dataclass
class HostDetectResult:
    """Results from detecting capabilities on a single host."""

    hostname: str
    success: bool
    error: str | None = None
    platform: object | None = None
    capabilities: dict = field(default_factory=dict)
    output: str = ""  # Buffered console output


def _parse_capability_overrides(flags: tuple[str, ...]) -> dict[str, bool]:
    """Parse -C key=value flags into a dict."""
    overrides = {}
    for flag in flags:
        if "=" not in flag:
            console.print(f"[red]Error:[/red] Invalid capability format: {flag} (expected KEY=VALUE)")
            sys.exit(1)
        key, value = flag.split("=", 1)
        if value.lower() == "true":
            overrides[key] = True
        elif value.lower() == "false":
            overrides[key] = False
        else:
            console.print(f"[red]Error:[/red] Invalid capability value: {value} (expected true/false)")
            sys.exit(1)
    return overrides


def _apply_capability_overrides(
    detected: dict[str, bool],
    overrides: dict[str, bool],
) -> dict[str, bool]:
    """Apply manual overrides to detected capabilities."""
    if not overrides:
        return detected

    result = detected.copy()
    for key, value in overrides.items():
        if key not in detected:
            console.print(f"[yellow]Warning:[/yellow] Unknown capability '{key}'")
        if verbose_mode and detected.get(key) != value:
            console.print(f"    [magenta]override:[/magenta] {key} = {value} (detected: {detected.get(key)})")
        result[key] = value
    return result


def _apply_capability_overrides_quiet(
    detected: dict[str, bool],
    overrides: dict[str, bool],
    buf_console: Console,
    verbose: bool,
) -> dict[str, bool]:
    """Apply manual overrides to detected capabilities (buffered output version)."""
    if not overrides:
        return detected

    result = detected.copy()
    for key, value in overrides.items():
        if key not in detected:
            buf_console.print(f"[yellow]Warning:[/yellow] Unknown capability '{key}'")
        if verbose and detected.get(key) != value:
            buf_console.print(f"    [magenta]override:[/magenta] {key} = {value} (detected: {detected.get(key)})")
        result[key] = value
    return result


# ── Shared options ──────────────────────────────────────────────────────────

def target_options(f):
    """Common target/connection options for all subcommands."""
    f = click.option("--host", "-h", default=None, help="Target host(s), comma-separated")(f)
    f = click.option("--inventory", "-i", default=None, help="Ansible inventory file (INI/YAML) or host list")(f)
    f = click.option("--limit", "-l", default=None, help="Limit to group or host glob pattern")(f)
    f = click.option("--user", "-u", default=None, help="SSH username")(f)
    f = click.option("--key", "-k", default=None, help="SSH private key path")(f)
    f = click.option("--password", "-p", default=None, help="SSH password")(f)
    f = click.option("--port", "-P", default=22, type=int, help="SSH port (default: 22)")(f)
    f = click.option("--verbose", "-v", is_flag=True, help="Show capability detection and implementation selection")(f)
    f = click.option("--sudo", is_flag=True, help="Run all remote commands via sudo")(f)
    f = click.option("--capability", "-C", multiple=True, metavar="KEY=VALUE",
                     help="Override detected capability (e.g., -C sshd_config_d=false)")(f)
    f = click.option("--workers", "-w", default=1, type=click.IntRange(1, 50),
                     help="Number of parallel SSH connections (default: 1, max: 50)")(f)
    return f


def rule_options(f):
    """Rule selection options for check/remediate."""
    f = click.option("--rules", "-r", default=None, help="Path to rules directory (recursive)")(f)
    f = click.option("--rule", default=None, help="Path to single rule file")(f)
    f = click.option("--severity", "-s", multiple=True, help="Filter by severity (repeatable)")(f)
    f = click.option("--tag", "-t", multiple=True, help="Filter by tag (repeatable)")(f)
    f = click.option("--category", "-c", default=None, help="Filter by category")(f)
    return f


# ── CLI group ───────────────────────────────────────────────────────────────

MAIN_HELP_EPILOG = """
\b
Common Options (all commands):
  -h, --host TEXT          Target host(s), comma-separated
  -i, --inventory TEXT     Ansible inventory file (INI/YAML)
  -l, --limit TEXT         Limit to group or hostname glob
  -u, --user TEXT          SSH username
  -k, --key TEXT           SSH private key path
  -p, --password TEXT      SSH password
  -P, --port INTEGER       SSH port (default: 22)
  --sudo                   Run commands via sudo
  -w, --workers INTEGER    Parallel connections (1-50, default: 1)
  -v, --verbose            Show capability details
  -C, --capability K=V     Override capability (repeatable)

\b
Rule Options (check/remediate):
  -r, --rules PATH         Rules directory
  --rule PATH              Single rule file
  -s, --severity TEXT      Filter by severity (repeatable)
  -t, --tag TEXT           Filter by tag (repeatable)
  -c, --category TEXT      Filter by category

\b
Remediation Options:
  --dry-run                Preview without changes
  --rollback-on-failure    Auto-rollback on failure

\b
Examples:
  aegis detect --host 192.168.1.100 -u admin --sudo
  aegis check -i hosts.ini --sudo -r rules/ -w 4
  aegis remediate -i hosts.ini --sudo -r rules/ --dry-run
"""


@click.group(epilog=MAIN_HELP_EPILOG, context_settings={"max_content_width": 120})
@click.version_option(version="0.1.0", prog_name="aegis")
def main():
    """Aegis — SSH-based compliance test runner."""
    pass


# ── detect ──────────────────────────────────────────────────────────────────


@main.command()
@target_options
def detect(host, inventory, limit, user, key, password, port, verbose, sudo, capability, workers):
    """Probe capabilities on target hosts."""
    global verbose_mode
    verbose_mode = verbose
    hosts = _resolve_hosts(host, inventory, limit, user, key, port)
    overrides = _parse_capability_overrides(capability)

    if workers == 1:
        # Sequential execution - use direct console output (original behavior)
        for hi in hosts:
            _detect_host_sequential(hi, password, sudo, overrides, verbose)
    else:
        # Parallel execution - use buffered output
        with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
            futures = {
                pool.submit(_detect_host, hi, password, sudo, overrides, verbose): hi
                for hi in hosts
            }
            for future in as_completed(futures):
                result = future.result()
                with print_lock:
                    _print_detect_result(result, overrides)


def _detect_host_sequential(
    hi: HostInfo,
    password: str | None,
    sudo: bool,
    overrides: dict[str, bool],
    verbose: bool,
) -> None:
    """Run capability detection on a single host with direct console output."""
    console.rule(f"[bold]Host: {hi.hostname}[/bold]")

    try:
        with _connect(hi, password, sudo=sudo) as ssh:
            platform = detect_platform(ssh)
            detected_caps = detect_capabilities(ssh, verbose=verbose)
            caps = _apply_capability_overrides(detected_caps, overrides)
    except Exception as exc:
        console.print(f"  [red]Connection failed:[/red] {exc}")
        return

    _print_platform(platform)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Capability", min_width=28)
    table.add_column("Available", justify="center")

    for name, available in sorted(caps.items()):
        is_override = name in overrides and overrides[name] != detected_caps.get(name)
        if is_override:
            mark = f"[magenta]{'yes' if available else 'no'}[/magenta] (override)"
        else:
            mark = "[green]yes[/green]" if available else "[dim]no[/dim]"
        table.add_row(name, mark)

    console.print(table)
    console.print()


def _detect_host(
    hi: HostInfo,
    password: str | None,
    sudo: bool,
    overrides: dict[str, bool],
    verbose: bool,
) -> HostDetectResult:
    """Run capability detection on a single host. Returns results for later printing."""
    buf = StringIO()
    buf_console = Console(file=buf, force_terminal=True, width=120)

    buf_console.rule(f"[bold]Host: {hi.hostname}[/bold]")

    try:
        with _connect(hi, password, sudo=sudo) as ssh:
            platform = detect_platform(ssh)
            detected_caps = detect_capabilities(ssh, verbose=verbose)
            caps = _apply_capability_overrides_quiet(detected_caps, overrides, buf_console, verbose)
    except Exception as exc:
        buf_console.print(f"  [red]Connection failed:[/red] {exc}")
        return HostDetectResult(
            hostname=hi.hostname,
            success=False,
            error=str(exc),
            output=buf.getvalue(),
        )

    # Build platform line
    if platform is None:
        buf_console.print("  [yellow]Platform: unknown (could not read /etc/os-release)[/yellow]")
    else:
        buf_console.print(f"  Platform: {platform.family.upper()} {platform.version}")

    # Build capability table
    table = Table(show_header=True, header_style="bold")
    table.add_column("Capability", min_width=28)
    table.add_column("Available", justify="center")

    for name, available in sorted(caps.items()):
        is_override = name in overrides and overrides[name] != detected_caps.get(name)
        if is_override:
            mark = f"[magenta]{'yes' if available else 'no'}[/magenta] (override)"
        else:
            mark = "[green]yes[/green]" if available else "[dim]no[/dim]"
        table.add_row(name, mark)

    buf_console.print(table)
    buf_console.print()

    return HostDetectResult(
        hostname=hi.hostname,
        success=True,
        platform=platform,
        capabilities=caps,
        output=buf.getvalue(),
    )


def _print_detect_result(result: HostDetectResult, overrides: dict[str, bool]) -> None:
    """Print buffered detect result to console."""
    # Use sys.stdout.write for already-formatted ANSI output
    sys.stdout.write(result.output)
    sys.stdout.flush()


# ── check ───────────────────────────────────────────────────────────────────


@main.command()
@target_options
@rule_options
def check(host, inventory, limit, user, key, password, port, verbose, sudo, capability, workers, rules, rule, severity, tag, category):
    """Run compliance checks on target hosts."""
    global verbose_mode
    verbose_mode = verbose
    hosts = _resolve_hosts(host, inventory, limit, user, key, port)
    rule_list = _load_rule_list(rules, rule, severity, tag, category)
    overrides = _parse_capability_overrides(capability)

    if workers == 1:
        # Sequential execution - use direct console output (original behavior)
        total_pass = 0
        total_fail = 0
        total_skip = 0
        host_count = 0

        for hi in hosts:
            console.print()
            console.rule(f"[bold]Host: {hi.hostname}[/bold]")
            try:
                with _connect(hi, password, sudo=sudo) as ssh:
                    platform = detect_platform(ssh)
                    detected_caps = detect_capabilities(ssh, verbose=verbose)
                    caps = _apply_capability_overrides(detected_caps, overrides)
                    _print_platform(platform)
                    _print_caps_verbose(caps)
                    host_pass, host_fail, host_skip = _run_checks(ssh, rule_list, caps, platform)
            except Exception as exc:
                console.print(f"  [red]Connection failed:[/red] {exc}")
                continue

            host_count += 1
            total_pass += host_pass
            total_fail += host_fail
            total_skip += host_skip

            total = host_pass + host_fail + host_skip
            console.print(
                f"  [bold]{total} rules[/bold] | "
                f"[green]{host_pass} pass[/green] | "
                f"[red]{host_fail} fail[/red]"
                + (f" | [dim]{host_skip} skip[/dim]" if host_skip else "")
            )

        if host_count > 1:
            console.print()
            console.rule("[bold]Summary[/bold]")
            grand_total = total_pass + total_fail + total_skip
            console.print(
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[red]{total_fail} fail[/red]"
                + (f" | [dim]{total_skip} skip[/dim]" if total_skip else "")
            )
        console.print()
    else:
        # Parallel execution - use buffered output
        results: list[HostCheckResult] = []

        with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
            futures = {
                pool.submit(_check_host, hi, password, sudo, overrides, rule_list, verbose): hi
                for hi in hosts
            }
            for future in as_completed(futures):
                result = future.result()
                with print_lock:
                    _print_check_result(result)
                results.append(result)

        # Aggregate results
        successful_results = [r for r in results if r.success]
        total_pass = sum(r.pass_count for r in successful_results)
        total_fail = sum(r.fail_count for r in successful_results)
        total_skip = sum(r.skip_count for r in successful_results)
        host_count = len(successful_results)

        if host_count > 1:
            console.print()
            console.rule("[bold]Summary[/bold]")
            grand_total = total_pass + total_fail + total_skip
            console.print(
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[red]{total_fail} fail[/red]"
                + (f" | [dim]{total_skip} skip[/dim]" if total_skip else "")
            )
        console.print()


def _check_host(
    hi: HostInfo,
    password: str | None,
    sudo: bool,
    overrides: dict[str, bool],
    rule_list: list[dict],
    verbose: bool,
) -> HostCheckResult:
    """Run checks on a single host. Returns results for later printing."""
    buf = StringIO()
    buf_console = Console(file=buf, force_terminal=True, width=120)

    buf_console.print()
    buf_console.rule(f"[bold]Host: {hi.hostname}[/bold]")

    try:
        with _connect(hi, password, sudo=sudo) as ssh:
            platform = detect_platform(ssh)
            detected_caps = detect_capabilities(ssh, verbose=verbose)
            caps = _apply_capability_overrides_quiet(detected_caps, overrides, buf_console, verbose)

            # Print platform info
            if platform is None:
                buf_console.print("  [yellow]Platform: unknown (could not read /etc/os-release)[/yellow]")
            else:
                buf_console.print(f"  Platform: {platform.family.upper()} {platform.version}")

            # Print capabilities in verbose mode
            if verbose:
                active = sorted(k for k, v in caps.items() if v)
                if active:
                    buf_console.print(f"  [dim]capabilities: {', '.join(active)}[/dim]")
                else:
                    buf_console.print("  [dim]capabilities: (none detected)[/dim]")

            # Run checks
            host_pass, host_fail, host_skip = _run_checks_buffered(
                ssh, rule_list, caps, platform, buf_console, verbose
            )
    except Exception as exc:
        buf_console.print(f"  [red]Connection failed:[/red] {exc}")
        return HostCheckResult(
            hostname=hi.hostname,
            success=False,
            error=str(exc),
            output=buf.getvalue(),
        )

    # Print host summary
    total = host_pass + host_fail + host_skip
    buf_console.print(
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
        output=buf.getvalue(),
    )


def _print_check_result(result: HostCheckResult) -> None:
    """Print buffered check result to console."""
    # Use sys.stdout.write for already-formatted ANSI output
    sys.stdout.write(result.output)
    sys.stdout.flush()


def _run_checks_buffered(ssh, rule_list, caps, platform, buf_console, verbose):
    """Run checks for a single host with buffered output. Returns (pass, fail, skip) counts."""
    host_pass = host_fail = host_skip = 0
    for r in rule_list:
        if platform and not rule_applies_to_platform(r, platform.family, platform.version):
            host_skip += 1
            buf_console.print(
                f"  [dim]SKIP[/dim]  {r['id']:<40s} {r.get('title', r['id'])}  "
                f"[dim](platform: requires {_platform_constraint_str(r)})[/dim]"
            )
            continue
        # Verbose implementation selection
        if verbose:
            impl = select_implementation(r, caps)
            rule_id = r["id"]
            if impl is None:
                buf_console.print(f"  [dim]  {rule_id}: no matching implementation[/dim]")
            elif impl.get("default"):
                buf_console.print(f"  [dim]  {rule_id}: using default implementation[/dim]")
            else:
                gate = impl.get("when", "?")
                buf_console.print(f"  [dim]  {rule_id}: matched gate [bold]{gate}[/bold][/dim]")

        result = evaluate_rule(ssh, r, caps)
        if result.skipped:
            host_skip += 1
            buf_console.print(f"  [dim]SKIP[/dim]  {result.rule_id:<40s} {result.title}  [dim]({result.skip_reason})[/dim]")
        elif result.passed:
            host_pass += 1
            buf_console.print(f"  [green]PASS[/green]  {result.rule_id:<40s} {result.title}")
        else:
            host_fail += 1
            detail = f"  [dim]{result.detail}[/dim]" if result.detail else ""
            buf_console.print(f"  [red]FAIL[/red]  {result.rule_id:<40s} {result.title}{detail}")
    return host_pass, host_fail, host_skip


def _run_checks(ssh, rule_list, caps, platform):
    """Run checks for a single host and print results. Returns (pass, fail, skip) counts."""
    host_pass = host_fail = host_skip = 0
    for r in rule_list:
        if platform and not rule_applies_to_platform(r, platform.family, platform.version):
            host_skip += 1
            console.print(
                f"  [dim]SKIP[/dim]  {r['id']:<40s} {r.get('title', r['id'])}  "
                f"[dim](platform: requires {_platform_constraint_str(r)})[/dim]"
            )
            continue
        _print_impl_verbose(r, caps)
        result = evaluate_rule(ssh, r, caps)
        if result.skipped:
            host_skip += 1
            console.print(f"  [dim]SKIP[/dim]  {result.rule_id:<40s} {result.title}  [dim]({result.skip_reason})[/dim]")
        elif result.passed:
            host_pass += 1
            console.print(f"  [green]PASS[/green]  {result.rule_id:<40s} {result.title}")
        else:
            host_fail += 1
            detail = f"  [dim]{result.detail}[/dim]" if result.detail else ""
            console.print(f"  [red]FAIL[/red]  {result.rule_id:<40s} {result.title}{detail}")
    return host_pass, host_fail, host_skip


# ── remediate ───────────────────────────────────────────────────────────────


@main.command()
@target_options
@rule_options
@click.option("--dry-run", is_flag=True, help="Show what would be done without making changes")
@click.option("--rollback-on-failure", is_flag=True, help="Auto-rollback changes if remediation or post-check fails")
def remediate(host, inventory, limit, user, key, password, port, verbose, sudo, capability, workers, rules, rule, severity, tag, category, dry_run, rollback_on_failure):
    """Check rules and remediate failures on target hosts."""
    global verbose_mode
    verbose_mode = verbose
    hosts = _resolve_hosts(host, inventory, limit, user, key, port)
    rule_list = _load_rule_list(rules, rule, severity, tag, category)
    overrides = _parse_capability_overrides(capability)

    if dry_run:
        console.print("[yellow]DRY RUN — no changes will be made[/yellow]\n")

    if workers == 1:
        # Sequential execution - use direct console output (original behavior)
        total_pass = 0
        total_fail = 0
        total_fixed = 0
        total_skip = 0
        total_rolled_back = 0
        host_count = 0

        for hi in hosts:
            console.print()
            console.rule(f"[bold]Host: {hi.hostname}[/bold]")
            try:
                with _connect(hi, password, sudo=sudo) as ssh:
                    platform = detect_platform(ssh)
                    detected_caps = detect_capabilities(ssh, verbose=verbose)
                    caps = _apply_capability_overrides(detected_caps, overrides)
                    _print_platform(platform)
                    _print_caps_verbose(caps)
                    host_pass, host_fail, host_fixed, host_skip, host_rolled_back = _run_remediation(
                        ssh, rule_list, caps, platform, dry_run=dry_run,
                        rollback_on_failure=rollback_on_failure,
                    )
            except Exception as exc:
                console.print(f"  [red]Connection failed:[/red] {exc}")
                continue

            host_count += 1
            total_pass += host_pass
            total_fail += host_fail
            total_fixed += host_fixed
            total_skip += host_skip
            total_rolled_back += host_rolled_back

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
            console.print(summary)

        if host_count > 1:
            console.print()
            console.rule("[bold]Summary[/bold]")
            grand_total = total_pass + total_fail + total_fixed + total_skip
            summary = (
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[yellow]{total_fixed} fixed[/yellow] | "
                f"[red]{total_fail} fail[/red]"
            )
            if total_skip:
                summary += f" | [dim]{total_skip} skip[/dim]"
            if total_rolled_back:
                summary += f" | [magenta]{total_rolled_back} rolled back[/magenta]"
            console.print(summary)
        console.print()
    else:
        # Parallel execution - use buffered output
        results: list[HostRemediateResult] = []

        with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
            futures = {
                pool.submit(
                    _remediate_host, hi, password, sudo, overrides, rule_list,
                    verbose, dry_run, rollback_on_failure
                ): hi
                for hi in hosts
            }
            for future in as_completed(futures):
                result = future.result()
                with print_lock:
                    _print_remediate_result(result)
                results.append(result)

        # Aggregate results
        successful_results = [r for r in results if r.success]
        total_pass = sum(r.pass_count for r in successful_results)
        total_fail = sum(r.fail_count for r in successful_results)
        total_fixed = sum(r.fixed_count for r in successful_results)
        total_skip = sum(r.skip_count for r in successful_results)
        total_rolled_back = sum(r.rolled_back_count for r in successful_results)
        host_count = len(successful_results)

        if host_count > 1:
            console.print()
            console.rule("[bold]Summary[/bold]")
            grand_total = total_pass + total_fail + total_fixed + total_skip
            summary = (
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[yellow]{total_fixed} fixed[/yellow] | "
                f"[red]{total_fail} fail[/red]"
            )
            if total_skip:
                summary += f" | [dim]{total_skip} skip[/dim]"
            if total_rolled_back:
                summary += f" | [magenta]{total_rolled_back} rolled back[/magenta]"
            console.print(summary)
        console.print()


def _remediate_host(
    hi: HostInfo,
    password: str | None,
    sudo: bool,
    overrides: dict[str, bool],
    rule_list: list[dict],
    verbose: bool,
    dry_run: bool,
    rollback_on_failure: bool,
) -> HostRemediateResult:
    """Run remediation on a single host. Returns results for later printing."""
    buf = StringIO()
    buf_console = Console(file=buf, force_terminal=True, width=120)

    buf_console.print()
    buf_console.rule(f"[bold]Host: {hi.hostname}[/bold]")

    try:
        with _connect(hi, password, sudo=sudo) as ssh:
            platform = detect_platform(ssh)
            detected_caps = detect_capabilities(ssh, verbose=verbose)
            caps = _apply_capability_overrides_quiet(detected_caps, overrides, buf_console, verbose)

            # Print platform info
            if platform is None:
                buf_console.print("  [yellow]Platform: unknown (could not read /etc/os-release)[/yellow]")
            else:
                buf_console.print(f"  Platform: {platform.family.upper()} {platform.version}")

            # Print capabilities in verbose mode
            if verbose:
                active = sorted(k for k, v in caps.items() if v)
                if active:
                    buf_console.print(f"  [dim]capabilities: {', '.join(active)}[/dim]")
                else:
                    buf_console.print("  [dim]capabilities: (none detected)[/dim]")

            # Run remediation
            host_pass, host_fail, host_fixed, host_skip, host_rolled_back = _run_remediation_buffered(
                ssh, rule_list, caps, platform, buf_console, verbose,
                dry_run=dry_run, rollback_on_failure=rollback_on_failure,
            )
    except Exception as exc:
        buf_console.print(f"  [red]Connection failed:[/red] {exc}")
        return HostRemediateResult(
            hostname=hi.hostname,
            success=False,
            error=str(exc),
            output=buf.getvalue(),
        )

    # Print host summary
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
    buf_console.print(summary)

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
        output=buf.getvalue(),
    )


def _print_remediate_result(result: HostRemediateResult) -> None:
    """Print buffered remediate result to console."""
    # Use sys.stdout.write for already-formatted ANSI output
    sys.stdout.write(result.output)
    sys.stdout.flush()


def _run_remediation(ssh, rule_list, caps, platform, *, dry_run, rollback_on_failure=False):
    """Run remediation for a single host. Returns (pass, fail, fixed, skip, rolled_back) counts."""
    host_pass = host_fail = host_fixed = host_skip = host_rolled_back = 0
    for r in rule_list:
        if platform and not rule_applies_to_platform(r, platform.family, platform.version):
            host_skip += 1
            console.print(
                f"  [dim]SKIP[/dim]  {r['id']:<40s} {r.get('title', r['id'])}  "
                f"[dim](platform: requires {_platform_constraint_str(r)})[/dim]"
            )
            continue
        _print_impl_verbose(r, caps)
        result = remediate_rule(
            ssh, r, caps, dry_run=dry_run, rollback_on_failure=rollback_on_failure,
        )
        if result.skipped:
            host_skip += 1
            console.print(f"  [dim]SKIP[/dim]  {result.rule_id:<40s} {result.title}  [dim]({result.skip_reason})[/dim]")
        elif result.passed and not result.remediated:
            host_pass += 1
            console.print(f"  [green]PASS[/green]  {result.rule_id:<40s} {result.title}")
        elif result.passed and result.remediated:
            host_fixed += 1
            detail = f"  [dim]{result.remediation_detail}[/dim]" if result.remediation_detail else ""
            tag = "[yellow]DRY [/yellow]" if dry_run else "[yellow]FIXED[/yellow]"
            console.print(f"  {tag} {result.rule_id:<40s} {result.title}{detail}")
        else:
            host_fail += 1
            suffix = "  [magenta](rolled back)[/magenta]" if result.rolled_back else ""
            detail = f"  [dim]{result.remediation_detail or result.detail}[/dim]" if (result.remediation_detail or result.detail) else ""
            console.print(f"  [red]FAIL[/red]  {result.rule_id:<40s} {result.title}{detail}{suffix}")
            if result.rolled_back:
                host_rolled_back += 1
            # Verbose: show step detail and rollback detail
            if verbose_mode and result.step_results:
                total_steps = len(result.step_results)
                for sr in result.step_results:
                    status = "[green]ok[/green]" if sr.success else "[red]FAIL[/red]"
                    console.print(f"    step {sr.step_index + 1}/{total_steps}: {sr.mechanism}  [{status}]  {sr.detail[:80]}")
                if result.rollback_results:
                    for rb in result.rollback_results:
                        status = "[green]ok[/green]" if rb.success else "[dim]skipped[/dim]"
                        console.print(f"    rollback step {rb.step_index}: {rb.mechanism}  [{status}]  {rb.detail[:80]}")
    return host_pass, host_fail, host_fixed, host_skip, host_rolled_back


def _run_remediation_buffered(
    ssh, rule_list, caps, platform, buf_console, verbose, *, dry_run, rollback_on_failure=False
):
    """Run remediation for a single host with buffered output. Returns (pass, fail, fixed, skip, rolled_back) counts."""
    host_pass = host_fail = host_fixed = host_skip = host_rolled_back = 0
    for r in rule_list:
        if platform and not rule_applies_to_platform(r, platform.family, platform.version):
            host_skip += 1
            buf_console.print(
                f"  [dim]SKIP[/dim]  {r['id']:<40s} {r.get('title', r['id'])}  "
                f"[dim](platform: requires {_platform_constraint_str(r)})[/dim]"
            )
            continue
        # Verbose implementation selection
        if verbose:
            impl = select_implementation(r, caps)
            rule_id = r["id"]
            if impl is None:
                buf_console.print(f"  [dim]  {rule_id}: no matching implementation[/dim]")
            elif impl.get("default"):
                buf_console.print(f"  [dim]  {rule_id}: using default implementation[/dim]")
            else:
                gate = impl.get("when", "?")
                buf_console.print(f"  [dim]  {rule_id}: matched gate [bold]{gate}[/bold][/dim]")

        result = remediate_rule(
            ssh, r, caps, dry_run=dry_run, rollback_on_failure=rollback_on_failure,
        )
        if result.skipped:
            host_skip += 1
            buf_console.print(f"  [dim]SKIP[/dim]  {result.rule_id:<40s} {result.title}  [dim]({result.skip_reason})[/dim]")
        elif result.passed and not result.remediated:
            host_pass += 1
            buf_console.print(f"  [green]PASS[/green]  {result.rule_id:<40s} {result.title}")
        elif result.passed and result.remediated:
            host_fixed += 1
            detail = f"  [dim]{result.remediation_detail}[/dim]" if result.remediation_detail else ""
            tag = "[yellow]DRY [/yellow]" if dry_run else "[yellow]FIXED[/yellow]"
            buf_console.print(f"  {tag} {result.rule_id:<40s} {result.title}{detail}")
        else:
            host_fail += 1
            suffix = "  [magenta](rolled back)[/magenta]" if result.rolled_back else ""
            detail = f"  [dim]{result.remediation_detail or result.detail}[/dim]" if (result.remediation_detail or result.detail) else ""
            buf_console.print(f"  [red]FAIL[/red]  {result.rule_id:<40s} {result.title}{detail}{suffix}")
            if result.rolled_back:
                host_rolled_back += 1
            # Verbose: show step detail and rollback detail
            if verbose and result.step_results:
                total_steps = len(result.step_results)
                for sr in result.step_results:
                    status = "[green]ok[/green]" if sr.success else "[red]FAIL[/red]"
                    buf_console.print(f"    step {sr.step_index + 1}/{total_steps}: {sr.mechanism}  [{status}]  {sr.detail[:80]}")
                if result.rollback_results:
                    for rb in result.rollback_results:
                        status = "[green]ok[/green]" if rb.success else "[dim]skipped[/dim]"
                        buf_console.print(f"    rollback step {rb.step_index}: {rb.mechanism}  [{status}]  {rb.detail[:80]}")
    return host_pass, host_fail, host_fixed, host_skip, host_rolled_back


# ── Helpers ─────────────────────────────────────────────────────────────────


def _print_platform(platform) -> None:
    """Print detected platform info."""
    if platform is None:
        console.print("  [yellow]Platform: unknown (could not read /etc/os-release)[/yellow]")
    else:
        console.print(f"  Platform: {platform.family.upper()} {platform.version}")


def _platform_constraint_str(rule: dict) -> str:
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


def _print_caps_verbose(caps: dict[str, bool]) -> None:
    """In verbose mode, print which capabilities were detected."""
    if not verbose_mode:
        return
    active = sorted(k for k, v in caps.items() if v)
    if active:
        console.print(f"  [dim]capabilities: {', '.join(active)}[/dim]")
    else:
        console.print("  [dim]capabilities: (none detected)[/dim]")


def _print_impl_verbose(rule: dict, caps: dict[str, bool]) -> None:
    """In verbose mode, print which implementation was selected for a rule."""
    if not verbose_mode:
        return
    impl = select_implementation(rule, caps)
    rule_id = rule["id"]
    if impl is None:
        console.print(f"  [dim]  {rule_id}: no matching implementation[/dim]")
    elif impl.get("default"):
        console.print(f"  [dim]  {rule_id}: using default implementation[/dim]")
    else:
        gate = impl.get("when", "?")
        console.print(f"  [dim]  {rule_id}: matched gate [bold]{gate}[/bold][/dim]")


def _resolve_hosts(host, inventory, limit, user, key, port) -> list[HostInfo]:
    """Resolve target hosts from CLI flags."""
    try:
        return resolve_targets(
            host=host,
            inventory=inventory,
            limit=limit,
            default_user=user,
            default_key=key,
            default_port=port,
        )
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


def _connect(hi: HostInfo, password: str | None, *, sudo: bool = False) -> SSHSession:
    """Create an SSHSession from a HostInfo."""
    return SSHSession(
        hostname=hi.hostname,
        port=hi.port,
        user=hi.user,
        key_path=hi.key_path,
        password=password,
        sudo=sudo,
    )


def _load_rule_list(rules, rule, severity, tag, category):
    """Load and filter rules from CLI options."""
    rule_path = rule or rules
    if not rule_path:
        console.print("[red]Error:[/red] Specify --rules or --rule")
        sys.exit(1)

    try:
        rule_list = load_rules(
            rule_path,
            severity=list(severity) if severity else None,
            tags=list(tag) if tag else None,
            category=category,
        )
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    if not rule_list:
        console.print("[yellow]No rules matched the given filters.[/yellow]")
        sys.exit(0)

    return rule_list
