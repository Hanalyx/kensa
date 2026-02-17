"""Aegis CLI — detect, check, and remediate compliance rules over SSH."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
from threading import Lock

import click
from rich.console import Console
from rich.table import Table

from runner._host_runner import (
    HostCheckResult,
    HostDetectResult,
    HostRemediateResult,
    HostRunConfig,
    apply_capability_overrides,
    connect,
    execute_on_host,
    platform_filter_control_rules,
    print_caps_verbose,
    print_platform,
    run_checks,
    run_remediation,
)
from runner._rule_selection import apply_auto_framework, select_rules
from runner.detect import detect_capabilities, detect_platform
from runner.engine import load_rules
from runner.inventory import HostInfo, resolve_targets
from runner.output import HostResult, RunResult, parse_output_spec, write_output

console = Console()
print_lock = Lock()


def _parse_capability_overrides(flags: tuple[str, ...]) -> dict[str, bool]:
    """Parse -C key=value flags into a dict."""
    overrides = {}
    for flag in flags:
        if "=" not in flag:
            console.print(
                f"[red]Error:[/red] Invalid capability format: {flag} (expected KEY=VALUE)"
            )
            sys.exit(1)
        key, value = flag.split("=", 1)
        if value.lower() == "true":
            overrides[key] = True
        elif value.lower() == "false":
            overrides[key] = False
        else:
            console.print(
                f"[red]Error:[/red] Invalid capability value: {value} (expected true/false)"
            )
            sys.exit(1)
    return overrides


# ── Shared options ──────────────────────────────────────────────────────────


def target_options(f):
    """Common target/connection options for all subcommands."""
    f = click.option(
        "--host", "-h", default=None, help="Target host(s), comma-separated"
    )(f)
    f = click.option(
        "--inventory",
        "-i",
        default=None,
        help="Ansible inventory file (INI/YAML) or host list",
    )(f)
    f = click.option(
        "--limit", "-l", default=None, help="Limit to group or host glob pattern"
    )(f)
    f = click.option("--user", "-u", default=None, help="SSH username")(f)
    f = click.option("--key", "-k", default=None, help="SSH private key path")(f)
    f = click.option("--password", "-p", default=None, help="SSH password")(f)
    f = click.option(
        "--port", "-P", default=22, type=int, help="SSH port (default: 22)"
    )(f)
    f = click.option(
        "--verbose",
        "-v",
        is_flag=True,
        help="Show capability detection and implementation selection",
    )(f)
    f = click.option("--sudo", is_flag=True, help="Run all remote commands via sudo")(f)
    f = click.option(
        "--strict-host-keys/--no-strict-host-keys",
        default=False,
        help="Verify SSH host keys against ~/.ssh/known_hosts (default: off)",
    )(f)
    f = click.option(
        "--capability",
        "-C",
        multiple=True,
        metavar="KEY=VALUE",
        help="Override detected capability (e.g., -C sshd_config_d=false)",
    )(f)
    f = click.option(
        "--workers",
        "-w",
        default=1,
        type=click.IntRange(1, 50),
        help="Number of parallel SSH connections (default: 1, max: 50)",
    )(f)
    return f


def rule_options(f):
    """Rule selection options for check/remediate."""
    f = click.option(
        "--rules", "-r", default=None, help="Path to rules directory (recursive)"
    )(f)
    f = click.option("--rule", default=None, help="Path to single rule file")(f)
    f = click.option(
        "--severity", "-s", multiple=True, help="Filter by severity (repeatable)"
    )(f)
    f = click.option("--tag", "-t", multiple=True, help="Filter by tag (repeatable)")(f)
    f = click.option("--category", "-c", default=None, help="Filter by category")(f)
    f = click.option(
        "--framework",
        "-f",
        default=None,
        help="Filter to rules in framework mapping (e.g., cis-rhel9-v2.0.0)",
    )(f)
    f = click.option(
        "--var",
        "-V",
        "var",
        multiple=True,
        metavar="KEY=VALUE",
        help="Override rule variable (e.g., -V pam_pwquality_minlen=20)",
    )(f)
    f = click.option(
        "--control",
        default=None,
        help="Run only rules for a framework control (e.g., cis-rhel9-v2.0.0:5.1.12 or 5.1.12)",
    )(f)
    return f


def output_options(f):
    """Output format options for check/remediate."""
    f = click.option(
        "--output",
        "-o",
        "outputs",
        multiple=True,
        help="Output format (csv, json, pdf). Add :path to write to file (e.g., -o json:results.json)",
    )(f)
    f = click.option(
        "--quiet", "-q", is_flag=True, help="Suppress terminal output (useful with -o)"
    )(f)
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
  --control ID             Run rules for a control (e.g., cis-rhel9-v2.0.0:5.1.12)
  -s, --severity TEXT      Filter by severity (repeatable)
  -t, --tag TEXT           Filter by tag (repeatable)
  -c, --category TEXT      Filter by category
  -f, --framework TEXT     Filter to framework (e.g., cis-rhel9-v2.0.0)
  -V, --var KEY=VALUE      Override rule variable (repeatable)

\b
Output Options (check/remediate):
  -o, --output FORMAT      Output format: csv, json, pdf
                           Add :path to write to file (e.g., -o json:report.json)
                           PDF requires a filepath (e.g., -o pdf:report.pdf)
                           Can be repeated for multiple outputs
  -q, --quiet              Suppress terminal output (useful with -o)

\b
Remediation Options:
  --dry-run                Preview without changes
  --rollback-on-failure    Auto-rollback on failure

\b
Examples:
  aegis detect --host 192.168.1.100 -u admin --sudo
  aegis check -i hosts.ini --sudo -r rules/ -w 4
  aegis check -i hosts.ini --sudo -r rules/ -o json -q
  aegis check -i hosts.ini --sudo -r rules/ -o csv:results.csv -o pdf:report.pdf
  aegis check -i hosts.ini --sudo -r rules/ -V pam_pwquality_minlen=20
  aegis check -i hosts.ini --sudo --control cis-rhel9-v2.0.0:5.1.12
  aegis remediate -i hosts.ini --sudo --control 5.1.12
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
def detect(
    host,
    inventory,
    limit,
    user,
    key,
    password,
    port,
    verbose,
    sudo,
    strict_host_keys,
    capability,
    workers,
):
    """Probe capabilities on target hosts."""
    hosts = _resolve_hosts(host, inventory, limit, user, key, port)
    overrides = _parse_capability_overrides(capability)

    if workers == 1:
        # Sequential execution - use direct console output (original behavior)
        for hi in hosts:
            _detect_host_sequential(
                hi,
                password,
                sudo,
                overrides,
                verbose,
                strict_host_keys=strict_host_keys,
            )
    else:
        # Parallel execution - use buffered output
        with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
            futures = {
                pool.submit(
                    _detect_host,
                    hi,
                    password,
                    sudo,
                    overrides,
                    verbose,
                    strict_host_keys=strict_host_keys,
                ): hi
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
    *,
    strict_host_keys: bool = False,
) -> None:
    """Run capability detection on a single host with direct console output."""
    console.rule(f"[bold]Host: {hi.hostname}[/bold]")

    try:
        with connect(hi, password, sudo=sudo, strict_host_keys=strict_host_keys) as ssh:
            platform = detect_platform(ssh)
            detected_caps = detect_capabilities(ssh, verbose=verbose)
            caps = apply_capability_overrides(
                detected_caps, overrides, console, verbose
            )
    except Exception as exc:
        console.print(f"  [red]Connection failed:[/red] {exc}")
        return

    print_platform(platform, console)

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
    *,
    strict_host_keys: bool = False,
) -> HostDetectResult:
    """Run capability detection on a single host. Returns results for later printing."""
    buf = StringIO()
    buf_console = Console(file=buf, force_terminal=True, width=120)

    buf_console.rule(f"[bold]Host: {hi.hostname}[/bold]")

    try:
        with connect(hi, password, sudo=sudo, strict_host_keys=strict_host_keys) as ssh:
            platform = detect_platform(ssh)
            detected_caps = detect_capabilities(ssh, verbose=verbose)
            caps = apply_capability_overrides(
                detected_caps, overrides, buf_console, verbose
            )
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
        buf_console.print(
            "  [yellow]Platform: unknown (could not read /etc/os-release)[/yellow]"
        )
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
@output_options
@click.option(
    "--store", is_flag=True, help="Store results in local database for history"
)
def check(
    host,
    inventory,
    limit,
    user,
    key,
    password,
    port,
    verbose,
    sudo,
    strict_host_keys,
    capability,
    workers,
    rules,
    rule,
    severity,
    tag,
    category,
    framework,
    var,
    control,
    outputs,
    quiet,
    store,
):
    """Run compliance checks on target hosts."""
    hosts = _resolve_hosts(host, inventory, limit, user, key, port)
    try:
        selection = select_rules(
            rules,
            rule,
            severity,
            tag,
            category,
            framework=framework,
            var=var,
            control=control,
            out=None if quiet else console,
        )
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    rule_list = selection.rules
    rule_to_section = selection.rule_to_section
    control_ctx = selection.control_ctx
    overrides = _parse_capability_overrides(capability)
    auto_framework_applied = False  # Track if auto framework has been applied

    # Collect results for output formatting
    run_result = RunResult(command="check")

    # Output console: real console for terminal output, null for quiet mode
    out = Console(file=StringIO()) if quiet else console

    run_config = HostRunConfig(
        mode="check",
        verbose=verbose,
        rule_to_section=rule_to_section,
        control_ctx=control_ctx,
        capability_overrides=overrides,
    )

    if workers == 1:
        # Sequential execution
        total_pass = 0
        total_fail = 0
        total_skip = 0
        host_count = 0

        for hi in hosts:
            out.print()
            out.rule(f"[bold]Host: {hi.hostname}[/bold]")
            host_result = HostResult(hostname=hi.hostname)
            try:
                with connect(
                    hi, password, sudo=sudo, strict_host_keys=strict_host_keys
                ) as ssh:
                    platform = detect_platform(ssh)
                    detected_caps = detect_capabilities(ssh, verbose=verbose)
                    caps = apply_capability_overrides(
                        detected_caps, overrides, out, verbose
                    )
                    print_platform(platform, out)
                    print_caps_verbose(caps, out, verbose)

                    # Apply auto framework selection on first host
                    if framework == "auto" and not auto_framework_applied:
                        rule_list, rule_to_section = apply_auto_framework(
                            rule_list, platform, out=out
                        )
                        run_config.rule_to_section = rule_to_section
                        auto_framework_applied = True

                    # Platform-aware control filtering
                    host_rules = rule_list
                    if control_ctx and platform:
                        host_rules = platform_filter_control_rules(
                            rule_list, control_ctx, platform
                        )

                    host_result.platform_family = platform.family if platform else None
                    host_result.platform_version = (
                        platform.version if platform else None
                    )
                    host_result.capabilities = caps
                    host_pass, host_fail, host_skip, rule_results = run_checks(
                        ssh,
                        host_rules,
                        caps,
                        platform,
                        out=out,
                        verbose=verbose,
                        rule_to_section=rule_to_section,
                    )
                    host_result.results = rule_results
            except Exception as exc:
                out.print(f"  [red]Connection failed:[/red] {exc}")
                host_result.error = str(exc)
                run_result.hosts.append(host_result)
                continue

            run_result.hosts.append(host_result)
            host_count += 1
            total_pass += host_pass
            total_fail += host_fail
            total_skip += host_skip

            total = host_pass + host_fail + host_skip
            out.print(
                f"  [bold]{total} rules[/bold] | "
                f"[green]{host_pass} pass[/green] | "
                f"[red]{host_fail} fail[/red]"
                + (f" | [dim]{host_skip} skip[/dim]" if host_skip else "")
            )

        if host_count > 1:
            out.print()
            out.rule("[bold]Summary[/bold]")
            grand_total = total_pass + total_fail + total_skip
            out.print(
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[red]{total_fail} fail[/red]"
                + (f" | [dim]{total_skip} skip[/dim]" if total_skip else "")
            )
        out.print()
    else:
        # Parallel execution - use buffered output
        results: list[HostCheckResult] = []

        # For auto framework, detect platform from first host before parallelizing
        if framework == "auto" and hosts:
            first_host = hosts[0]
            try:
                with connect(
                    first_host, password, sudo=sudo, strict_host_keys=strict_host_keys
                ) as ssh:
                    first_platform = detect_platform(ssh)
                    rule_list, rule_to_section = apply_auto_framework(
                        rule_list, first_platform, out=None if quiet else console
                    )
                    run_config.rule_to_section = rule_to_section
            except Exception as exc:
                if not quiet:
                    console.print(
                        f"[yellow]Warning: Could not detect platform from {first_host.hostname}: {exc}[/yellow]"
                    )
                    console.print("[yellow]Running with all rules[/yellow]")

        def _check_worker(hi):
            buf = StringIO()
            buf_console = Console(file=buf, force_terminal=True, width=120)
            r = execute_on_host(
                hi, password, sudo, strict_host_keys, rule_list, run_config, buf_console
            )
            return r

        with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
            futures = {pool.submit(_check_worker, hi): hi for hi in hosts}
            for future in as_completed(futures):
                result = future.result()
                if not quiet:
                    with print_lock:
                        sys.stdout.write(result.output)
                        sys.stdout.flush()
                results.append(result)

        # Aggregate results
        successful_results = [r for r in results if r.success]
        total_pass = sum(r.pass_count for r in successful_results)
        total_fail = sum(r.fail_count for r in successful_results)
        total_skip = sum(r.skip_count for r in successful_results)
        host_count = len(successful_results)

        # Build RunResult from parallel results
        for r in results:
            host_result = HostResult(
                hostname=r.hostname,
                platform_family=r.platform.family if r.platform else None,
                platform_version=r.platform.version if r.platform else None,
                capabilities=r.capabilities,
                results=r.rule_results,
                error=r.error,
            )
            run_result.hosts.append(host_result)

        if not quiet and host_count > 1:
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
        if not quiet:
            console.print()

    # Sort results by framework section if framework is active
    if framework:
        from runner.mappings import order_results_by_section

        for host_result in run_result.hosts:
            host_result.results = order_results_by_section(
                host_result.results, rule_to_section
            )

    # Write outputs
    _write_outputs(run_result, outputs)

    # Store results if requested
    if store:
        _store_results(run_result, hosts, rules or rule)


def _store_results(run_result: RunResult, hosts: list, rules_path: str) -> None:
    """Store check results in local database."""
    from runner.storage import ResultStore

    store = ResultStore()
    try:
        hostnames = [h.hostname for h in hosts]
        session_id = store.create_session(
            hosts=hostnames,
            rules_path=rules_path,
        )

        for host_result in run_result.hosts:
            for rule_result in host_result.results:
                store.record_result(
                    session_id=session_id,
                    host=host_result.hostname,
                    rule_id=rule_result.rule_id,
                    passed=rule_result.passed,
                    detail=rule_result.detail or "",
                    remediated=getattr(rule_result, "remediated", False),
                )

        console.print(f"[dim]Stored results in session {session_id}[/dim]")
    finally:
        store.close()


# ── remediate ───────────────────────────────────────────────────────────────


@main.command()
@target_options
@rule_options
@output_options
@click.option(
    "--dry-run", is_flag=True, help="Show what would be done without making changes"
)
@click.option(
    "--rollback-on-failure",
    is_flag=True,
    help="Auto-rollback changes if remediation or post-check fails",
)
@click.option(
    "--allow-conflicts",
    is_flag=True,
    help="Proceed despite detected conflicts (last rule wins)",
)
def remediate(
    host,
    inventory,
    limit,
    user,
    key,
    password,
    port,
    verbose,
    sudo,
    strict_host_keys,
    capability,
    workers,
    rules,
    rule,
    severity,
    tag,
    category,
    framework,
    var,
    control,
    outputs,
    quiet,
    dry_run,
    rollback_on_failure,
    allow_conflicts,
):
    """Check rules and remediate failures on target hosts."""
    hosts = _resolve_hosts(host, inventory, limit, user, key, port)
    try:
        selection = select_rules(
            rules,
            rule,
            severity,
            tag,
            category,
            framework=framework,
            var=var,
            control=control,
            out=None if quiet else console,
        )
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    rule_list = selection.rules
    rule_to_section = selection.rule_to_section
    control_ctx = selection.control_ctx
    overrides = _parse_capability_overrides(capability)
    auto_framework_applied = False  # Track if auto framework has been applied

    # Collect results for output formatting
    run_result = RunResult(command="remediate")

    # Output console: real console for terminal output, null for quiet mode
    out = Console(file=StringIO()) if quiet else console

    if dry_run:
        out.print("[yellow]DRY RUN — no changes will be made[/yellow]\n")

    # Check for conflicts (preliminary check with empty capabilities)
    # Full per-host check happens during processing
    from runner.conflicts import detect_conflicts, format_conflicts

    preliminary_conflicts = detect_conflicts(rule_list, {})
    if preliminary_conflicts and not allow_conflicts:
        console.print(format_conflicts(preliminary_conflicts))
        sys.exit(1)
    elif preliminary_conflicts:
        out.print(
            "[yellow]WARNING:[/yellow] Conflicts detected, proceeding anyway (--allow-conflicts)\n"
        )

    run_config = HostRunConfig(
        mode="remediate",
        verbose=verbose,
        dry_run=dry_run,
        rollback_on_failure=rollback_on_failure,
        rule_to_section=rule_to_section,
        control_ctx=control_ctx,
        capability_overrides=overrides,
    )

    if workers == 1:
        # Sequential execution
        total_pass = 0
        total_fail = 0
        total_fixed = 0
        total_skip = 0
        total_rolled_back = 0
        host_count = 0

        for hi in hosts:
            out.print()
            out.rule(f"[bold]Host: {hi.hostname}[/bold]")
            host_result = HostResult(hostname=hi.hostname)
            try:
                with connect(
                    hi, password, sudo=sudo, strict_host_keys=strict_host_keys
                ) as ssh:
                    platform = detect_platform(ssh)
                    detected_caps = detect_capabilities(ssh, verbose=verbose)
                    caps = apply_capability_overrides(
                        detected_caps, overrides, out, verbose
                    )
                    print_platform(platform, out)
                    print_caps_verbose(caps, out, verbose)

                    # Apply auto framework selection on first host
                    if framework == "auto" and not auto_framework_applied:
                        rule_list, rule_to_section = apply_auto_framework(
                            rule_list, platform, out=out
                        )
                        run_config.rule_to_section = rule_to_section
                        auto_framework_applied = True

                    # Platform-aware control filtering
                    host_rules = rule_list
                    if control_ctx and platform:
                        host_rules = platform_filter_control_rules(
                            rule_list, control_ctx, platform
                        )

                    host_result.platform_family = platform.family if platform else None
                    host_result.platform_version = (
                        platform.version if platform else None
                    )
                    host_result.capabilities = caps
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
                        verbose=verbose,
                        dry_run=dry_run,
                        rollback_on_failure=rollback_on_failure,
                        rule_to_section=rule_to_section,
                    )
                    host_result.results = rule_results
            except Exception as exc:
                out.print(f"  [red]Connection failed:[/red] {exc}")
                host_result.error = str(exc)
                run_result.hosts.append(host_result)
                continue

            run_result.hosts.append(host_result)
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
            out.print(summary)

        if host_count > 1:
            out.print()
            out.rule("[bold]Summary[/bold]")
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
            out.print(summary)
        out.print()
    else:
        # Parallel execution - use buffered output
        results: list[HostRemediateResult] = []

        # For auto framework, detect platform from first host before parallelizing
        if framework == "auto" and hosts:
            first_host = hosts[0]
            try:
                with connect(
                    first_host, password, sudo=sudo, strict_host_keys=strict_host_keys
                ) as ssh:
                    first_platform = detect_platform(ssh)
                    rule_list, rule_to_section = apply_auto_framework(
                        rule_list, first_platform, out=None if quiet else console
                    )
                    run_config.rule_to_section = rule_to_section
            except Exception as exc:
                if not quiet:
                    console.print(
                        f"[yellow]Warning: Could not detect platform from {first_host.hostname}: {exc}[/yellow]"
                    )
                    console.print("[yellow]Running with all rules[/yellow]")

        def _remediate_worker(hi):
            buf = StringIO()
            buf_console = Console(file=buf, force_terminal=True, width=120)
            r = execute_on_host(
                hi, password, sudo, strict_host_keys, rule_list, run_config, buf_console
            )
            return r

        with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
            futures = {pool.submit(_remediate_worker, hi): hi for hi in hosts}
            for future in as_completed(futures):
                result = future.result()
                if not quiet:
                    with print_lock:
                        sys.stdout.write(result.output)
                        sys.stdout.flush()
                results.append(result)

        # Aggregate results
        successful_results = [r for r in results if r.success]
        total_pass = sum(r.pass_count for r in successful_results)
        total_fail = sum(r.fail_count for r in successful_results)
        total_fixed = sum(r.fixed_count for r in successful_results)
        total_skip = sum(r.skip_count for r in successful_results)
        total_rolled_back = sum(r.rolled_back_count for r in successful_results)
        host_count = len(successful_results)

        # Build RunResult from parallel results
        for r in results:
            host_result = HostResult(
                hostname=r.hostname,
                platform_family=r.platform.family if r.platform else None,
                platform_version=r.platform.version if r.platform else None,
                capabilities=r.capabilities,
                results=r.rule_results,
                error=r.error,
            )
            run_result.hosts.append(host_result)

        if not quiet and host_count > 1:
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
        if not quiet:
            console.print()

    # Sort results by framework section if framework is active
    if framework:
        from runner.mappings import order_results_by_section

        for host_result in run_result.hosts:
            host_result.results = order_results_by_section(
                host_result.results, rule_to_section
            )

    # Write outputs
    _write_outputs(run_result, outputs)


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


def _write_outputs(run_result: RunResult, outputs: tuple[str, ...]) -> None:
    """Write formatted outputs based on --output flags."""
    for spec in outputs:
        try:
            fmt, filepath = parse_output_spec(spec)
            output = write_output(run_result, fmt, filepath)
            if filepath:
                console.print(f"[dim]Wrote {fmt} output to {filepath}[/dim]")
            else:
                # Print to stdout
                print(output)
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            sys.exit(1)


# ── history ─────────────────────────────────────────────────────────────────


@main.command()
@click.option("--host", "-h", default=None, help="Filter by host")
@click.option("--rule", "-r", default=None, help="Filter by rule ID")
@click.option("--sessions", "-s", is_flag=True, help="List sessions instead of results")
@click.option("--session-id", "-S", type=int, help="Show results for specific session")
@click.option("--limit", "-n", default=20, type=int, help="Max entries to show")
@click.option("--stats", is_flag=True, help="Show database statistics")
@click.option(
    "--prune", type=int, metavar="DAYS", help="Remove results older than N days"
)
def history(host, rule, sessions, session_id, limit, stats, prune):
    """Query compliance scan history.

    Examples:
      aegis history --host 192.168.1.100
      aegis history --sessions
      aegis history --session-id 5
      aegis history --stats
      aegis history --prune 30
    """
    from runner.storage import ResultStore

    store = ResultStore()

    try:
        if stats:
            db_stats = store.get_stats()
            table = Table(title="Database Statistics")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Sessions", str(db_stats["session_count"]))
            table.add_row("Results", str(db_stats["result_count"]))
            table.add_row("Oldest Session", db_stats["oldest_session"] or "N/A")
            table.add_row("Newest Session", db_stats["newest_session"] or "N/A")
            table.add_row("Database Path", db_stats["db_path"])
            console.print(table)
            return

        if prune is not None:
            deleted = store.prune_old_results(prune)
            console.print(f"Deleted {deleted} sessions older than {prune} days")
            return

        if session_id:
            session = store.get_session(session_id)
            if session is None:
                console.print(f"[red]Session {session_id} not found[/red]")
                sys.exit(1)

            console.print(f"[bold]Session {session_id}[/bold]")
            console.print(f"  Timestamp: {session.timestamp}")
            console.print(f"  Hosts: {', '.join(session.hosts)}")
            console.print(f"  Rules Path: {session.rules_path}")
            console.print()

            results = store.get_results(session_id)
            if not results:
                console.print("[yellow]No results for this session[/yellow]")
                return

            table = Table(title="Results")
            table.add_column("Host", style="cyan")
            table.add_column("Rule", style="white")
            table.add_column("Status", style="green")
            table.add_column("Remediated", style="yellow")
            table.add_column("Detail", style="dim")

            for r in results:
                status = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
                remediated = "Yes" if r.remediated else ""
                detail = r.detail[:50] + "..." if len(r.detail) > 50 else r.detail
                table.add_row(r.host, r.rule_id, status, remediated, detail)

            console.print(table)
            return

        if sessions:
            session_list = store.list_sessions(host=host, limit=limit)
            if not session_list:
                console.print("[yellow]No sessions found[/yellow]")
                return

            table = Table(title="Scan Sessions")
            table.add_column("ID", style="cyan")
            table.add_column("Timestamp", style="white")
            table.add_column("Hosts", style="green")
            table.add_column("Rules Path", style="dim")

            for s in session_list:
                hosts_str = ", ".join(s.hosts[:3])
                if len(s.hosts) > 3:
                    hosts_str += f" (+{len(s.hosts) - 3})"
                table.add_row(str(s.id), str(s.timestamp), hosts_str, s.rules_path)

            console.print(table)
            return

        # Default: show result history
        if not host:
            console.print(
                "[red]Error:[/red] Specify --host for result history, or use --sessions"
            )
            sys.exit(1)

        entries = store.get_history(host, rule_id=rule, limit=limit)
        if not entries:
            console.print(f"[yellow]No history for host {host}[/yellow]")
            return

        table = Table(title=f"History for {host}")
        table.add_column("Session", style="cyan")
        table.add_column("Timestamp", style="white")
        table.add_column("Rule", style="white")
        table.add_column("Status", style="green")
        table.add_column("Remediated", style="yellow")

        for e in entries:
            status = "[green]PASS[/green]" if e.passed else "[red]FAIL[/red]"
            remediated = "Yes" if e.remediated else ""
            table.add_row(
                str(e.session_id), str(e.timestamp), e.rule_id, status, remediated
            )

        console.print(table)

    finally:
        store.close()


# ── diff ────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("session1", type=int)
@click.argument("session2", type=int)
@click.option("--host", "-h", default=None, help="Filter by host")
@click.option("--show-unchanged", is_flag=True, help="Include unchanged results")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def diff(session1, session2, host, show_unchanged, json_output):
    """Compare two scan sessions to show drift.

    Shows what changed between SESSION1 (older) and SESSION2 (newer):
    - Regressions: rules that were passing but now fail
    - Resolved: rules that were failing but now pass
    - New failures: rules new in session2 that fail
    - New passes: rules new in session2 that pass

    Examples:
      aegis diff 1 5
      aegis diff 1 5 --host 192.168.1.100
      aegis diff 1 5 --json
    """
    from runner.storage import ResultStore, diff_sessions

    store = ResultStore()

    try:
        report = diff_sessions(store, session1, session2)

        if json_output:
            import json

            output = {
                "session1": {
                    "id": report.session1_id,
                    "timestamp": report.session1_timestamp.isoformat(),
                },
                "session2": {
                    "id": report.session2_id,
                    "timestamp": report.session2_timestamp.isoformat(),
                },
                "summary": report.summary(),
                "changes": [
                    {
                        "host": e.host,
                        "rule_id": e.rule_id,
                        "status": e.status,
                        "old_passed": e.old_passed,
                        "new_passed": e.new_passed,
                    }
                    for e in report.entries
                    if show_unchanged or e.status != "unchanged"
                ],
            }
            print(json.dumps(output, indent=2))
            return

        # Filter by host if specified
        entries = report.entries
        if host:
            entries = [e for e in entries if e.host == host]

        if not show_unchanged:
            entries = [e for e in entries if e.status != "unchanged"]

        console.print(f"[bold]Diff: Session {session1} → Session {session2}[/bold]")
        console.print(f"  {report.session1_timestamp} → {report.session2_timestamp}")
        console.print()

        summary = report.summary()
        console.print("[bold]Summary:[/bold]")
        if summary["regressions"]:
            console.print(f"  [red]Regressions: {summary['regressions']}[/red]")
        if summary["resolved"]:
            console.print(f"  [green]Resolved: {summary['resolved']}[/green]")
        if summary["new_failures"]:
            console.print(f"  [red]New Failures: {summary['new_failures']}[/red]")
        if summary["new_passes"]:
            console.print(f"  [green]New Passes: {summary['new_passes']}[/green]")
        if show_unchanged:
            console.print(f"  [dim]Unchanged: {summary['unchanged']}[/dim]")
        console.print()

        if not entries:
            console.print("[green]No changes between sessions[/green]")
            return

        # Group by status
        status_order = [
            "regression",
            "new_failure",
            "resolved",
            "new_pass",
            "unchanged",
        ]
        status_labels = {
            "regression": ("[red]REGRESSION[/red]", "Was passing, now failing"),
            "new_failure": ("[red]NEW FAIL[/red]", "New rule, failing"),
            "resolved": ("[green]RESOLVED[/green]", "Was failing, now passing"),
            "new_pass": ("[green]NEW PASS[/green]", "New rule, passing"),
            "unchanged": ("[dim]UNCHANGED[/dim]", "No change"),
        }

        table = Table(title="Changes")
        table.add_column("Status", style="white")
        table.add_column("Host", style="cyan")
        table.add_column("Rule", style="white")
        table.add_column("Old", style="dim")
        table.add_column("New", style="white")

        for status in status_order:
            status_entries = [e for e in entries if e.status == status]
            if not status_entries:
                continue

            label, _ = status_labels[status]
            for e in status_entries:
                old_status = (
                    "PASS"
                    if e.old_passed
                    else "FAIL"
                    if e.old_passed is not None
                    else "-"
                )
                new_status = (
                    "PASS"
                    if e.new_passed
                    else "FAIL"
                    if e.new_passed is not None
                    else "-"
                )
                table.add_row(label, e.host, e.rule_id, old_status, new_status)

        console.print(table)

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    finally:
        store.close()


# ── coverage ─────────────────────────────────────────────────────────────────


@main.command()
@click.option(
    "--framework",
    "-f",
    required=True,
    help="Framework mapping ID (e.g., cis-rhel9-v2.0.0)",
)
@click.option("--rules", "-r", default="rules/", help="Path to rules directory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def coverage(framework, rules, json_output):
    """Show coverage report for a framework mapping.

    Reports which framework sections have rules, which are explicitly
    unimplemented, and which have missing rules.

    Examples:
      aegis coverage --framework cis-rhel9-v2.0.0
      aegis coverage --framework cis-rhel9-v2.0.0 --json
    """
    from runner.mappings import check_coverage, load_all_mappings

    # Load mappings
    mappings = load_all_mappings()
    if framework not in mappings:
        console.print(f"[red]Error:[/red] Unknown framework: {framework}")
        console.print(f"Available: {', '.join(sorted(mappings.keys()))}")
        sys.exit(1)

    mapping = mappings[framework]

    # Load rules
    try:
        rule_list = load_rules(rules)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    available_rules = {r["id"] for r in rule_list}

    # Check coverage
    report = check_coverage(mapping, available_rules)

    if json_output:
        import json

        output = {
            "framework": {
                "id": mapping.id,
                "title": mapping.title,
            },
            "coverage": {
                "total_controls": report.total_controls,
                "implemented": report.implemented,
                "unimplemented": report.unimplemented,
                "unaccounted": len(report.unaccounted),
                "coverage_percent": round(report.coverage_percent, 1),
                "accounted_percent": round(report.accounted_percent, 1),
                "is_complete": report.is_complete,
                "has_manifest": report.has_manifest,
            },
            "unaccounted_controls": report.unaccounted,
            "missing_rules": report.missing_rules,
        }
        print(json.dumps(output, indent=2))
        return

    console.print(f"[bold]{mapping.title}[/bold]")
    console.print()

    if not report.has_manifest:
        console.print(
            "[yellow]⚠ No control manifest - coverage is approximate[/yellow]"
        )
        console.print()

    console.print("[bold]Coverage:[/bold]")
    console.print(f"  Total controls: {report.total_controls}")
    console.print(
        f"  [green]Implemented: {report.implemented}[/green] (mapped to rules)"
    )
    console.print(
        f"  [yellow]Unimplemented: {report.unimplemented}[/yellow] (need rules or manual)"
    )
    if report.has_manifest:
        console.print(
            f"  [red]Unaccounted: {len(report.unaccounted)}[/red] (need mapping)"
        )
    console.print()
    console.print(f"  Rule coverage: [bold]{report.coverage_percent:.1f}%[/bold]")
    if report.has_manifest:
        console.print(
            f"  Mapping complete: [bold]{'Yes' if report.is_complete else 'No'}[/bold]"
        )

    if report.unaccounted and len(report.unaccounted) <= 20:
        console.print()
        console.print(f"[red]Unaccounted controls ({len(report.unaccounted)}):[/red]")
        for control_id in report.unaccounted[:20]:
            console.print(f"    - {control_id}")
    elif report.unaccounted:
        console.print()
        console.print(
            f"[red]Unaccounted controls: {len(report.unaccounted)}[/red] "
            "(use --json for full list)"
        )

    if report.missing_rules:
        console.print()
        console.print(f"[red]Missing rules ({len(report.missing_rules)}):[/red]")
        console.print("  These rules are referenced in the mapping but don't exist:")
        for rule_id in sorted(report.missing_rules):
            console.print(f"    - {rule_id}")


# ── list-frameworks ──────────────────────────────────────────────────────────


@main.command("list-frameworks")
def list_frameworks():
    """List available framework mappings.

    Shows all framework mapping files found in the mappings/ directory.
    """
    from runner.mappings import load_all_mappings

    mappings = load_all_mappings()

    if not mappings:
        console.print("[yellow]No framework mappings found in mappings/[/yellow]")
        return

    console.print(f"[bold]Available Frameworks ({len(mappings)}):[/bold]")
    console.print()

    for mapping_id in sorted(mappings.keys()):
        mapping = mappings[mapping_id]
        platform_str = ""
        if mapping.platform:
            platform_str = f" ({mapping.platform.family}"
            if mapping.platform.min_version:
                platform_str += f" >={mapping.platform.min_version}"
            if mapping.platform.max_version:
                platform_str += f" <={mapping.platform.max_version}"
            platform_str += ")"

        console.print(f"  [cyan]{mapping_id}[/cyan]")
        console.print(f"    {mapping.title}{platform_str}")
        console.print(
            f"    Sections: {mapping.implemented_count} implemented, {mapping.unimplemented_count} skipped"
        )
        console.print()


# ── info ─────────────────────────────────────────────────────────────────────


def _get_control_info(
    control_spec: str,
    mappings: dict,
    prefix_match: bool = False,
) -> list[dict]:
    """Get control info (title, metadata) from mappings.

    Args:
        control_spec: Control specification (e.g., "cis-rhel9-v2.0.0:5.1.12").
        mappings: Dict of mapping_id -> FrameworkMapping.
        prefix_match: Whether to match as prefix.

    Returns:
        List of control info dicts with mapping_id, section_id, title, metadata.

    """
    results = []

    if ":" in control_spec:
        # Format: "mapping_id:section_id"
        mapping_id, section_id = control_spec.split(":", 1)
        if mapping_id in mappings:
            mapping = mappings[mapping_id]
            if prefix_match:
                for sid, entry in mapping.sections.items():
                    if sid.startswith(section_id) or sid.startswith(section_id + "."):
                        results.append(
                            {
                                "mapping_id": mapping_id,
                                "section_id": sid,
                                "title": entry.title,
                                "metadata": entry.metadata,
                            }
                        )
            elif section_id in mapping.sections:
                entry = mapping.sections[section_id]
                results.append(
                    {
                        "mapping_id": mapping_id,
                        "section_id": section_id,
                        "title": entry.title,
                        "metadata": entry.metadata,
                    }
                )
    else:
        # Search all mappings for section_id
        for mapping_id, mapping in mappings.items():
            if prefix_match:
                for sid, entry in mapping.sections.items():
                    if sid.startswith(control_spec) or sid.startswith(
                        control_spec + "."
                    ):
                        results.append(
                            {
                                "mapping_id": mapping_id,
                                "section_id": sid,
                                "title": entry.title,
                                "metadata": entry.metadata,
                            }
                        )
            elif control_spec in mapping.sections:
                entry = mapping.sections[control_spec]
                results.append(
                    {
                        "mapping_id": mapping_id,
                        "section_id": control_spec,
                        "title": entry.title,
                        "metadata": entry.metadata,
                    }
                )

    return results


@main.command()
@click.option(
    "--control",
    "-c",
    default=None,
    help="Find rules implementing a control (e.g., cis-rhel9-v2.0.0:5.1.12 or just 5.1.12)",
)
@click.option(
    "--rule",
    "-r",
    default=None,
    help="Find framework references for a rule ID",
)
@click.option(
    "--list-controls",
    "-l",
    is_flag=True,
    help="List all controls with rule counts",
)
@click.option(
    "--framework",
    "-f",
    default=None,
    help="Filter by framework ID (for --list-controls)",
)
@click.option(
    "--prefix-match",
    "-p",
    is_flag=True,
    help="Match control as prefix (e.g., 5.1 matches 5.1.1, 5.1.2, etc.)",
)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def info(control, rule, list_controls, framework, prefix_match, json_output):
    """Show detailed information about rules and framework controls.

    Cross-reference rules and framework controls to understand coverage
    and find relationships between compliance requirements and rules.

    Examples:
      aegis info --control cis-rhel9-v2.0.0:5.1.12
      aegis info --control 5.1 --prefix-match
      aegis info --rule ssh-disable-root-login
      aegis info --list-controls --framework cis-rhel9-v2.0.0
    """
    from runner.mappings import FrameworkIndex, load_all_mappings

    # Load mappings and build index
    mappings = load_all_mappings()
    if not mappings:
        console.print("[yellow]No framework mappings found in mappings/[/yellow]")
        sys.exit(1)

    index = FrameworkIndex.build(mappings)

    # Validate options
    options_count = sum([bool(control), bool(rule), list_controls])
    if options_count == 0:
        console.print("[red]Error:[/red] Specify --control, --rule, or --list-controls")
        sys.exit(1)
    if options_count > 1:
        console.print(
            "[red]Error:[/red] Only one of --control, --rule, --list-controls allowed"
        )
        sys.exit(1)

    # Query by control
    if control:
        rules = index.query_by_control(control, prefix_match=prefix_match)

        # Load rule metadata for detail display
        from runner._loading import load_rules

        try:
            all_rules = load_rules("rules/")
            rules_by_id = {r["id"]: r for r in all_rules}
        except (ValueError, FileNotFoundError):
            rules_by_id = {}

        # Get control info from mapping
        control_info = _get_control_info(control, mappings, prefix_match)

        if json_output:
            import json

            # Build detailed rule info
            detailed_rules = []
            for rule_id in sorted(rules):
                rule_data = rules_by_id.get(rule_id, {})
                detailed_rules.append(
                    {
                        "rule_id": rule_id,
                        "title": rule_data.get("title", ""),
                        "severity": rule_data.get("severity", ""),
                        "category": rule_data.get("category", ""),
                    }
                )

            output = {
                "query": {"control": control, "prefix_match": prefix_match},
                "control_info": control_info,
                "rules": detailed_rules,
            }
            print(json.dumps(output, indent=2))
            return

        if not rules:
            console.print(f"[yellow]No rules found for control: {control}[/yellow]")
            return

        console.print(f"[bold]Rules implementing {control}:[/bold]")
        if prefix_match:
            console.print("[dim](prefix match enabled)[/dim]")

        # Show control title if available
        if control_info:
            for info in control_info:
                console.print(f"[dim]{info['mapping_id']}: {info['title']}[/dim]")
        console.print()

        for rule_id in sorted(rules):
            rule_data = rules_by_id.get(rule_id, {})
            title = rule_data.get("title", "")
            severity = rule_data.get("severity", "")

            console.print(f"  [cyan]{rule_id}[/cyan]")
            if title:
                console.print(f"    {title}")
            if severity:
                sev_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "dim",
                }.get(severity, "white")
                console.print(f"    [{sev_color}]Severity: {severity}[/{sev_color}]")
            console.print()

        console.print(f"[dim]Total: {len(rules)} rules[/dim]")

    # Query by rule
    elif rule:
        refs = index.query_by_rule(rule)
        if json_output:
            import json

            output = {
                "query": {"rule": rule},
                "frameworks": [
                    {
                        "mapping_id": ref.mapping_id,
                        "mapping_title": ref.mapping_title,
                        "section_id": ref.section_id,
                        "title": ref.title,
                        "metadata": ref.metadata,
                    }
                    for ref in refs
                ],
            }
            print(json.dumps(output, indent=2))
            return

        if not refs:
            console.print(f"[yellow]Rule not found in any framework: {rule}[/yellow]")
            return

        console.print(f"[bold]Framework references for {rule}:[/bold]")
        console.print()
        for ref in refs:
            console.print(f"  [cyan]{ref.mapping_id}[/cyan]: {ref.section_id}")
            console.print(f"    {ref.title}")
            if ref.metadata:
                meta_str = ", ".join(f"{k}={v}" for k, v in ref.metadata.items())
                console.print(f"    [dim]{meta_str}[/dim]")
            console.print()
        console.print(f"[dim]Total: {len(refs)} framework references[/dim]")

    # List controls
    elif list_controls:
        controls = index.list_controls(mapping_id=framework)
        if json_output:
            import json

            output = {
                "query": {"list_controls": True, "framework": framework},
                "controls": [
                    {"mapping_id": mid, "section_id": sid, "rule_count": count}
                    for mid, sid, count in controls
                ],
            }
            print(json.dumps(output, indent=2))
            return

        if not controls:
            if framework:
                console.print(
                    f"[yellow]No controls found for framework: {framework}[/yellow]"
                )
            else:
                console.print("[yellow]No controls found[/yellow]")
            return

        title = f"Controls in {framework}" if framework else "All Controls"
        console.print(f"[bold]{title}:[/bold]")
        console.print()

        # Group by mapping if showing all
        current_mapping = None
        for mid, sid, count in controls:
            if not framework and mid != current_mapping:
                if current_mapping is not None:
                    console.print()
                console.print(f"[cyan]{mid}[/cyan]")
                current_mapping = mid

            prefix = "  " if not framework else ""
            console.print(
                f"{prefix}  {sid:<15s} ({count} rule{'s' if count != 1 else ''})"
            )

        console.print()
        console.print(f"[dim]Total: {len(controls)} controls[/dim]")


# ── lookup ────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("section", required=False)
@click.option(
    "--cis", "cis_section", default=None, help="CIS section number (e.g., 2.2.5)"
)
@click.option("--stig", "stig_id", default=None, help="STIG ID (e.g., V-257874)")
@click.option(
    "--nist", "nist_control", default=None, help="NIST 800-53 control (e.g., AC-3)"
)
@click.option(
    "--rhel",
    "rhel_version",
    type=click.Choice(["8", "9", "10"]),
    default=None,
    help="Filter by RHEL version",
)
@click.option("--all", "show_all", is_flag=True, help="Show all RHEL versions")
def lookup(section, cis_section, stig_id, nist_control, rhel_version, show_all):
    r"""Look up rules by CIS section, STIG ID, or NIST control.

    Searches all rules to find which ones implement a specific compliance control.

    \b
    Examples:
      aegis lookup 2.2.5                  # CIS section (auto-detected)
      aegis lookup --cis 2.2.5            # Explicit CIS lookup
      aegis lookup --cis 5.1 --rhel 9     # CIS 5.1.x for RHEL 9 only
      aegis lookup --stig V-257874        # STIG vulnerability ID
      aegis lookup --nist AC-3            # NIST 800-53 control
    """
    from pathlib import Path

    import yaml

    # Determine what to search for
    search_type = None
    search_value = None

    if cis_section:
        search_type = "cis"
        search_value = cis_section
    elif stig_id:
        search_type = "stig"
        search_value = stig_id.upper()
    elif nist_control:
        search_type = "nist"
        search_value = nist_control.upper()
    elif section:
        # Auto-detect type from format
        if section.upper().startswith("V-"):
            search_type = "stig"
            search_value = section.upper()
        elif "-" in section and section.replace("-", "").isalpha():
            search_type = "nist"
            search_value = section.upper()
        else:
            search_type = "cis"
            search_value = section
    else:
        console.print(
            "[red]Error:[/red] Specify a section number or use --cis/--stig/--nist"
        )
        console.print("\nExamples:")
        console.print("  aegis lookup 2.2.5")
        console.print("  aegis lookup --cis 5.1.12")
        console.print("  aegis lookup --stig V-257874")
        console.print("  aegis lookup --nist AC-3")
        sys.exit(1)

    # Load all rules and search
    rules_dir = Path("rules")
    if not rules_dir.exists():
        console.print("[red]Error:[/red] rules/ directory not found")
        sys.exit(1)

    matches = []

    for rule_path in sorted(rules_dir.rglob("*.yml")):
        if rule_path.name == "defaults.yml":
            continue
        try:
            with open(rule_path) as f:
                rule = yaml.safe_load(f)
            if not isinstance(rule, dict) or "id" not in rule:
                continue
        except Exception:
            continue

        refs = rule.get("references", {})
        rule_id = rule["id"]
        title = rule.get("title", "")
        severity = rule.get("severity", "")

        matched_refs = []

        if search_type == "cis":
            cis_refs = refs.get("cis", {})
            for ref_key, ref_data in cis_refs.items():
                ref_section = ref_data.get("section", "")
                # Match exact or prefix
                if ref_section == search_value or ref_section.startswith(
                    search_value + "."
                ):
                    # Filter by RHEL version if specified
                    if rhel_version and f"rhel{rhel_version}" not in ref_key:
                        continue
                    matched_refs.append(
                        {
                            "framework": ref_key,
                            "section": ref_section,
                            "level": ref_data.get("level", ""),
                            "type": ref_data.get("type", ""),
                        }
                    )

        elif search_type == "stig":
            stig_refs = refs.get("stig", {})
            for ref_key, ref_data in stig_refs.items():
                vuln_id = ref_data.get("vuln_id", "")
                stig_rule_id = ref_data.get("stig_id", "")
                if (
                    vuln_id.upper() == search_value
                    or stig_rule_id.upper() == search_value
                ):
                    if rhel_version and f"rhel{rhel_version}" not in ref_key:
                        continue
                    matched_refs.append(
                        {
                            "framework": ref_key,
                            "vuln_id": vuln_id,
                            "stig_id": stig_rule_id,
                            "severity": ref_data.get("severity", ""),
                        }
                    )

        elif search_type == "nist":
            nist_refs = refs.get("nist_800_53", [])
            if isinstance(nist_refs, list):
                for ctrl in nist_refs:
                    if ctrl.upper() == search_value or ctrl.upper().startswith(
                        search_value
                    ):
                        matched_refs.append({"control": ctrl})

        if matched_refs:
            matches.append(
                {
                    "rule_id": rule_id,
                    "title": title,
                    "severity": severity,
                    "refs": matched_refs,
                }
            )

    # Display results
    if not matches:
        console.print(
            f"[yellow]No rules found for {search_type.upper()} {search_value}[/yellow]"
        )
        return

    # Header
    type_label = {"cis": "CIS", "stig": "STIG", "nist": "NIST 800-53"}[search_type]
    console.print(f"[bold]{type_label} {search_value}[/bold]")
    if rhel_version:
        console.print(f"[dim]Filtered: RHEL {rhel_version}[/dim]")
    console.print()

    # Group by framework version if showing all
    if search_type in ("cis", "stig") and (show_all or not rhel_version):
        # Collect all framework versions
        fw_rules: dict[str, list] = {}
        for match in matches:
            for ref in match["refs"]:
                fw = ref.get("framework", "")
                if fw not in fw_rules:
                    fw_rules[fw] = []
                fw_rules[fw].append(match)

        for fw in sorted(fw_rules.keys()):
            console.print(f"[cyan]{fw}:[/cyan]")
            seen = set()
            for match in fw_rules[fw]:
                if match["rule_id"] in seen:
                    continue
                seen.add(match["rule_id"])
                sev_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "dim",
                }.get(match["severity"], "white")
                console.print(f"  [green]{match['rule_id']}[/green]")
                console.print(f"    {match['title']}")
                console.print(
                    f"    [{sev_color}]Severity: {match['severity']}[/{sev_color}]"
                )
            console.print()
    else:
        # Simple list
        for match in matches:
            sev_color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(match["severity"], "white")
            console.print(f"  [green]{match['rule_id']}[/green]")
            console.print(f"    {match['title']}")
            console.print(
                f"    [{sev_color}]Severity: {match['severity']}[/{sev_color}]"
            )
            console.print()

    console.print(f"[dim]Total: {len(matches)} rules[/dim]")
