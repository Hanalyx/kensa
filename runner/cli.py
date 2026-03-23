"""Kensa CLI — detect, check, and remediate compliance rules over SSH."""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
from pathlib import Path
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
    f = click.option(
        "--password",
        "-p",
        default=None,
        prompt=True,
        prompt_required=False,
        hide_input=True,
        help="SSH password (prompts securely if flag given without value)",
    )(f)
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


def _complete_framework(ctx, param, incomplete):
    """Shell completion callback for --framework."""
    from click.shell_completion import CompletionItem

    try:
        from runner.mappings import load_all_mappings

        ids = list(load_all_mappings().keys())
    except Exception:
        return []
    return [CompletionItem(fid) for fid in ids if fid.startswith(incomplete)]


def rule_options(f):
    """Rule selection options for check/remediate."""
    f = click.option(
        "--rules", "-r", default=None, help="Path to rules directory (recursive)"
    )(f)
    f = click.option("--rule", default=None, help="Path to single rule file")(f)
    f = click.option(
        "--severity",
        "-s",
        multiple=True,
        type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
        help="Filter by severity (repeatable)",
    )(f)
    f = click.option("--tag", "-t", multiple=True, help="Filter by tag (repeatable)")(f)
    f = click.option("--category", "-c", default=None, help="Filter by category")(f)
    f = click.option(
        "--framework",
        "-f",
        default=None,
        shell_complete=_complete_framework,
        help="Filter to rules in framework mapping (e.g., cis-rhel9)",
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
        help="Run only rules for a framework control (e.g., cis-rhel9:5.1.12 or 5.1.12)",
    )(f)
    f = click.option(
        "--config-dir",
        "config_dir",
        default=None,
        help="Path to config directory (default: auto-detect)",
    )(f)
    return f


def _complete_output_format(ctx, param, incomplete):
    """Shell completion callback for --output format."""
    from click.shell_completion import CompletionItem

    formats = ["csv", "json", "pdf", "evidence"]
    return [CompletionItem(f) for f in formats if f.startswith(incomplete)]


def output_options(f):
    """Output format options for check/remediate."""
    f = click.option(
        "--output",
        "-o",
        "outputs",
        multiple=True,
        shell_complete=_complete_output_format,
        help="Output format (csv, json, pdf, evidence). Add :path to write to file (e.g., -o json:results.json)",
    )(f)
    f = click.option(
        "--quiet", "-q", is_flag=True, help="Suppress terminal output (useful with -o)"
    )(f)
    return f


# ── CLI group ───────────────────────────────────────────────────────────────

MAIN_HELP_EPILOG = """
\b
Connection Options (detect/check/remediate):
  -h, --host TEXT          Target host(s), comma-separated
  -i, --inventory TEXT     Ansible inventory file (INI/YAML)
  -l, --limit TEXT         Limit to group or hostname glob
  -u, --user TEXT          SSH username
  -k, --key TEXT           SSH private key path
  -p, --password TEXT      SSH password (-p alone prompts securely)
  -P, --port INTEGER       SSH port (default: 22)
  --sudo                   Run commands via sudo
  -w, --workers INTEGER    Parallel connections (1-50, default: 1)
  -v, --verbose            Show capability details
  -C, --capability K=V     Override capability (repeatable)

\b
Rule Options (check/remediate):
  -r, --rules PATH         Rules directory
  --rule PATH              Single rule file
  --control ID             Run rules for a control (e.g., cis-rhel9:5.1.12)
  -s, --severity TEXT      Filter by severity (repeatable)
  -t, --tag TEXT           Filter by tag (repeatable)
  -c, --category TEXT      Filter by category
  -f, --framework TEXT     Filter to framework (e.g., cis-rhel9)
  -V, --var KEY=VALUE      Override rule variable (repeatable)
  --config-dir PATH        Config directory (default: auto-detect)

\b
Output Options (check/remediate):
  -o, --output FORMAT      Output format: csv, json, pdf, evidence
                           Add :path to write to file (e.g., -o json:report.json)
                           PDF requires a filepath (e.g., -o pdf:report.pdf)
                           Can be repeated for multiple outputs
  -q, --quiet              Suppress terminal output (useful with -o)

\b
Check Options:
  --store                  Persist results to local SQLite database

\b
Remediation Options:
  --dry-run                Preview without changes
  --rollback-on-failure    Auto-rollback on failure
  --allow-conflicts        Proceed despite rule conflicts
  --no-snapshot            Skip pre-state capture (faster, no rollback)

\b
Examples:
  kensa detect --host 192.168.1.100 -u admin --sudo
  kensa check -i hosts.ini --sudo -w 4
  kensa check -i hosts.ini --sudo -o json -q
  kensa check -i hosts.ini --sudo -o csv:results.csv -o pdf:report.pdf
  kensa check -i hosts.ini --sudo -V pam_pwquality_minlen=20
  kensa check -i hosts.ini --sudo --control cis-rhel9:5.1.12
  kensa remediate -i hosts.ini --sudo --control 5.1.12
  kensa remediate -i hosts.ini --sudo --dry-run
"""


def _get_version() -> str:
    from runner.paths import get_version

    return get_version()


@click.group(epilog=MAIN_HELP_EPILOG, context_settings={"max_content_width": 120})
@click.version_option(version=_get_version(), prog_name="kensa")
def main():
    """Kensa — SSH-based compliance test runner."""
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
        buf_console.print(
            f"  Platform: {platform.family.upper()} {platform.version_id}"
        )

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
    config_dir,
    outputs,
    quiet,
    store,
):
    """Run compliance checks on target hosts."""
    _validate_output_paths(outputs)
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
            config_dir=config_dir,
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
        rule_config=selection.config,
        cli_overrides=selection.cli_overrides,
        framework=selection.framework,
    )

    run_start = time.monotonic()

    if workers == 1:
        # Sequential execution
        total_pass = 0
        total_fail = 0
        total_error = 0
        total_skip = 0
        host_count = 0

        for hi in hosts:
            out.print()
            out.rule(f"[bold]Host: {hi.hostname}[/bold]")
            host_result = HostResult(hostname=hi.hostname, groups=hi.groups)
            host_start = time.monotonic()
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

                    # Per-host variable resolution
                    if selection.config:
                        from runner._config import (
                            _get_effective_variables,
                            resolve_variables,
                        )

                        host_rules = [
                            resolve_variables(
                                r,
                                selection.config,
                                framework=selection.framework,
                                cli_overrides=selection.cli_overrides,
                                hostname=hi.hostname,
                                groups=hi.groups,
                                strict=True,
                            )
                            for r in host_rules
                        ]
                        host_result.effective_variables = _get_effective_variables(
                            selection.config,
                            framework=selection.framework,
                            cli_overrides=selection.cli_overrides,
                            hostname=hi.hostname,
                            groups=hi.groups,
                        )

                    host_result.platform_family = platform.family if platform else None
                    host_result.platform_version = (
                        platform.version if platform else None
                    )
                    host_result.platform_version_id = (
                        platform.version_id if platform else None
                    )
                    host_result.capabilities = caps
                    host_pass, host_fail, host_error, host_skip, rule_results = (
                        run_checks(
                            ssh,
                            host_rules,
                            caps,
                            platform,
                            out=out,
                            verbose=verbose,
                            rule_to_section=rule_to_section,
                        )
                    )
                    host_result.results = rule_results
            except Exception as exc:
                out.print(f"  [red]Connection failed:[/red] {exc}")
                host_result.error = str(exc)
                run_result.hosts.append(host_result)
                continue

            host_result.duration_seconds = time.monotonic() - host_start
            run_result.hosts.append(host_result)
            host_count += 1
            total_pass += host_pass
            total_fail += host_fail
            total_error += host_error
            total_skip += host_skip

            total = host_pass + host_fail + host_error + host_skip
            summary = (
                f"  [bold]{total} rules[/bold] | "
                f"[green]{host_pass} pass[/green] | "
                f"[red]{host_fail} fail[/red]"
            )
            if host_error:
                summary += f" | [red]{host_error} error[/red]"
            if host_skip:
                summary += f" | [dim]{host_skip} skip[/dim]"
            summary += f" | [dim]{host_result.duration_seconds:.1f}s[/dim]"
            out.print(summary)

        run_duration = time.monotonic() - run_start
        if host_count > 1:
            out.print()
            out.rule("[bold]Summary[/bold]")
            grand_total = total_pass + total_fail + total_error + total_skip
            summary = (
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[red]{total_fail} fail[/red]"
            )
            if total_error:
                summary += f" | [red]{total_error} error[/red]"
            if total_skip:
                summary += f" | [dim]{total_skip} skip[/dim]"
            summary += f" | [dim]{run_duration:.1f}s[/dim]"
            out.print(summary)
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

        host_groups_map = {hi.hostname: hi.groups for hi in hosts}

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
        total_error = sum(r.error_count for r in successful_results)
        total_skip = sum(r.skip_count for r in successful_results)
        host_count = len(successful_results)

        # Build RunResult from parallel results
        for r in results:
            host_result = HostResult(
                hostname=r.hostname,
                platform_family=r.platform.family if r.platform else None,
                platform_version=r.platform.version if r.platform else None,
                platform_version_id=r.platform.version_id if r.platform else None,
                capabilities=r.capabilities,
                results=r.rule_results,
                error=r.error,
                groups=host_groups_map.get(r.hostname, []),
                duration_seconds=r.duration_seconds,
            )
            run_result.hosts.append(host_result)

        run_duration = time.monotonic() - run_start
        if not quiet and host_count > 1:
            console.print()
            console.rule("[bold]Summary[/bold]")
            grand_total = total_pass + total_fail + total_error + total_skip
            summary = (
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[red]{total_fail} fail[/red]"
            )
            if total_error:
                summary += f" | [red]{total_error} error[/red]"
            if total_skip:
                summary += f" | [dim]{total_skip} skip[/dim]"
            summary += f" | [dim]{run_duration:.1f}s[/dim]"
            console.print(summary)
        if not quiet:
            console.print()

    run_result.duration_seconds = time.monotonic() - run_start

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
        _store_results(run_result, hosts, selection.rules_path)


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


def _store_remediation_results(
    run_result: RunResult,
    hosts: list,
    rules_path: str,
    *,
    dry_run: bool = False,
    rollback_on_failure: bool = False,
    snapshot_mode: str = "all",
) -> None:
    """Store remediation results in local database.

    Creates a scan session, remediation session, and records all rule results
    including per-step data and pre-state snapshots.
    """
    from runner.storage import ResultStore

    store = ResultStore()
    try:
        hostnames = [h.hostname for h in hosts]
        session_id = store.create_session(
            hosts=hostnames,
            rules_path=rules_path or "",
        )

        rem_session_id = store.create_remediation_session(
            session_id,
            dry_run=dry_run,
            rollback_on_failure=rollback_on_failure,
            snapshot_mode=snapshot_mode,
        )

        for host_result in run_result.hosts:
            if host_result.error:
                continue

            for rule_result in host_result.results:
                if rule_result.skipped:
                    continue

                # Record the check result in results table too
                store.record_result(
                    session_id=session_id,
                    host=host_result.hostname,
                    rule_id=rule_result.rule_id,
                    passed=rule_result.passed,
                    detail=rule_result.detail or "",
                    remediated=rule_result.remediated,
                    evidence=rule_result.evidence,
                    framework_refs=rule_result.framework_refs or None,
                )

                # Record remediation-specific data
                rem_id = store.record_remediation(
                    rem_session_id,
                    host=host_result.hostname,
                    rule_id=rule_result.rule_id,
                    severity=rule_result.severity,
                    passed_before=not rule_result.remediated and rule_result.passed,
                    passed_after=rule_result.passed if rule_result.remediated else None,
                    remediated=rule_result.remediated,
                    rolled_back=rule_result.rolled_back,
                    detail=rule_result.remediation_detail or rule_result.detail or "",
                )

                # Record steps and pre-states
                for sr in rule_result.step_results:
                    step_id = store.record_step(
                        rem_id,
                        step_index=sr.step_index,
                        mechanism=sr.mechanism,
                        success=sr.success,
                        detail=sr.detail or "",
                    )

                    if sr.pre_state is not None and sr.pre_state.capturable:
                        store.record_pre_state(
                            step_id,
                            mechanism=sr.pre_state.mechanism,
                            data=sr.pre_state.data,
                            capturable=sr.pre_state.capturable,
                        )

                # Record inline rollback events
                for rb in rule_result.rollback_results:
                    # Find the matching step_id for this rollback
                    # Rollback results map by step_index to step records
                    matching_steps = [
                        sr
                        for sr in rule_result.step_results
                        if sr.step_index == rb.step_index
                    ]
                    if matching_steps:
                        # Look up the stored step_id
                        steps = store.get_remediation_steps(rem_id)
                        for stored_step in steps:
                            if stored_step.step_index == rb.step_index:
                                store.record_rollback_event(
                                    stored_step.id,
                                    mechanism=rb.mechanism,
                                    success=rb.success,
                                    detail=rb.detail or "",
                                    source="inline",
                                )
                                break

        console.print(
            f"[dim]Stored remediation results in session {rem_session_id}[/dim]"
        )
    finally:
        store.close()


def _get_rollback_archive_days(config_dir: str | None) -> int:
    """Read snapshot_archive_days from the rollback config section.

    Loads the ``rollback:`` block from ``config/defaults.yml`` (and any
    conf.d overrides), returning the ``snapshot_archive_days`` value.
    Falls back to 90 if not configured or if loading fails.

    Args:
        config_dir: Path to the config directory, or None to auto-detect.

    Returns:
        Archive retention period in days.

    """
    from pathlib import Path

    import yaml

    default_days = 90

    if config_dir is None:
        from runner.paths import get_config_path

        try:
            cfg_path = get_config_path()
        except FileNotFoundError:
            return default_days
    else:
        cfg_path = Path(config_dir)

    if not cfg_path.is_dir():
        return default_days

    archive_days = default_days

    # Load from defaults.yml
    defaults_file = cfg_path / "defaults.yml"
    if defaults_file.exists():
        try:
            data = yaml.safe_load(defaults_file.read_text())
            if isinstance(data, dict):
                rollback = data.get("rollback", {})
                if isinstance(rollback, dict):
                    val = rollback.get("snapshot_archive_days")
                    if isinstance(val, int) and val > 0:
                        archive_days = val
        except yaml.YAMLError:
            pass

    # Apply conf.d overrides (alphabetical)
    conf_d = cfg_path / "conf.d"
    if conf_d.is_dir():
        for override_file in sorted(conf_d.glob("*.yml")):
            try:
                data = yaml.safe_load(override_file.read_text())
                if isinstance(data, dict):
                    rollback = data.get("rollback", {})
                    if isinstance(rollback, dict):
                        val = rollback.get("snapshot_archive_days")
                        if isinstance(val, int) and val > 0:
                            archive_days = val
            except yaml.YAMLError:
                pass

    return archive_days


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
@click.option(
    "--no-snapshot",
    is_flag=True,
    help="Disable pre-state snapshot capture (captures by default)",
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
    config_dir,
    outputs,
    quiet,
    dry_run,
    rollback_on_failure,
    allow_conflicts,
    no_snapshot,
):
    """Check rules and remediate failures on target hosts."""
    _validate_output_paths(outputs)
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
            config_dir=config_dir,
            out=None if quiet else console,
        )
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)

    # Prune old snapshot data before processing hosts
    try:
        from runner.storage import ResultStore

        archive_days = _get_rollback_archive_days(config_dir)
        _prune_store = ResultStore()
        try:
            deleted = _prune_store.prune_snapshots(archive_days=archive_days)
            if deleted > 0 and not quiet:
                console.print(
                    f"[dim]Pruned {deleted} expired pre-state snapshots "
                    f"(>{archive_days} days)[/dim]"
                )
        finally:
            _prune_store.close()
    except Exception:
        pass  # Pruning failure must not block remediation

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

    snapshot = not no_snapshot
    run_config = HostRunConfig(
        mode="remediate",
        verbose=verbose,
        dry_run=dry_run,
        rollback_on_failure=rollback_on_failure,
        snapshot=snapshot,
        rule_to_section=rule_to_section,
        control_ctx=control_ctx,
        capability_overrides=overrides,
        rule_config=selection.config,
        cli_overrides=selection.cli_overrides,
        framework=selection.framework,
    )

    run_start = time.monotonic()

    if workers == 1:
        # Sequential execution
        total_pass = 0
        total_fail = 0
        total_fixed = 0
        total_error = 0
        total_skip = 0
        total_rolled_back = 0
        host_count = 0

        for hi in hosts:
            out.print()
            out.rule(f"[bold]Host: {hi.hostname}[/bold]")
            host_result = HostResult(hostname=hi.hostname, groups=hi.groups)
            host_start = time.monotonic()
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

                    # Per-host variable resolution
                    if selection.config:
                        from runner._config import (
                            _get_effective_variables,
                            resolve_variables,
                        )

                        host_rules = [
                            resolve_variables(
                                r,
                                selection.config,
                                framework=selection.framework,
                                cli_overrides=selection.cli_overrides,
                                hostname=hi.hostname,
                                groups=hi.groups,
                                strict=True,
                            )
                            for r in host_rules
                        ]
                        host_result.effective_variables = _get_effective_variables(
                            selection.config,
                            framework=selection.framework,
                            cli_overrides=selection.cli_overrides,
                            hostname=hi.hostname,
                            groups=hi.groups,
                        )

                    host_result.platform_family = platform.family if platform else None
                    host_result.platform_version = (
                        platform.version if platform else None
                    )
                    host_result.platform_version_id = (
                        platform.version_id if platform else None
                    )
                    host_result.capabilities = caps
                    (
                        host_pass,
                        host_fail,
                        host_fixed,
                        host_error,
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
                        snapshot=snapshot,
                        rule_to_section=rule_to_section,
                    )
                    host_result.results = rule_results
            except Exception as exc:
                out.print(f"  [red]Connection failed:[/red] {exc}")
                host_result.error = str(exc)
                run_result.hosts.append(host_result)
                continue

            host_result.duration_seconds = time.monotonic() - host_start
            run_result.hosts.append(host_result)
            host_count += 1
            total_pass += host_pass
            total_fail += host_fail
            total_fixed += host_fixed
            total_error += host_error
            total_skip += host_skip
            total_rolled_back += host_rolled_back

            total = host_pass + host_fail + host_fixed + host_error + host_skip
            summary = (
                f"  [bold]{total} rules[/bold] | "
                f"[green]{host_pass} pass[/green] | "
                f"[yellow]{host_fixed} fixed[/yellow] | "
                f"[red]{host_fail} fail[/red]"
            )
            if host_error:
                summary += f" | [red]{host_error} error[/red]"
            if host_skip:
                summary += f" | [dim]{host_skip} skip[/dim]"
            if host_rolled_back:
                summary += f" | [magenta]{host_rolled_back} rolled back[/magenta]"
            summary += f" | [dim]{host_result.duration_seconds:.1f}s[/dim]"
            out.print(summary)

        run_duration = time.monotonic() - run_start
        if host_count > 1:
            out.print()
            out.rule("[bold]Summary[/bold]")
            grand_total = (
                total_pass + total_fail + total_fixed + total_error + total_skip
            )
            summary = (
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[yellow]{total_fixed} fixed[/yellow] | "
                f"[red]{total_fail} fail[/red]"
            )
            if total_error:
                summary += f" | [red]{total_error} error[/red]"
            if total_skip:
                summary += f" | [dim]{total_skip} skip[/dim]"
            if total_rolled_back:
                summary += f" | [magenta]{total_rolled_back} rolled back[/magenta]"
            summary += f" | [dim]{run_duration:.1f}s[/dim]"
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

        host_groups_map = {hi.hostname: hi.groups for hi in hosts}

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
        total_error = sum(r.error_count for r in successful_results)
        total_skip = sum(r.skip_count for r in successful_results)
        total_rolled_back = sum(r.rolled_back_count for r in successful_results)
        host_count = len(successful_results)

        # Build RunResult from parallel results
        for r in results:
            host_result = HostResult(
                hostname=r.hostname,
                platform_family=r.platform.family if r.platform else None,
                platform_version=r.platform.version if r.platform else None,
                platform_version_id=r.platform.version_id if r.platform else None,
                capabilities=r.capabilities,
                results=r.rule_results,
                error=r.error,
                groups=host_groups_map.get(r.hostname, []),
                duration_seconds=r.duration_seconds,
            )
            run_result.hosts.append(host_result)

        run_duration = time.monotonic() - run_start
        if not quiet and host_count > 1:
            console.print()
            console.rule("[bold]Summary[/bold]")
            grand_total = (
                total_pass + total_fail + total_fixed + total_error + total_skip
            )
            summary = (
                f"  {host_count} hosts | "
                f"{grand_total} total checks | "
                f"[green]{total_pass} pass[/green] | "
                f"[yellow]{total_fixed} fixed[/yellow] | "
                f"[red]{total_fail} fail[/red]"
            )
            if total_error:
                summary += f" | [red]{total_error} error[/red]"
            if total_skip:
                summary += f" | [dim]{total_skip} skip[/dim]"
            if total_rolled_back:
                summary += f" | [magenta]{total_rolled_back} rolled back[/magenta]"
            summary += f" | [dim]{run_duration:.1f}s[/dim]"
            console.print(summary)
        if not quiet:
            console.print()

    run_result.duration_seconds = time.monotonic() - run_start

    # Sort results by framework section if framework is active
    if framework:
        from runner.mappings import order_results_by_section

        for host_result in run_result.hosts:
            host_result.results = order_results_by_section(
                host_result.results, rule_to_section
            )

    # Write outputs
    _write_outputs(run_result, outputs)

    # Always persist remediation results
    _store_remediation_results(
        run_result,
        hosts,
        selection.rules_path,
        dry_run=dry_run,
        rollback_on_failure=rollback_on_failure,
        snapshot_mode="none" if no_snapshot else "all",
    )


def _resolve_hosts(host, inventory, limit, user, key, port) -> list[HostInfo]:
    """Resolve target hosts from CLI flags."""
    # Auto-discover inventory when not explicitly provided
    if inventory is None and host is None:
        from runner.paths import get_inventory_path

        discovered = get_inventory_path()
        if discovered is not None:
            inventory = str(discovered)

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


def _validate_output_paths(outputs: tuple[str, ...]) -> None:
    """Validate output file paths before starting a scan.

    Checks that every path-bearing output spec (e.g., 'json:./results/out.json')
    has a parent directory that exists and is writable. Exits 1 with a human-
    readable error if not, so users get immediate feedback before any SSH work.
    """
    for spec in outputs:
        _, filepath = parse_output_spec(spec)
        if not filepath:
            continue
        parent = Path(filepath).parent
        if not parent.exists():
            console.print(
                f'[red]Error:[/red] output directory "{parent}" does not exist.'
                " Create it first or choose a different path."
            )
            sys.exit(1)
        if not os.access(parent, os.W_OK):
            console.print(
                f'[red]Error:[/red] output directory "{parent}" is not writable.'
            )
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
        except (ValueError, OSError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            sys.exit(1)


# ── history ─────────────────────────────────────────────────────────────────


@main.command()
@click.option("--host", "-h", default=None, help="Filter by host")
@click.option("--rule", "-r", default=None, help="Filter by rule ID")
@click.option(
    "--id", "-S", "session_id", type=int, help="Show results for specific session"
)
@click.option("--limit", "-n", default=20, type=int, help="Max entries to show")
@click.option("--stats", is_flag=True, help="Show database statistics")
@click.option(
    "--prune", type=int, metavar="DAYS", help="Remove results older than N days"
)
def history(host, rule, session_id, limit, stats, prune):
    """Query compliance scan history.

    By default, lists recent scan sessions. Use --host to filter sessions,
    or --host --rule to show per-host result history.

    Examples:
      kensa history
      kensa history --host 192.168.1.100
      kensa history --host 192.168.1.100 --rule ssh-root-login
      kensa history --id 5
      kensa history --stats
      kensa history --prune 30
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

        # Per-host result history mode (--host --rule)
        if host and rule:
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
            return

        # Default: list sessions (optionally filtered by host)
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
      kensa diff 1 5
      kensa diff 1 5 --host 192.168.1.100
      kensa diff 1 5 --json
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
    shell_complete=_complete_framework,
    help="Framework mapping ID (e.g., cis-rhel9)",
)
@click.option("--rules", "-r", default=None, help="Path to rules directory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def coverage(framework, rules, json_output):
    """Show coverage report for a framework mapping.

    Reports which framework sections have rules, which are explicitly
    unimplemented, and which have missing rules.

    Examples:
      kensa coverage --framework cis-rhel9
      kensa coverage --framework cis-rhel9 --json
    """
    from runner.mappings import check_coverage, load_all_mappings
    from runner.paths import get_rules_path

    # Resolve rules path
    if rules is None:
        try:
            rules = str(get_rules_path())
        except FileNotFoundError:
            console.print("[red]Error:[/red] Unable to locate rules directory")
            sys.exit(1)

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

    # Check coverage (pass rule data for quality metrics)
    report = check_coverage(mapping, available_rules, rule_data=rule_list)

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
                "automated": report.automated,
                "remediable": report.remediable,
                "typed_remediable": report.typed_remediable,
                "rollback_safe": report.rollback_safe,
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

    # Quality metrics (only when rule data was provided)
    if report.automated or report.remediable:
        console.print()
        console.print("[bold]Quality:[/bold]")
        console.print(f"  Automated checks: {report.automated}")
        console.print(f"  Remediable: {report.remediable}")
        console.print(f"  Typed (declarative): {report.typed_remediable}")
        console.print(f"  Rollback-safe: {report.rollback_safe}")

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


# ── list (group) ────────────────────────────────────────────────────────────


@main.group("list", invoke_without_command=True)
@click.pass_context
def list_group(ctx):
    """List available resources (frameworks, etc.)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


def _list_frameworks_impl():
    """Shared implementation for list frameworks."""
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


@list_group.command("frameworks")
def list_frameworks():
    """List available framework mappings.

    Shows all framework mapping files found in the mappings/ directory.
    """
    _list_frameworks_impl()


@main.command("list-frameworks", hidden=True, deprecated=True)
def list_frameworks_deprecated():
    """Deprecated: use 'kensa list frameworks'."""
    _list_frameworks_impl()


# ── info ─────────────────────────────────────────────────────────────────────


def _severity_color(severity: str) -> str:
    """Return a Rich color tag for a severity level."""
    return {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
    }.get(severity, "white")


def _get_control_info(
    control_spec: str,
    mappings: dict,
    prefix_match: bool = False,
) -> list[dict]:
    """Get control info (title, metadata) from mappings.

    Args:
        control_spec: Control specification (e.g., "cis-rhel9:5.1.12").
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


def _info_rule_detail(rule_data: dict, index, json_output: bool) -> None:
    """Display full rule detail for ``kensa info <rule-id>``."""
    rule_id = rule_data["id"]
    refs = index.query_by_rule(rule_id)

    if json_output:
        import json

        output = {
            "query": {"rule_id": rule_id},
            "rule": {
                "id": rule_id,
                "title": rule_data.get("title", ""),
                "description": rule_data.get("description", ""),
                "severity": rule_data.get("severity", ""),
                "category": rule_data.get("category", ""),
                "tags": rule_data.get("tags", []),
                "depends_on": rule_data.get("depends_on", []),
                "platforms": rule_data.get("platforms", []),
                "references": rule_data.get("references", {}),
                "implementations": _summarize_implementations(rule_data),
            },
            "frameworks": [
                {
                    "mapping_id": ref.mapping_id,
                    "mapping_title": ref.mapping_title,
                    "section_id": ref.section_id,
                    "title": ref.title,
                }
                for ref in refs
            ],
        }
        print(json.dumps(output, indent=2))
        return

    # Header
    console.print(f"[bold cyan]{rule_id}[/bold cyan]")
    title = rule_data.get("title", "")
    if title:
        console.print(f"  {title}")
    console.print()

    # Description
    desc = rule_data.get("description", "")
    if desc:
        console.print("[bold]Description:[/bold]")
        console.print(f"  {desc.strip()}")
        console.print()

    # Severity / Category / Tags
    severity = rule_data.get("severity", "")
    if severity:
        color = _severity_color(severity)
        console.print(f"[bold]Severity:[/bold] [{color}]{severity}[/{color}]")
    category = rule_data.get("category", "")
    if category:
        console.print(f"[bold]Category:[/bold] {category}")
    tags = rule_data.get("tags", [])
    if tags:
        console.print(f"[bold]Tags:[/bold] {', '.join(tags)}")

    # Dependencies
    depends = rule_data.get("depends_on", [])
    if depends:
        console.print(f"[bold]Depends on:[/bold] {', '.join(depends)}")

    # Platforms
    platforms = rule_data.get("platforms", [])
    if platforms:
        parts = []
        for p in platforms:
            s = p.get("family", "")
            if p.get("min_version"):
                s += f" >={p['min_version']}"
            if p.get("max_version"):
                s += f" <={p['max_version']}"
            parts.append(s)
        console.print(f"[bold]Platforms:[/bold] {', '.join(parts)}")

    console.print()

    # Implementations summary
    impls = rule_data.get("implementations", [])
    if impls:
        console.print(f"[bold]Implementations ({len(impls)}):[/bold]")
        for i, impl in enumerate(impls):
            default = impl.get("default", False)
            when = impl.get("when")
            label = f"  [{i + 1}]"
            if default:
                label += " (default)"
            if when:
                label += f" when={when}"
            console.print(label)

            check = impl.get("check", {})
            if check:
                method = check.get("method", "")
                console.print(f"    Check: {method}")

            remediation = impl.get("remediation", {})
            if remediation:
                mechanism = remediation.get("mechanism", "")
                console.print(f"    Remediation: {mechanism}")
        console.print()

    # YAML references
    yaml_refs = rule_data.get("references", {})
    if yaml_refs:
        console.print("[bold]References (from rule YAML):[/bold]")
        cis_refs = yaml_refs.get("cis", {})
        for ref_key, ref_data in cis_refs.items():
            section = ref_data.get("section", "")
            level = ref_data.get("level", "")
            console.print(f"  CIS {ref_key}: section {section} ({level})")
        stig_refs = yaml_refs.get("stig", {})
        for ref_key, ref_data in stig_refs.items():
            vuln_id = ref_data.get("vuln_id", "")
            stig_sev = ref_data.get("severity", "")
            console.print(f"  STIG {ref_key}: {vuln_id} ({stig_sev})")
        nist_refs = yaml_refs.get("nist_800_53", [])
        if nist_refs:
            console.print(f"  NIST 800-53: {', '.join(nist_refs)}")
        console.print()

    # Framework cross-references
    if refs:
        console.print("[bold]Framework cross-references:[/bold]")
        for ref in refs:
            console.print(
                f"  [cyan]{ref.mapping_id}[/cyan]: {ref.section_id} — {ref.title}"
            )
        console.print()
        console.print(f"[dim]{len(refs)} framework references[/dim]")
    else:
        console.print("[dim]No framework cross-references found[/dim]")


def _summarize_implementations(rule_data: dict) -> list[dict]:
    """Build a JSON-safe summary of a rule's implementations."""
    summaries = []
    for impl in rule_data.get("implementations", []):
        entry: dict = {}
        if impl.get("default"):
            entry["default"] = True
        if impl.get("when"):
            entry["when"] = impl["when"]
        check = impl.get("check", {})
        if check:
            entry["check_method"] = check.get("method", "")
        remediation = impl.get("remediation", {})
        if remediation:
            entry["remediation_mechanism"] = remediation.get("mechanism", "")
        summaries.append(entry)
    return summaries


def _info_by_reference(
    search_type: str,
    value: str,
    rules_by_id: dict[str, dict],
    rhel_version: str | None,
    show_all: bool,
    json_output: bool,
) -> None:
    """Display rules matching a CIS/STIG/NIST reference."""
    from runner.rule_info import search_rules_by_reference

    matches = search_rules_by_reference(rules_by_id, search_type, value, rhel_version)

    if json_output:
        import json

        output = {
            "query": {"type": search_type, "value": value, "rhel": rhel_version},
            "matches": matches,
        }
        print(json.dumps(output, indent=2))
        return

    if not matches:
        console.print(
            f"[yellow]No rules found for {search_type.upper()} {value}[/yellow]"
        )
        return

    type_label = {"cis": "CIS", "stig": "STIG", "nist": "NIST 800-53"}[search_type]
    console.print(f"[bold]{type_label} {value}[/bold]")
    if rhel_version:
        console.print(f"[dim]Filtered: RHEL {rhel_version}[/dim]")
    console.print()

    if search_type in ("cis", "stig") and (show_all or not rhel_version):
        fw_rules: dict[str, list] = {}
        for match in matches:
            for ref in match["refs"]:
                fw = ref.get("framework", "")
                if fw not in fw_rules:
                    fw_rules[fw] = []
                fw_rules[fw].append(match)

        for fw in sorted(fw_rules.keys()):
            console.print(f"[cyan]{fw}:[/cyan]")
            seen: set[str] = set()
            for match in fw_rules[fw]:
                if match["rule_id"] in seen:
                    continue
                seen.add(match["rule_id"])
                color = _severity_color(match["severity"])
                console.print(f"  [green]{match['rule_id']}[/green]")
                console.print(f"    {match['title']}")
                console.print(f"    [{color}]Severity: {match['severity']}[/{color}]")
            console.print()
    else:
        for match in matches:
            color = _severity_color(match["severity"])
            console.print(f"  [green]{match['rule_id']}[/green]")
            console.print(f"    {match['title']}")
            console.print(f"    [{color}]Severity: {match['severity']}[/{color}]")
            console.print()

    console.print(f"[dim]Total: {len(matches)} rules[/dim]")


@main.command()
@click.argument("query", required=False)
@click.option(
    "--control",
    "-c",
    default=None,
    help="Find rules implementing a control (e.g., cis-rhel9:5.1.12 or just 5.1.12)",
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
@click.option(
    "--cis", "cis_section", default=None, help="CIS section number (e.g., 5.2.2)"
)
@click.option("--stig", "stig_id", default=None, help="STIG ID (e.g., V-258036)")
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
def info(
    query,
    control,
    rule,
    list_controls,
    framework,
    prefix_match,
    json_output,
    cis_section,
    stig_id,
    nist_control,
    rhel_version,
    show_all,
):
    r"""Show detailed information about rules and framework controls.

    With a positional QUERY, auto-detects the query type:

    \b
      Rule ID   → full rule detail (title, severity, check, remediation, refs)
      V-NNNNNN  → STIG lookup
      XX-N      → NIST 800-53 control
      N.N.N     → CIS section

    Use explicit flags for framework lookups or existing control queries.

    \b
    Examples:
      kensa info sudo-use-pty                         # Rule detail
      kensa info 5.2.2                                # Auto-detect CIS
      kensa info V-258036                             # Auto-detect STIG
      kensa info AC-3                                 # Auto-detect NIST
      kensa info --cis 5.2.2 --rhel 9                # Explicit CIS
      kensa info --stig V-258036                      # Explicit STIG
      kensa info --nist AC-3                          # Explicit NIST
      kensa info --control cis-rhel9:5.1.12   # Mapping-based control
      kensa info --list-controls -f cis-rhel9  # List controls
    """
    from runner.mappings import FrameworkIndex, load_all_mappings
    from runner.paths import get_rules_path
    from runner.rule_info import build_rule_index, classify_query

    # Load rules index
    try:
        rules_path = get_rules_path()
    except FileNotFoundError:
        rules_path = None

    rules_by_id: dict[str, dict] = {}
    if rules_path:
        rules_by_id = build_rule_index(rules_path)

    # Load mappings and build framework index
    mappings = load_all_mappings()
    index = FrameworkIndex.build(mappings) if mappings else None

    # --- Explicit framework reference flags (--cis, --stig, --nist) ---
    explicit_ref = cis_section or stig_id or nist_control
    if explicit_ref:
        if not rules_by_id:
            console.print("[red]Error:[/red] Unable to locate rules directory")
            sys.exit(1)
        if cis_section:
            _info_by_reference(
                "cis", cis_section, rules_by_id, rhel_version, show_all, json_output
            )
        elif stig_id:
            _info_by_reference(
                "stig",
                stig_id.upper(),
                rules_by_id,
                rhel_version,
                show_all,
                json_output,
            )
        elif nist_control:
            _info_by_reference(
                "nist",
                nist_control.upper(),
                rules_by_id,
                rhel_version,
                show_all,
                json_output,
            )
        return

    # --- Existing --control, --rule, --list-controls flags ---
    flag_count = sum([bool(control), bool(rule), list_controls])

    if flag_count > 1:
        console.print(
            "[red]Error:[/red] Only one of --control, --rule, --list-controls allowed"
        )
        sys.exit(1)

    if control:
        if not index:
            console.print("[yellow]No framework mappings found in mappings/[/yellow]")
            sys.exit(1)
        rules_list = index.query_by_control(control, prefix_match=prefix_match)
        control_info_list = _get_control_info(control, mappings, prefix_match)

        if json_output:
            import json

            detailed_rules = []
            for rule_id in sorted(rules_list):
                rd = rules_by_id.get(rule_id, {})
                detailed_rules.append(
                    {
                        "rule_id": rule_id,
                        "title": rd.get("title", ""),
                        "severity": rd.get("severity", ""),
                        "category": rd.get("category", ""),
                    }
                )
            output = {
                "query": {"control": control, "prefix_match": prefix_match},
                "control_info": control_info_list,
                "rules": detailed_rules,
            }
            print(json.dumps(output, indent=2))
            return

        if not rules_list:
            console.print(f"[yellow]No rules found for control: {control}[/yellow]")
            return

        console.print(f"[bold]Rules implementing {control}:[/bold]")
        if prefix_match:
            console.print("[dim](prefix match enabled)[/dim]")
        if control_info_list:
            for ci in control_info_list:
                console.print(f"[dim]{ci['mapping_id']}: {ci['title']}[/dim]")
        console.print()

        for rule_id in sorted(rules_list):
            rd = rules_by_id.get(rule_id, {})
            title = rd.get("title", "")
            severity = rd.get("severity", "")
            console.print(f"  [cyan]{rule_id}[/cyan]")
            if title:
                console.print(f"    {title}")
            if severity:
                color = _severity_color(severity)
                console.print(f"    [{color}]Severity: {severity}[/{color}]")
            console.print()
        console.print(f"[dim]Total: {len(rules_list)} rules[/dim]")
        return

    if rule:
        if not index:
            console.print("[yellow]No framework mappings found in mappings/[/yellow]")
            sys.exit(1)

        # If --rule points to a known rule ID, show full detail
        if rule in rules_by_id:
            _info_rule_detail(rules_by_id[rule], index, json_output)
            return

        # Otherwise fall back to framework cross-ref only
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
        return

    if list_controls:
        if not index:
            console.print("[yellow]No framework mappings found in mappings/[/yellow]")
            sys.exit(1)
        controls_list = index.list_controls(mapping_id=framework)
        if json_output:
            import json

            output = {
                "query": {"list_controls": True, "framework": framework},
                "controls": [
                    {"mapping_id": mid, "section_id": sid, "rule_count": count}
                    for mid, sid, count in controls_list
                ],
            }
            print(json.dumps(output, indent=2))
            return

        if not controls_list:
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

        current_mapping = None
        for mid, sid, count in controls_list:
            if not framework and mid != current_mapping:
                if current_mapping is not None:
                    console.print()
                console.print(f"[cyan]{mid}[/cyan]")
                current_mapping = mid

            pfx = "  " if not framework else ""
            console.print(
                f"{pfx}  {sid:<15s} ({count} rule{'s' if count != 1 else ''})"
            )

        console.print()
        console.print(f"[dim]Total: {len(controls_list)} controls[/dim]")
        return

    # --- Positional QUERY argument ---
    if query:
        query_type, query_value = classify_query(query, set(rules_by_id.keys()))

        if query_type == "rule":
            if query_value in rules_by_id:
                if not index:
                    # Build a minimal empty index for display
                    index = FrameworkIndex.build({})
                _info_rule_detail(rules_by_id[query_value], index, json_output)
            else:
                console.print(f"[yellow]Rule not found: {query_value}[/yellow]")
                sys.exit(1)
        else:
            if not rules_by_id:
                console.print("[red]Error:[/red] Unable to locate rules directory")
                sys.exit(1)
            _info_by_reference(
                query_type,
                query_value,
                rules_by_id,
                rhel_version,
                show_all,
                json_output,
            )
        return

    # No arguments at all
    console.print(
        "[red]Error:[/red] Specify a QUERY, --control, --rule, or --list-controls"
    )
    console.print()
    console.print("Examples:")
    console.print("  kensa info sudo-use-pty          # Rule detail")
    console.print("  kensa info 5.2.2                 # CIS section")
    console.print("  kensa info V-258036              # STIG ID")
    console.print("  kensa info AC-3                  # NIST control")
    console.print("  kensa info --control cis-rhel9:5.1.12")
    console.print("  kensa info --list-controls -f cis-rhel9")
    sys.exit(1)


# ── lookup (deprecated) ──────────────────────────────────────────────────────


@main.command(hidden=True, deprecated=True)
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

    Deprecated: use ``kensa info`` instead.

    \b
    Examples:
      kensa info 2.2.5                   # CIS section (replaces lookup)
      kensa info --cis 2.2.5             # Explicit CIS lookup
      kensa info --stig V-257874         # STIG vulnerability ID
      kensa info --nist AC-3             # NIST 800-53 control
    """
    click.echo(
        "Warning: 'kensa lookup' is deprecated. Use 'kensa info' instead.",
        err=True,
    )

    from runner.paths import get_rules_path
    from runner.rule_info import build_rule_index

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
        console.print("\nUse 'kensa info' instead:")
        console.print("  kensa info 2.2.5")
        console.print("  kensa info --cis 5.1.12")
        console.print("  kensa info --stig V-257874")
        console.print("  kensa info --nist AC-3")
        sys.exit(1)

    try:
        rules_path = get_rules_path()
    except FileNotFoundError:
        console.print("[red]Error:[/red] Unable to locate rules directory")
        sys.exit(1)

    rules_by_id = build_rule_index(rules_path)
    if not rules_by_id:
        console.print("[red]Error:[/red] No rules found")
        sys.exit(1)

    _info_by_reference(
        search_type, search_value, rules_by_id, rhel_version, show_all, False
    )


# ── rollback ─────────────────────────────────────────────────────────────


@main.command()
@click.option(
    "--list", "list_mode", is_flag=True, help="List recent remediation sessions"
)
@click.option(
    "--info",
    "info_id",
    type=int,
    default=None,
    help="Show details for a remediation session",
)
@click.option(
    "--start",
    "start_id",
    type=int,
    default=None,
    help="Execute rollback from stored snapshots",
)
@click.option(
    "--detail", is_flag=True, help="Show per-step pre-state data (with --info)"
)
@click.option(
    "--rule",
    "filter_rule",
    default=None,
    help="Filter to a specific rule (with --info/--start)",
)
@click.option(
    "--host", "-h", default=None, help="Target host (--start) or filter (--list/--info)"
)
@click.option(
    "--inventory",
    "-i",
    default=None,
    help="Ansible inventory file (INI/YAML) for SSH credentials",
)
@click.option(
    "--limit", "-l", "host_limit", default=None, help="Limit to host glob pattern"
)
@click.option(
    "--max", "-n", "max_sessions", default=20, type=int, help="Max sessions to list"
)
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--user", "-u", default=None, help="SSH username")
@click.option("--key", "-k", default=None, help="SSH private key path")
@click.option(
    "--password",
    "-p",
    default=None,
    prompt=True,
    prompt_required=False,
    hide_input=True,
    help="SSH password (prompts securely if flag given without value)",
)
@click.option("--port", "-P", default=22, type=int, help="SSH port (default: 22)")
@click.option("--sudo", is_flag=True, help="Run commands via sudo")
@click.option(
    "--strict-host-keys/--no-strict-host-keys",
    default=False,
    help="Verify SSH host keys",
)
@click.option(
    "--dry-run", is_flag=True, help="Show what would be rolled back (--start)"
)
@click.option(
    "--force",
    is_flag=True,
    help="Override stale/already-rolled-back warnings (--start)",
)
def rollback(
    list_mode,
    info_id,
    start_id,
    detail,
    filter_rule,
    host,
    inventory,
    host_limit,
    max_sessions,
    json_output,
    user,
    key,
    password,
    port,
    sudo,
    strict_host_keys,
    dry_run,
    force,
):
    """Inspect past remediations and execute rollback from stored snapshots.

    Uses the same SSH infrastructure as check/remediate. Specify targets with
    --host (direct) or --inventory + --limit (inventory-based).

    Examples:
      kensa rollback --list
      kensa rollback --list --host 10.0.0.5
      kensa rollback --info 42
      kensa rollback --info 42 --detail --rule ssh-disable-root-login
      kensa rollback --info 42 --json
      kensa rollback --start 42 --host 10.0.0.5 -u admin --sudo
      kensa rollback --start 42 -i inventory.ini --limit 10.0.0.5 --sudo
      kensa rollback --start 42 --host 10.0.0.5 --sudo --dry-run
    """
    mode_count = sum([list_mode, info_id is not None, start_id is not None])
    if mode_count == 0:
        console.print("[red]Error:[/red] Specify --list, --info ID, or --start ID")
        sys.exit(1)
    if mode_count > 1:
        console.print("[red]Error:[/red] Only one of --list, --info, --start allowed")
        sys.exit(1)

    # For --list and --info, the target host is a DB filter.
    # For --start, we need to resolve it to an SSH-capable HostInfo.
    # Determine the effective target hostname for DB filtering.
    filter_host = host
    if not filter_host and host_limit:
        filter_host = host_limit

    from runner.storage import ResultStore

    store = ResultStore()
    try:
        if list_mode:
            _rollback_list(store, filter_host, max_sessions, json_output)
        elif info_id is not None:
            _rollback_info(
                store, info_id, detail, filter_rule, filter_host, json_output
            )
        elif start_id is not None:
            if not filter_host:
                console.print(
                    "[red]Error:[/red] --host or --limit is required with --start"
                )
                sys.exit(1)
            # Resolve SSH target using the same path as check/remediate
            hosts = _resolve_hosts(host, inventory, host_limit, user, key, port)
            if not hosts:
                console.print(f"[red]Error:[/red] Could not resolve host {filter_host}")
                sys.exit(1)
            _rollback_start(
                store,
                start_id,
                target_host=filter_host,
                host_info=hosts[0],
                rule_filter=filter_rule,
                password=password,
                sudo=sudo,
                strict_host_keys=strict_host_keys,
                dry_run=dry_run,
                force=force,
            )
    finally:
        store.close()


def _rollback_list(store, host: str | None, limit: int, json_output: bool) -> None:
    """List recent remediation sessions with summary counts."""
    sessions = store.list_remediation_sessions(host=host, limit=limit)

    if not sessions:
        console.print("[yellow]No remediation sessions found[/yellow]")
        return

    if json_output:
        import json

        output = []
        for s in sessions:
            rems = store.get_remediations(s.id)
            hosts = sorted({r.host for r in rems})
            output.append(
                {
                    "id": s.id,
                    "timestamp": s.timestamp.isoformat(),
                    "hosts": hosts,
                    "dry_run": s.dry_run,
                    "rollback_on_failure": s.rollback_on_failure,
                    "snapshot_mode": s.snapshot_mode,
                    "total_rules": len(rems),
                    "fixed": sum(1 for r in rems if r.remediated and r.passed_after),
                    "fail": sum(
                        1
                        for r in rems
                        if r.remediated and not (r.passed_after or False)
                    ),
                    "rolled_back": sum(1 for r in rems if r.rolled_back),
                }
            )
        print(json.dumps(output, indent=2))
        return

    table = Table(title="Remediation Sessions")
    table.add_column("ID", style="cyan")
    table.add_column("Timestamp", style="white")
    table.add_column("Host(s)", style="green")
    table.add_column("Rules", justify="right")
    table.add_column("Fixed", justify="right", style="yellow")
    table.add_column("Fail", justify="right", style="red")
    table.add_column("Rolled Back", justify="right", style="magenta")

    for s in sessions:
        rems = store.get_remediations(s.id)
        hosts = sorted({r.host for r in rems})
        hosts_str = ", ".join(hosts[:2])
        if len(hosts) > 2:
            hosts_str += f" (+{len(hosts) - 2})"

        total = len(rems)
        fixed = sum(1 for r in rems if r.remediated and r.passed_after)
        fail = sum(1 for r in rems if r.remediated and not (r.passed_after or False))
        rolled_back = sum(1 for r in rems if r.rolled_back)

        mode_tag = " [dim](dry)[/dim]" if s.dry_run else ""
        table.add_row(
            str(s.id),
            str(s.timestamp) + mode_tag,
            hosts_str,
            str(total),
            str(fixed),
            str(fail),
            str(rolled_back),
        )

    console.print(table)


def _rollback_info(
    store,
    remediation_session_id: int,
    detail: bool,
    filter_rule: str | None,
    filter_host: str | None,
    json_output: bool,
) -> None:
    """Show detailed info about a remediation session."""
    rs = store.get_remediation_session(remediation_session_id)
    if rs is None:
        console.print(
            f"[red]Error:[/red] Remediation session {remediation_session_id} not found"
        )
        sys.exit(1)

    rems = store.get_remediations(rs.id, host=filter_host)
    if filter_rule:
        rems = [r for r in rems if r.rule_id == filter_rule]

    if json_output:
        _rollback_info_json(rs, rems, store, detail)
        return

    # Header
    console.print(f"[bold]Remediation Session #{rs.id}[/bold]")
    console.print()

    # Session metadata
    hosts = sorted({r.host for r in rems})
    mode = "dry-run" if rs.dry_run else "live (not dry-run)"
    rollback_mode = "on-failure (enabled)" if rs.rollback_on_failure else "manual only"
    console.print(f"  Timestamp:   {rs.timestamp}")
    console.print(f"  Host(s):     {', '.join(hosts) if hosts else 'none'}")
    console.print(f"  Mode:        {mode}")
    console.print(f"  Snapshot:    {rs.snapshot_mode}")
    console.print(f"  Rollback:    {rollback_mode}")
    console.print()

    # Counts
    remediated = [r for r in rems if r.remediated]
    rolled_back = [r for r in rems if r.rolled_back]
    console.print(f"  Rules processed:    {len(rems)}")
    console.print(f"  Rules remediated:   {len(remediated)}")
    if rolled_back:
        console.print(f"  Rules rolled back:  [magenta]{len(rolled_back)}[/magenta]")
    console.print()

    # Remediated rules summary
    if remediated:
        console.print("[bold]  Remediated rules:[/bold]")
        for r in remediated:
            if r.rolled_back:
                steps = store.get_remediation_steps(r.id)
                step_count = len(steps)
                reversed_count = 0
                for step in steps:
                    events = store.get_rollback_events(step.id)
                    reversed_count += sum(1 for e in events if e.success)
                console.print(
                    f"    [red]FAIL[/red]  {r.rule_id:<40s} "
                    f"(rolled back — {step_count} step{'s' if step_count != 1 else ''}, "
                    f"{reversed_count} reversed)"
                )
            elif r.passed_after:
                console.print(f"    [green]PASS[/green]  {r.rule_id}")
            else:
                console.print(f"    [red]FAIL[/red]  {r.rule_id}")
        console.print()

    # Non-rollbackable steps
    non_capturable = []
    for r in remediated:
        steps = store.get_remediation_steps(r.id)
        for step in steps:
            if not step.pre_state_capturable:
                non_capturable.append((r.rule_id, step))

    if non_capturable:
        console.print("[bold]  Non-rollbackable steps encountered:[/bold]")
        for rule_id, step in non_capturable:
            console.print(
                f"    {rule_id}  step {step.step_index}: {step.mechanism}  "
                f"[dim](not capturable)[/dim]"
            )
        console.print()

    # Detailed per-step info
    if detail:
        console.print("[bold]  Step Details:[/bold]")
        for r in rems:
            if not r.remediated:
                continue
            console.print()
            status = "[green]PASS[/green]" if r.passed_after else "[red]FAIL[/red]"
            suffix = "  [magenta](rolled back)[/magenta]" if r.rolled_back else ""
            console.print(f"  {r.rule_id}  [{status}]{suffix}")

            steps = store.get_remediation_steps(r.id)
            for step in steps:
                step_status = "[green]ok[/green]" if step.success else "[red]FAIL[/red]"
                console.print(
                    f"    Step {step.step_index}: {step.mechanism}  [{step_status}]"
                )

                # Pre-state
                if step.pre_state_data is not None:
                    console.print("      Pre-state:")
                    for k, v in step.pre_state_data.items():
                        val_str = str(v)
                        if len(val_str) > 80:
                            val_str = val_str[:77] + "..."
                        console.print(f"        {k}: {val_str}")
                elif not step.pre_state_capturable:
                    console.print(
                        f"      Pre-state: [dim]not capturable ({step.mechanism})[/dim]"
                    )

                # Rollback events
                events = store.get_rollback_events(step.id)
                for event in events:
                    rb_status = (
                        "[green]ok[/green]" if event.success else "[red]FAIL[/red]"
                    )
                    detail_str = f"  {event.detail}" if event.detail else ""
                    console.print(
                        f"      Rollback ({event.source}): [{rb_status}]{detail_str}"
                    )


def _rollback_info_json(rs, rems, store, detail: bool) -> None:
    """Output rollback info as JSON."""
    import json

    hosts = sorted({r.host for r in rems})
    output: dict = {
        "id": rs.id,
        "timestamp": rs.timestamp.isoformat(),
        "hosts": hosts,
        "dry_run": rs.dry_run,
        "rollback_on_failure": rs.rollback_on_failure,
        "snapshot_mode": rs.snapshot_mode,
        "summary": {
            "total_rules": len(rems),
            "remediated": sum(1 for r in rems if r.remediated),
            "rolled_back": sum(1 for r in rems if r.rolled_back),
        },
        "remediations": [],
    }

    for r in rems:
        rem_data: dict = {
            "rule_id": r.rule_id,
            "host": r.host,
            "severity": r.severity,
            "passed_before": r.passed_before,
            "passed_after": r.passed_after,
            "remediated": r.remediated,
            "rolled_back": r.rolled_back,
            "detail": r.detail,
        }

        if detail and r.remediated:
            steps_data = []
            steps = store.get_remediation_steps(r.id)
            for step in steps:
                step_data: dict = {
                    "step_index": step.step_index,
                    "mechanism": step.mechanism,
                    "success": step.success,
                    "detail": step.detail,
                    "pre_state_capturable": step.pre_state_capturable,
                    "pre_state_data": step.pre_state_data,
                }
                events = store.get_rollback_events(step.id)
                if events:
                    step_data["rollback_events"] = [
                        {
                            "mechanism": e.mechanism,
                            "success": e.success,
                            "detail": e.detail,
                            "source": e.source,
                            "timestamp": e.timestamp.isoformat(),
                        }
                        for e in events
                    ]
                steps_data.append(step_data)
            rem_data["steps"] = steps_data

        output["remediations"].append(rem_data)

    # This is the last print in _rollback_info_json
    print(json.dumps(output, indent=2))


def _rollback_start(
    store,
    remediation_session_id: int,
    *,
    target_host: str,
    host_info,
    rule_filter: str | None,
    password: str | None,
    sudo: bool,
    strict_host_keys: bool,
    dry_run: bool,
    force: bool,
) -> None:
    """Execute rollback from stored pre-state snapshots."""
    from datetime import datetime, timedelta

    host = target_host

    rs = store.get_remediation_session(remediation_session_id)
    if rs is None:
        console.print(
            f"[red]Error:[/red] Remediation session {remediation_session_id} not found"
        )
        sys.exit(1)

    # Get remediations for this session filtered to the target host
    rems = store.get_remediations(rs.id, host=host)
    if not rems:
        # Check if there are remediations for other hosts
        all_rems = store.get_remediations(rs.id)
        stored_hosts = sorted({r.host for r in all_rems})
        console.print(
            f"[red]Error:[/red] Host {host} not found in session #{rs.id}. "
            f"Stored hosts: {', '.join(stored_hosts)}"
        )
        sys.exit(1)

    if rule_filter:
        rems = [r for r in rems if r.rule_id == rule_filter]
        if not rems:
            console.print(
                f"[red]Error:[/red] Rule {rule_filter} not found in session #{rs.id}"
            )
            sys.exit(1)

    # Only process remediated rules
    rems = [r for r in rems if r.remediated]
    if not rems:
        console.print("[yellow]No remediated rules to roll back[/yellow]")
        return

    # Collect all steps and check rollback eligibility
    all_steps = []
    already_rolled_back = 0
    non_capturable = 0
    for r in rems:
        steps = store.get_remediation_steps(r.id)
        for step in steps:
            if not step.success:
                continue  # Nothing to undo
            events = store.get_rollback_events(step.id)
            if events and not force:
                already_rolled_back += 1
                continue  # Already rolled back
            if not step.pre_state_capturable or step.pre_state_data is None:
                non_capturable += 1
                continue
            all_steps.append((r, step))

    if not all_steps:
        if already_rolled_back > 0:
            console.print(
                f"[yellow]All {already_rolled_back} eligible step(s) already "
                f"rolled back.[/yellow] Use --force to re-execute."
            )
        else:
            console.print("[yellow]No rollbackable steps found[/yellow]")
        return

    # Stale snapshot warning
    active_days = 7
    age = datetime.now() - rs.timestamp
    if age > timedelta(days=active_days) and not force:
        console.print(
            f"[yellow]Warning:[/yellow] Remediation session #{rs.id} is "
            f"{age.days} days old (active window: {active_days} days)."
        )
        console.print(
            "The system may have changed since the snapshot was taken. "
            "Use --force to proceed."
        )
        sys.exit(1)

    # Show summary
    step_count = len(all_steps)
    rule_ids = sorted({r.rule_id for r, _ in all_steps})
    console.print(f"[bold]Rollback Session #{rs.id}[/bold]")
    console.print(f"  Host:    {host}")
    console.print(f"  Rules:   {len(rule_ids)}")
    console.print(f"  Steps:   {step_count}")
    if already_rolled_back:
        console.print(f"  Skipped: {already_rolled_back} (already rolled back)")
    if non_capturable:
        console.print(f"  Skipped: {non_capturable} (not capturable)")
    console.print()

    if dry_run:
        console.print("[bold]Dry-run — steps that would be executed:[/bold]")
        console.print()
        for r, step in all_steps:
            console.print(
                f"  {r.rule_id}  step {step.step_index}: "
                f"{step.mechanism}  [dim](reverse)[/dim]"
            )
            if step.pre_state_data:
                for k, v in step.pre_state_data.items():
                    val_str = str(v)
                    if len(val_str) > 60:
                        val_str = val_str[:57] + "..."
                    console.print(f"    restore {k} = {val_str}")
        console.print()
        console.print(
            f"[dim]{step_count} step(s) would be reversed "
            f"(dry-run, no action taken)[/dim]"
        )
        return

    # Execute rollback via SSH
    from runner._orchestration import rollback_from_stored

    console.print("[bold]Executing rollback...[/bold]")
    console.print()

    # Collect step records for rollback
    step_records = [step for _, step in all_steps]

    try:
        with connect(
            host_info, password, sudo=sudo, strict_host_keys=strict_host_keys
        ) as ssh:
            results = rollback_from_stored(ssh, step_records)
    except Exception as exc:
        console.print(f"[red]Error:[/red] SSH connection failed: {exc}")
        sys.exit(1)

    # Persist rollback events and display results
    success_count = 0
    fail_count = 0
    for rb_result in results:
        # Find the matching step record to get its db id
        matching_step = None
        for _, step in all_steps:
            if step.step_index == rb_result.step_index:
                matching_step = step
                break

        if matching_step is not None:
            store.record_rollback_event(
                matching_step.id,
                rb_result.mechanism,
                rb_result.success,
                rb_result.detail,
                source="manual",
            )

        status = "[green]ok[/green]" if rb_result.success else "[red]FAIL[/red]"
        console.print(
            f"  Step {rb_result.step_index}: {rb_result.mechanism}  [{status}]"
            f"  {rb_result.detail}"
        )
        if rb_result.success:
            success_count += 1
        else:
            fail_count += 1

    # Mark remediations as rolled_back
    rolled_rem_ids = set()
    for r, _ in all_steps:
        if r.id not in rolled_rem_ids:
            store.mark_remediation_rolled_back(r.id)
            rolled_rem_ids.add(r.id)

    console.print()
    if fail_count == 0:
        console.print(
            f"[green]Rollback complete:[/green] {success_count} step(s) reversed"
        )
    else:
        console.print(
            f"[red]Rollback completed with errors:[/red] "
            f"{success_count} ok, {fail_count} failed"
        )


if __name__ == "__main__":
    main()
