"""E2E test fixtures for container and live host testing.

Manages container lifecycle (build, start, stop, remove) and provides
SSH connection details to tests. Supports both podman and docker.

Usage:
    pytest tests/e2e/ -m container          # Container tier only
    pytest tests/e2e/ -m livehost           # Live hosts only
    pytest tests/e2e/                       # Both tiers

Container fixtures generate an ephemeral SSH key pair per session,
inject it into the container, and clean up on teardown.

Live host fixtures read targets from the project inventory.ini file.
Hosts, IPs, and users may change — the inventory path is the constant.

Result storage:
    Every run_kensa() invocation persists its output to results/e2e/<timestamp>/.
    For commands that support -o (check, remediate), JSON, CSV, evidence, and
    PDF outputs are captured alongside stdout/stderr and a meta.json manifest.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest

# ── Paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONTAINERS_DIR = Path(__file__).parent / "containers"
INVENTORY_PATH = PROJECT_ROOT / "inventory.ini"
RESULTS_BASE = PROJECT_ROOT / "results" / "e2e"

# ── Result storage constants ─────────────────────────────────────────────────
OUTPUT_COMMANDS = {"check", "remediate"}  # Commands that support -o flags

# ── Container constants ──────────────────────────────────────────────────────
IMAGE_PREFIX = "kensa-e2e"
NETWORK_NAME = "kensa_network"
SSH_USER = "kensa-test"
CONTAINER_STARTUP_TIMEOUT = 30
SSH_READY_TIMEOUT = 30

# ── Module-level test context (set by autouse fixture) ───────────────────────
_current_test_ctx: E2ETestContext | None = None


@dataclass
class E2ETestContext:
    """Tracks test identity, output directory, and step counter."""

    test_name: str  # e.g. "TestCheckKnownBadE2E::test_gpgcheck_fails"
    test_module: str  # e.g. "test_check_cycle"
    output_dir: Path  # e.g. results/e2e/<ts>/test_check_cycle/TestCheck...
    step_count: int = 0
    first_step_subcommand: str = ""

    def next_step(self, subcommand: str) -> Path:
        """Return the output path for the next run_kensa step.

        For single-call tests, returns output_dir directly.
        When step 2 triggers, retroactively moves step-1 files into
        step_001_<cmd>/ and returns step_002_<cmd>/.
        """
        self.step_count += 1

        if self.step_count == 1:
            self.first_step_subcommand = subcommand
            return self.output_dir

        if self.step_count == 2:
            _promote_to_multistep(self.output_dir, self.first_step_subcommand)

        step_dir = self.output_dir / f"step_{self.step_count:03d}_{subcommand}"
        step_dir.mkdir(parents=True, exist_ok=True)
        return step_dir


@dataclass
class E2EHost:
    """Connection details for an E2E test target."""

    host: str
    port: int
    user: str
    key_path: str | None = None
    distro: str = "unknown"
    is_container: bool = False
    sudo: bool = False
    groups: list[str] = field(default_factory=list)


def _extract_subcommand(args: list[str]) -> str:
    """Extract the kensa subcommand from args (first non-flag arg)."""
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return "unknown"


def _promote_to_multistep(output_dir: Path, first_subcommand: str) -> None:
    """Move flat step-1 files into step_001_<cmd>/ subdirectory."""
    step1_dir = output_dir / f"step_001_{first_subcommand}"
    step1_dir.mkdir(parents=True, exist_ok=True)

    for item in output_dir.iterdir():
        if item.is_file():
            item.rename(step1_dir / item.name)


def _save_run_artifacts(
    output_dir: Path,
    *,
    cmd: list[str],
    subcommand: str,
    host: E2EHost,
    result: subprocess.CompletedProcess,
    start_time: datetime,
    duration: float,
    output_files: list[str],
    test_name: str,
    test_module: str,
) -> None:
    """Write stdout.log, stderr.log, and meta.json to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # stdout.log
    (output_dir / "stdout.log").write_text(result.stdout or "")

    # stderr.log
    (output_dir / "stderr.log").write_text(result.stderr or "")

    # meta.json
    meta = {
        "test_name": test_name,
        "test_module": test_module,
        "timestamp": start_time.isoformat(),
        "command": cmd,
        "subcommand": subcommand,
        "exit_code": result.returncode,
        "host": {
            "hostname": host.host,
            "port": host.port,
            "user": host.user,
            "distro": host.distro,
            "is_container": host.is_container,
        },
        "duration_seconds": round(duration, 3),
        "output_files": output_files,
    }
    (output_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")


def run_kensa(
    host: E2EHost, args: list[str], timeout: int = 120
) -> subprocess.CompletedProcess:
    """Run a kensa CLI command against an E2E host.

    Builds the CLI invocation from the host's connection details.
    Shared by both container and live host tests.

    When a test context is active, persists all output to the session
    results directory and appends -o flags for supported commands.
    """
    global _current_test_ctx

    subcommand = _extract_subcommand(args)
    output_dir: Path | None = None
    output_files: list[str] = []
    extra_args: list[str] = []

    if _current_test_ctx is not None:
        output_dir = _current_test_ctx.next_step(subcommand)
        output_dir.mkdir(parents=True, exist_ok=True)

        if subcommand in OUTPUT_COMMANDS:
            # JSON
            json_path = output_dir / "results.json"
            extra_args.extend(["-o", f"json:{json_path}"])
            output_files.append("results.json")

            # CSV
            csv_path = output_dir / "results.csv"
            extra_args.extend(["-o", f"csv:{csv_path}"])
            output_files.append("results.csv")

            # Evidence
            evidence_path = output_dir / "evidence.json"
            extra_args.extend(["-o", f"evidence:{evidence_path}"])
            output_files.append("evidence.json")

            # PDF (guarded by reportlab availability)
            try:
                import reportlab  # noqa: F401

                pdf_path = output_dir / "report.pdf"
                extra_args.extend(["-o", f"pdf:{pdf_path}"])
                output_files.append("report.pdf")
            except ImportError:
                pass

    cmd = [
        "python3",
        "-m",
        "runner.cli",
        *args,
        *extra_args,
        "--host",
        f"{host.user}@{host.host}:{host.port}",
    ]
    if host.key_path:
        cmd.extend(["--key", host.key_path])
    if host.sudo:
        cmd.append("--sudo")

    start_time = datetime.now(timezone.utc)
    t0 = time.monotonic()

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    duration = time.monotonic() - t0

    if _current_test_ctx is not None and output_dir is not None:
        # Filter output_files to only those actually created
        actual_files = [f for f in output_files if (output_dir / f).exists()]
        _save_run_artifacts(
            output_dir,
            cmd=cmd,
            subcommand=subcommand,
            host=host,
            result=result,
            start_time=start_time,
            duration=duration,
            output_files=actual_files,
            test_name=_current_test_ctx.test_name,
            test_module=_current_test_ctx.test_module,
        )

    return result


def _find_runtime() -> str | None:
    """Find an available container runtime (podman preferred)."""
    for runtime in ("podman", "docker"):
        if shutil.which(runtime):
            return runtime
    return None


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _run(
    cmd: list[str], *, check: bool = True, **kwargs
) -> subprocess.CompletedProcess:
    """Run a subprocess command with defaults."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check, **kwargs)


def _wait_for_ssh(host: str, port: int, key_path: str, user: str, timeout: int) -> bool:
    """Wait until SSH is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=2",
                    "-o",
                    "BatchMode=yes",
                    "-i",
                    key_path,
                    "-p",
                    str(port),
                    f"{user}@{host}",
                    "echo ready",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "ready" in result.stdout:
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass
        time.sleep(1)
    return False


def _ensure_network(runtime: str) -> None:
    """Create the kensa_network bridge network if it doesn't exist."""
    result = _run([runtime, "network", "inspect", NETWORK_NAME], check=False)
    if result.returncode != 0:
        _run([runtime, "network", "create", NETWORK_NAME])


def _remove_network(runtime: str) -> None:
    """Remove the kensa_network if it exists."""
    _run([runtime, "network", "rm", NETWORK_NAME], check=False)


def _build_image(runtime: str, distro: str) -> str:
    """Build a container image for the given distro."""
    image_name = f"{IMAGE_PREFIX}-{distro}"
    containerfile = CONTAINERS_DIR / f"Containerfile.{distro}"
    if not containerfile.exists():
        pytest.skip(f"No Containerfile for {distro}")

    _run([runtime, "build", "-t", image_name, "-f", str(containerfile), "."])
    return image_name


def _start_container(
    runtime: str,
    image: str,
    distro: str,
    ssh_port: int,
    pubkey_path: str,
    network: str = NETWORK_NAME,
) -> str:
    """Start a container on kensa_network and return its ID."""
    container_name = f"kensa-e2e-{distro}-{ssh_port}"

    # Remove any stale container with the same name
    _run([runtime, "rm", "-f", container_name], check=False)

    cmd = [
        runtime,
        "run",
        "-d",
        "--name",
        container_name,
        "--hostname",
        f"kensa-{distro}",
        "--network",
        network,
        "-p",
        f"{ssh_port}:22",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/run/lock",
        "-v",
        "/sys/fs/cgroup:/sys/fs/cgroup:ro",
    ]

    # Podman has native systemd support
    if runtime == "podman":
        cmd.extend(["--systemd=true"])
    else:
        cmd.extend(["--privileged"])

    cmd.append(image)
    result = _run(cmd)
    container_id = result.stdout.strip()

    # Inject the SSH public key into the container
    _run(
        [
            runtime,
            "exec",
            container_name,
            "bash",
            "-c",
            f"cat > /home/{SSH_USER}/.ssh/authorized_keys << 'KEYEOF'\n"
            f"{Path(pubkey_path).read_text()}"
            f"KEYEOF\n"
            f"chown {SSH_USER}:{SSH_USER} /home/{SSH_USER}/.ssh/authorized_keys && "
            f"chmod 600 /home/{SSH_USER}/.ssh/authorized_keys",
        ]
    )

    return container_id


def _stop_container(runtime: str, container_id: str) -> None:
    """Stop and remove a container."""
    _run([runtime, "stop", "-t", "5", container_id], check=False)
    _run([runtime, "rm", "-f", container_id], check=False)


# ── pytest configuration ──────────────────────────────────────────────────────


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "container: E2E tests using containers")
    config.addinivalue_line("markers", "livehost: E2E tests using live hosts")
    config.addinivalue_line("markers", "e2e: all E2E tests")


# ── Result storage fixtures ──────────────────────────────────────────────────


@pytest.fixture(scope="session")
def e2e_session_dir(request):
    """Create a timestamped session directory under results/e2e/.

    Writes session_meta.json on teardown with timing and test counts.
    """
    ts = datetime.now(timezone.utc)
    session_dir = RESULTS_BASE / ts.strftime("%Y-%m-%d_%H-%M-%S")
    session_dir.mkdir(parents=True, exist_ok=True)

    # Stash on config so the terminal summary hook can find it
    request.config._e2e_session_dir = session_dir
    request.config._e2e_session_start = ts

    yield session_dir

    # Write session summary on teardown
    duration = (datetime.now(timezone.utc) - ts).total_seconds()
    test_dirs = list(session_dir.rglob("meta.json"))
    meta = {
        "session_start": ts.isoformat(),
        "session_end": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(duration, 3),
        "total_runs": len(test_dirs),
        "results_dir": str(session_dir),
    }
    (session_dir / "session_meta.json").write_text(json.dumps(meta, indent=2) + "\n")


@pytest.fixture(autouse=True)
def _e2e_test_context(request, e2e_session_dir):
    """Set module-level test context before each test.

    Automatically active for all e2e tests. Provides run_kensa() with
    the test identity and output directory for result persistence.
    """
    global _current_test_ctx

    # Build test identity from pytest node
    node = request.node
    # Class::method or just function name
    test_name = f"{node.cls.__name__}::{node.name}" if node.cls else node.name

    # Module name without path prefix (e.g. "test_check_cycle")
    test_module = Path(node.fspath).stem

    # Directory name: TestClass__method or just method
    dir_name = test_name.replace("::", "__")
    output_dir = e2e_session_dir / test_module / dir_name

    _current_test_ctx = E2ETestContext(
        test_name=test_name,
        test_module=test_module,
        output_dir=output_dir,
    )

    yield

    _current_test_ctx = None


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print the results directory path at end of session."""
    session_dir = getattr(config, "_e2e_session_dir", None)
    if session_dir and session_dir.exists():
        # Count meta.json files to see how many runs were captured
        meta_count = len(list(session_dir.rglob("meta.json")))
        if meta_count > 0:
            terminalreporter.write_sep("=", "E2E result storage")
            terminalreporter.write_line(
                f"  {meta_count} run(s) saved to: {session_dir}"
            )


# ── Session-scoped fixtures ───────────────────────────────────────────────────


@pytest.fixture(scope="session")
def container_runtime():
    """Detect and return the available container runtime."""
    runtime = _find_runtime()
    if runtime is None:
        pytest.skip("No container runtime (podman or docker) found")
    return runtime


@pytest.fixture(scope="session")
def kensa_network(container_runtime):
    """Create an isolated Docker/Podman network for E2E tests.

    The network is created once per session and torn down after all
    container tests complete. Containers attach to this network so
    they are isolated from the host's default bridge.
    """
    _ensure_network(container_runtime)
    yield NETWORK_NAME
    _remove_network(container_runtime)


@pytest.fixture(scope="session")
def ssh_keypair(tmp_path_factory):
    """Generate an ephemeral SSH key pair for the test session."""
    key_dir = tmp_path_factory.mktemp("ssh")
    key_path = key_dir / "id_ed25519"
    _run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(key_path),
            "-N",
            "",
            "-q",
        ]
    )
    return str(key_path), str(key_path) + ".pub"


@pytest.fixture(scope="session")
def el9_container(container_runtime, ssh_keypair, kensa_network):
    """Build and start a Rocky Linux 9 container for E2E tests."""
    runtime = container_runtime
    key_path, pubkey_path = ssh_keypair
    ssh_port = _find_free_port()

    image = _build_image(runtime, "el9")
    container_id = _start_container(
        runtime, image, "el9", ssh_port, pubkey_path, network=kensa_network
    )

    # Wait for SSH to be ready
    if not _wait_for_ssh("127.0.0.1", ssh_port, key_path, SSH_USER, SSH_READY_TIMEOUT):
        # Capture logs for debugging
        logs = _run([runtime, "logs", container_id], check=False)
        _stop_container(runtime, container_id)
        pytest.fail(
            f"SSH not ready within {SSH_READY_TIMEOUT}s.\n"
            f"Container logs:\n{logs.stdout}\n{logs.stderr}"
        )

    host = E2EHost(
        host="127.0.0.1",
        port=ssh_port,
        user=SSH_USER,
        key_path=key_path,
        distro="el9",
        is_container=True,
    )

    yield host

    _stop_container(runtime, container_id)


@pytest.fixture(scope="session")
def el8_container(container_runtime, ssh_keypair, kensa_network):
    """Build and start a Rocky Linux 8 container for E2E tests."""
    runtime = container_runtime
    key_path, pubkey_path = ssh_keypair
    ssh_port = _find_free_port()

    image = _build_image(runtime, "el8")
    container_id = _start_container(
        runtime, image, "el8", ssh_port, pubkey_path, network=kensa_network
    )

    if not _wait_for_ssh("127.0.0.1", ssh_port, key_path, SSH_USER, SSH_READY_TIMEOUT):
        logs = _run([runtime, "logs", container_id], check=False)
        _stop_container(runtime, container_id)
        pytest.fail(
            f"SSH not ready within {SSH_READY_TIMEOUT}s.\n"
            f"Container logs:\n{logs.stdout}\n{logs.stderr}"
        )

    host = E2EHost(
        host="127.0.0.1",
        port=ssh_port,
        user=SSH_USER,
        key_path=key_path,
        distro="el8",
        is_container=True,
    )

    yield host

    _stop_container(runtime, container_id)


# ── Live host fixtures ───────────────────────────────────────────────────────


def _parse_inventory_hosts() -> list[E2EHost]:
    """Parse inventory.ini and return E2EHost entries.

    Reads the project inventory.ini (INI format with ansible_user).
    Returns an empty list if the file doesn't exist.
    """
    if not INVENTORY_PATH.exists():
        return []

    from runner.inventory import resolve_targets

    targets = resolve_targets(inventory=str(INVENTORY_PATH))
    hosts = []
    for t in targets:
        hosts.append(
            E2EHost(
                host=t.hostname,
                port=t.port,
                user=t.user or "root",
                key_path=t.key_path,
                distro="unknown",
                is_container=False,
                sudo=True,
                groups=list(t.groups),
            )
        )
    return hosts


@pytest.fixture(scope="session")
def livehost_targets() -> list[E2EHost]:
    """Resolve live hosts from inventory.ini.

    Skips if inventory.ini doesn't exist or contains no hosts.
    """
    hosts = _parse_inventory_hosts()
    if not hosts:
        pytest.skip("No live hosts in inventory.ini (file missing or empty)")
    return hosts


@pytest.fixture(scope="session")
def livehost(livehost_targets) -> E2EHost:
    """Return the first live host from inventory for single-host tests."""
    return livehost_targets[0]
