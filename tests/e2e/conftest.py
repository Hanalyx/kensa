"""E2E test fixtures for container and live host testing.

Manages container lifecycle (build, start, stop, remove) and provides
SSH connection details to tests. Supports both podman and docker.

Usage:
    pytest tests/e2e/ -m container          # Container tier only
    pytest tests/e2e/ -m livehost           # Live hosts only
    pytest tests/e2e/                       # Both tiers

Container fixtures generate an ephemeral SSH key pair per session,
inject it into the container, and clean up on teardown.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

CONTAINERS_DIR = Path(__file__).parent / "containers"
IMAGE_PREFIX = "kensa-e2e"
NETWORK_NAME = "kensa_network"
SSH_USER = "kensa-test"
CONTAINER_STARTUP_TIMEOUT = 30
SSH_READY_TIMEOUT = 30


@dataclass
class E2EHost:
    """Connection details for an E2E test target."""

    host: str
    port: int
    user: str
    key_path: str
    distro: str  # "el8" or "el9"
    is_container: bool


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
