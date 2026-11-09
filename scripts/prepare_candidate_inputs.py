"""Fetch verified test inputs and install pinned validation tools on a disposable runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib
import urllib.request

LOCK = Path(__file__).with_name('candidate-inputs.toml')


def checked_bytes(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input SHA-256 mismatch; no fallback is permitted')
    return data


def prepare(dest):
    lock = tomllib.loads(LOCK.read_text())
    os_release = Path('/etc/os-release').read_text()
    if 'ID=ubuntu\n' not in os_release or 'VERSION_ID="24.04"' not in os_release:
        raise ValueError('candidate tools require Ubuntu 24.04')
    dest.mkdir(mode=0o700, parents=True, exist_ok=False)
    packages = []
    for name, pin in lock['ubuntu'].items():
        # Verify before apt can unpack or execute any downloaded package.
        with urllib.request.urlopen(pin['url'], timeout=120) as response:
            data = checked_bytes(response.read(), pin['sha256'])
        path = dest / (name + '.deb')
        path.write_bytes(data)
        packages.append(str(path))
    subprocess.run(['sudo', 'apt-get', 'update', '-qq'], check=True)
    subprocess.run(['sudo', 'apt-get', 'install', '-y', '--no-install-recommends', *packages], check=True)
    for name, pin in lock['ubuntu'].items():
        version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', name], text=True)
        if version != pin['version']:
            raise ValueError('installed version differs from pin: ' + name)
    qemu = Path('/usr/bin/qemu-aarch64-static')
    checked_bytes(qemu.read_bytes(), lock['qemu']['binary_sha256'])
    version = subprocess.check_output([str(qemu), '--version'], text=True).splitlines()[0]
    if ('version ' + lock['qemu']['version']) not in version:
        raise ValueError('wrong QEMU version')
    legacy = lock['legacy']
    # gh supplies read-only authentication for private repositories. No token is
    # written to disk or passed to the artifact-verification subprocesses.
    data = subprocess.check_output(['gh', 'api', f"repos/{legacy['repository']}/releases/assets/{legacy['asset_id']}",
                                    '-H', 'Accept: application/octet-stream'])
    archive = dest / legacy['filename']
    archive.write_bytes(checked_bytes(data, legacy['sha256']))
    record = {'lock_sha256': hashlib.sha256(LOCK.read_bytes()).hexdigest(),
              'pins': lock, 'qemu_version': version,
              'qemu': str(qemu), 'legacy_archive': str(archive),
              'os_packages': subprocess.check_output(['dpkg-query', '-W'], text=True)}
    (dest / 'inputs.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dest', type=Path, required=True)
    prepare(parser.parse_args().dest.resolve())
