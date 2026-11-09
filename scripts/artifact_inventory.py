"""Exact inventory and digest checks for unsigned Kensa snapshot outputs."""
from pathlib import Path
import hashlib
import re

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_checksum_inventory(dist, version):
    """Check the full unsigned artifact inventory and every SHA-256 digest."""
    checksum_files = sorted(p for p in dist.glob('*.sha256') if p.is_file())
    if len(checksum_files) != 1:
        raise ValueError('expected exactly one checksum file')
    checks = checksum_files[0]
    if checks.name != f'kensa_{version}_checksums.sha256':
        raise ValueError('unexpected checksum file name: ' + checks.name)
    payloads = {f'kensa_{version}_linux_{arch}{ending}'
                for arch in ('amd64', 'arm64')
                for ending in ('.tar.gz', '_with-rules.tar.gz', '.rpm', '.deb')}
    payloads.update(f'kensa-rules_{version}_noarch.{kind}' for kind in ('rpm', 'deb'))
    actual = {p.name for p in dist.iterdir() if p.is_file() and
              (p.name.endswith('.tar.gz') or p.suffix in ('.rpm', '.deb'))}
    if actual != payloads:
        raise ValueError('artifact inventory mismatch: missing=' + str(sorted(payloads - actual)) +
                         ' unexpected=' + str(sorted(actual - payloads)))
    sbom = dist / f'kensa_{version}_sbom.cdx.json'
    sbom_files = sorted(p for p in dist.glob('*_sbom.cdx.json') if p.is_file())
    if sbom_files != [sbom]:
        raise ValueError('expected exactly one version-matched SBOM')
    expected = payloads | {sbom.name}
    checksums = {}
    lines = checks.read_bytes().decode('ascii').split('\n')
    if lines[-1] == '':
        lines.pop()
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r'([0-9a-fA-F]{64}) [ *](.+)', line)
        if match is None:
            raise ValueError(f'malformed checksum entry on line {number}')
        digest, name = match.groups()
        if name in checksums:
            raise ValueError('duplicate checksum filename: ' + name)
        if name not in expected:
            raise ValueError('unexpected checksum filename: ' + name)
        checksums[name] = digest.lower()
    if set(checksums) != expected:
        raise ValueError('checksum coverage mismatch: missing=' +
                         str(sorted(expected - set(checksums))))
    for name, digest in checksums.items():
        if sha(dist / name) != digest:
            raise ValueError('checksum digest mismatch: ' + name)
    return checks, checksums, sbom
