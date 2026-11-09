"""Validate the existing CI snapshot once and retain precisely the bytes tested."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

from artifact_inventory import sha, verify_checksum_inventory
from candidate_bundle import binding_for, matrix_evidence_paths, require, seal_bundle, verify_bundle


def safe_env():
    # No signing keys, tokens, agent/host targets or dynamic-library overrides.
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR') if k in os.environ}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    return env


def run_check(command, log):
    with log.open('w') as output:
        subprocess.run([str(v) for v in command], env=safe_env(), stdout=output,
                       stderr=subprocess.STDOUT, timeout=5400, check=True)


def retain_matrix_evidence(matrix, results):
    """Keep raw verification records; never copy extracted executables or operational keys."""
    manifest = json.loads((matrix / 'artifact-manifest.json').read_text())['artifacts']
    records = matrix_evidence_paths(manifest)
    for name in records:
        path = matrix / name
        require(path.is_file() and not path.is_symlink(), 'missing matrix evidence: ' + name)
    for name in records:
        dest = results / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(matrix / name, dest)
    # These are synthetic fixtures and public keys created by the verifier.
    # All initial fixture files must also match the retained hash inventory.
    for name in ('matrix-fixtures', 'additional-controls'):
        for path in (matrix / name).rglob('*'):
            if path.is_file() and path.suffix in ('.json', '.pub'):
                require(not path.is_symlink(), 'symlink in matrix evidence')
                dest = results / path.relative_to(matrix)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, dest)


def main():
    if not __debug__:
        raise RuntimeError('validation requires Python assertions enabled')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'dist', 'out', 'inputs'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('sha', 'repository', 'run-id', 'attempt', 'workflow-ref'):
        parser.add_argument('--' + name, required=True)
    a = parser.parse_args()
    source, dist, out = a.source.resolve(), a.dist.resolve(), a.out.resolve()
    git = lambda *args: subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    require(git('rev-parse', 'HEAD') == a.sha, 'checkout does not match candidate')
    require(not git('diff', '--name-only', 'HEAD'), 'tracked source changed during build')
    version = (source / 'VERSION').read_text().strip() + '-SNAPSHOT-' + a.sha[:7]
    binding = binding_for(a.sha, git('rev-parse', 'HEAD^{tree}'), a.repository,
                          a.run_id, a.attempt, a.workflow_ref, version)
    lock_path = source / 'scripts/candidate-inputs.toml'
    lock = tomllib.loads(lock_path.read_text())
    inputs = json.loads(a.inputs.read_text())
    require(inputs['lock_sha256'] == sha(lock_path) and inputs['pins'] == lock, 'input lock mismatch')
    import cryptography
    require(cryptography.__version__ == lock['cryptography']['version'], 'wrong cryptography version')
    for name, pin in lock['ubuntu'].items():
        installed = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', name], text=True)
        require(installed == pin['version'], 'tool package drift: ' + name)
    qemu, legacy = Path(inputs['qemu']), Path(inputs['legacy_archive'])
    require(sha(qemu) == lock['qemu']['binary_sha256'], 'QEMU hash mismatch')
    require(sha(legacy) == lock['legacy']['sha256'], 'historical verifier archive hash mismatch')
    checks, inventory, sbom = verify_checksum_inventory(dist, version)
    document = json.loads(sbom.read_text())
    require(document['bomFormat'] == 'CycloneDX' and document['components'], 'invalid SBOM')
    # Preserve the existing CI requirement for every shipping direct module.
    go_env = dict(safe_env(), GOFLAGS='-mod=readonly')
    production = subprocess.check_output(['go', 'list', '-deps', './...'], cwd=source, env=go_env, text=True).splitlines()
    direct = subprocess.check_output(['go', 'list', '-m', '-f', '{{if not .Indirect}}{{.Path}}{{end}}', 'all'],
                                     cwd=source, env=go_env, text=True).splitlines()
    for module in direct:
        if module and module != 'github.com/Hanalyx/kensa' and any(p == module or p.startswith(module + '/') for p in production):
            require(module in sbom.read_text(), 'shipping direct dependency missing from SBOM: ' + module)
    before = {n: sha(dist / n) for n in [*inventory, checks.name]}
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    matrix = out / 'matrix'
    run_check([sys.executable, '-B', source / 'scripts/artifact_matrix.py',
               '--source', source, '--dist', dist, '--out', matrix, '--version', version,
               '--qemu', qemu, '--legacy-archive', legacy], out / 'artifact-matrix.log')
    run_check([sys.executable, '-B', source / 'scripts/artifact_controls.py',
               '--source', source, '--matrix-out', matrix, '--qemu', qemu, '--version', version],
              out / 'artifact-controls.log')
    require(before == {n: sha(dist / n) for n in before}, 'artifact changed during verification')
    require(not git('diff', '--name-only', 'HEAD'), 'verification changed tracked source')
    bundle = out / 'bundle'
    payloads, results = bundle / 'payloads', bundle / 'results'
    payloads.mkdir(parents=True)
    results.mkdir()
    for name, digest in before.items():
        shutil.copyfile(dist / name, payloads / name)
        require(sha(payloads / name) == digest, 'copy changed artifact: ' + name)
    retain_matrix_evidence(matrix, results)
    for name in ('artifact-matrix.log', 'artifact-controls.log'):
        shutil.copyfile(out / name, results / name)
    tools = {}
    for name in ('go', 'goreleaser', 'syft', 'python3', 'rpm', 'rpm2cpio', 'cpio', 'readelf', 'dpkg-deb'):
        path = Path(shutil.which(name)).resolve()
        tools[name] = {'sha256': sha(path)}
    tools['goreleaser']['module'] = subprocess.check_output(['go', 'version', '-m', shutil.which('goreleaser')], text=True)
    require('\tmod\tgithub.com/goreleaser/goreleaser/v2\tv2.15.4\t' in tools['goreleaser']['module'],
            'GoReleaser provenance differs from existing CI pin')
    tools['syft']['version'] = subprocess.check_output(['syft', 'version'], text=True)
    require('1.46.0' in tools['syft']['version'], 'Syft version mismatch')
    (results / 'input-provenance.json').write_text(json.dumps({'inputs': inputs, 'tools': tools}, indent=2) + '\n')
    validation = {'status': 'passed', 'binding': binding, 'artifact_hashes': before,
                  'arm64': 'QEMU user emulation; not native managed-host testing',
                  'packages': 'extracted, not installed', 'rebuilt_during_verification': False}
    (results / 'validation.json').write_text(json.dumps(validation, indent=2) + '\n')
    (bundle / 'BINDING.json').write_text(json.dumps(binding, indent=2) + '\n')
    seal_bundle(bundle)
    verify_bundle(bundle, binding)
    print(json.dumps({'status': 'passed', 'binding': binding, 'bundle': str(bundle)}, indent=2))


if __name__ == '__main__':
    main()
