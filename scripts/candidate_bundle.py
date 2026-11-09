"""Bind tested snapshot bytes and verification results without rebuilding them."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import tomllib
import zipfile

from artifact_inventory import sha, verify_checksum_inventory

REQUIRED_RESULTS = {'artifact-manifest.json', 'artifact-matrix-summary.json',
                    'additional-controls/results.json', 'input-provenance.json',
                    'validation.json', 'artifact-matrix.log', 'artifact-controls.log',
                    'matrix-input-hashes.json', 'released-v0.12.0/actual-cli-compatibility.json'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def artifact_name(sha_value, run_id, attempt):
    require(re.fullmatch(r'[0-9a-f]{40}', sha_value), 'invalid candidate SHA')
    require(str(run_id).isdigit() and int(run_id) > 0, 'invalid run id')
    require(str(attempt).isdigit() and int(attempt) > 0, 'invalid run attempt')
    return f'kensa-snapshot-{sha_value}-{run_id}-{attempt}'


def binding_for(sha_value, tree, repository, run_id, attempt, workflow_ref, version):
    name = artifact_name(sha_value, run_id, attempt)
    require(re.fullmatch(r'[0-9a-f]{40}', tree), 'invalid source tree')
    require(repository == 'Hanalyx/kensa', 'unexpected repository')
    require(workflow_ref.startswith(repository + '/.github/workflows/ci.yml@'), 'unexpected workflow')
    return {'candidate_sha': sha_value, 'source_tree': tree, 'repository': repository,
            'run_id': str(run_id), 'run_attempt': str(attempt), 'workflow_ref': workflow_ref,
            'snapshot_version': version, 'artifact_name': name, 'unsigned': True,
            'retention_days': 90, 'build_count': 1}


def matrix_evidence_paths(artifacts):
    """Required raw records emitted by the existing matrix, excluding payloads."""
    paths = {'artifact-manifest.json', 'artifact-matrix-summary.json',
             'matrix-input-hashes.json', 'released-v0.12.0/actual-cli-compatibility.json'}
    for item in artifacts:
        name = Path(item['artifact']).name
        if not name.startswith('kensa-rules_'):
            paths.add('matrix-output/' + name + '.json')
        if name.endswith('.rpm'):
            paths.add('extracted/' + name + '.rpm-digests.json')
    return paths


def validate_matrix_records(results, artifacts, summary, payload_hashes, version):
    require(all((results / name).is_file() for name in matrix_evidence_paths(artifacts)),
            'missing underlying matrix evidence')
    by_name = {Path(item['artifact']).name: item for item in artifacts}
    cli_names = {n for n in by_name if not n.startswith('kensa-rules_')}
    actual_cli = {p.name for p in (results / 'matrix-output').glob('*.json')}
    require(actual_cli == {n + '.json' for n in cli_names}, 'CLI result inventory mismatch')
    total = 0
    for row in summary['artifact_results']:
        name = row['artifact']
        item = by_name[name]
        path = results / 'matrix-output' / (name + '.json')
        require(row.get('evidence_sha256') == sha(path), 'CLI result file hash mismatch')
        require(Path(row.get('evidence', '')).name == path.name, 'CLI summary evidence identity mismatch')
        record = json.loads(path.read_text())
        require(record.get('artifact') == item, 'CLI record artifact binding mismatch')
        architecture = 'arm64' if '_arm64' in name else 'amd64'
        require(item.get('contains_cli') is True and item.get('architecture') == architecture and
                row['architecture'] == architecture, 'CLI architecture binding mismatch')
        binary_hash = item.get('binary_sha256')
        require(isinstance(binary_hash, str) and re.fullmatch(r'[0-9a-f]{64}', binary_hash) and
                row.get('binary_sha256') == binary_hash and
                row.get('artifact_sha256') == payload_hashes[name], 'CLI summary hash binding mismatch')
        runs = record.get('runs')
        require(isinstance(runs, list) and type(row['runs']) is int and
                len(runs) == row['runs'] and row['runs'] > 0, 'CLI result run count mismatch')
        prefix = record['version']['argv'][:-1]
        require(len(prefix) == (2 if architecture == 'arm64' else 1) and prefix[-1] == item['binary'] and
                record['version']['argv'][-1] == 'version' and record['version']['exit'] == 0 and
                record['version']['stdout'].split()[1:2] == [version], 'CLI version record mismatch')
        require(record['help']['argv'] == prefix + ['verify', '--help'] and
                record['help']['exit'] == 0 and '--accept-legacy-v1' in record['help']['stdout'],
                'CLI help record mismatch')
        for run in runs:
            require(isinstance(run, dict) and isinstance(run.get('argv'), list) and
                    run['argv'][:len(prefix) + 1] == prefix + ['verify'] and
                    type(run.get('exit')) is int and run['exit'] in (0, 1, 2) and
                    isinstance(run.get('stdout'), str) and isinstance(run.get('stderr'), str),
                    'CLI response binding mismatch')
        total += len(runs)
    require(type(summary.get('candidate_cli_runs')) is int and summary['candidate_cli_runs'] == total,
            'aggregate CLI run count mismatch')

    path = results / 'matrix-input-hashes.json'
    require(summary.get('fixture_hash_inventory_sha256') == sha(path), 'fixture inventory hash mismatch')
    fixtures = json.loads(path.read_text())
    actual = {str(p.relative_to(results / 'matrix-fixtures')) for p in (results / 'matrix-fixtures').rglob('*') if p.is_file()}
    require(isinstance(fixtures, dict) and {'v1-valid.json', 'v2-valid.json'} <= set(fixtures) and
            actual == set(fixtures), 'fixture inventory coverage mismatch')
    for name, digest in fixtures.items():
        require(sha(results / 'matrix-fixtures' / name) == digest, 'fixture hash mismatch')

    expected_rpm = {n + '.rpm-digests.json': n for n in by_name if n.endswith('.rpm')}
    rpm_hashes = summary.get('rpm_digest_records', {})
    require(set(rpm_hashes) == set(expected_rpm) and
            {p.name for p in (results / 'extracted').glob('*.rpm-digests.json')} == set(expected_rpm),
            'RPM digest record inventory mismatch')
    for filename, name in expected_rpm.items():
        path = results / 'extracted' / filename
        require(sha(path) == rpm_hashes[filename], 'RPM digest record hash mismatch')
        record = json.loads(path.read_text())
        require(record['argv'] == ['rpm', '-Kv', by_name[name]['artifact']] and record['exit'] == 0 and
                'Header SHA256 digest: OK' in record['stdout'] and
                'Payload SHA256 digest: OK' in record['stdout'], 'RPM digest record binding mismatch')

    path = results / 'released-v0.12.0/actual-cli-compatibility.json'
    require(summary.get('published_verifier_evidence_sha256') == sha(path), 'published verifier record hash mismatch')
    published = json.loads(path.read_text())
    pin = tomllib.loads(Path(__file__).with_name('candidate-inputs.toml').read_text())['legacy']
    provenance = json.loads((results / 'input-provenance.json').read_text())
    require(provenance['inputs']['pins']['legacy'] == pin and
            published.get('binary_sha256') == pin['binary_sha256'], 'published verifier binary binding mismatch')
    runs = published.get('runs')
    require(isinstance(runs, list) and len(runs) == 2 and
            {r['fixture_version'] for r in runs} == {'v1', 'v2'}, 'published verifier response inventory mismatch')
    executable = runs[0]['argv'][0]
    require(Path(executable).name == 'kensa', 'published verifier executable mismatch')
    for run in runs:
        schema = run['fixture_version']
        argv = run['argv']
        require(len(argv) == 7 and argv[0] == executable and argv[1] == 'verify' and
                Path(argv[2]).name == schema + '-valid.json' and argv[3] == '--trust-dir' and
                argv[5:] == ['--format', 'json'], 'published verifier response binding mismatch')
        require(type(run['exit']) is int and run['exit'] == (0 if schema == 'v1' else 1) and
                json.loads(run['stdout'])['valid'] is (schema == 'v1'), 'published verifier response outcome mismatch')
        if schema == 'v2':
            require('unknown schema_version' in run['stderr'], 'published verifier v2 rejection mismatch')


def validate_results(root, binding):
    results = root / 'results'
    require(all((results / name).is_file() for name in REQUIRED_RESULTS), 'missing verification results')
    validation = json.loads((results / 'validation.json').read_text())
    require(validation['status'] == 'passed', 'verification did not pass')
    require(validation['binding'] == binding, 'verification binding mismatch')
    checks, inventory, sbom = verify_checksum_inventory(root / 'payloads', binding['snapshot_version'])
    payload_hashes = {name: sha(root / 'payloads' / name) for name in [*inventory, checks.name]}
    require(validation['artifact_hashes'] == payload_hashes, 'tested bytes differ from retained bytes')
    document = json.loads(sbom.read_text())
    require(document['bomFormat'] == 'CycloneDX' and document['components'], 'invalid SBOM')
    manifest = json.loads((results / 'artifact-manifest.json').read_text())['artifacts']
    expected = set(inventory) - {sbom.name}
    require(len(manifest) == 10 and {Path(m['artifact']).name for m in manifest} == expected,
            'artifact verification inventory incomplete or duplicated')
    for item in manifest:
        name = Path(item['artifact']).name
        require(item['artifact_sha256'] == payload_hashes[name], 'artifact result hash mismatch')
    cli_names = {n for n in expected if not n.startswith('kensa-rules_')}
    summary = json.loads((results / 'artifact-matrix-summary.json').read_text())
    rows = summary['artifact_results']
    require(len(rows) == 8 and {r['artifact'] for r in rows} == cli_names, 'missing packaged CLI variant')
    require(all(r['result'] == 'pass' and r['runs'] > 0 for r in rows), 'packaged CLI verification failed')
    require(summary['candidate_version'] == binding['snapshot_version'] and
            summary['published_v012_valid_v1_and_rejects_v2'] is True and
            summary['fixture_and_key_files_unchanged'] is True and
            summary['binary_files_unchanged'] is True, 'matrix contract failed')
    validate_matrix_records(results, manifest, summary, payload_hashes, binding['snapshot_version'])
    controls = json.loads((results / 'additional-controls/results.json').read_text())
    require(controls['status'] == 'passed' and controls['numeric_cli'] and
            controls['independent_numeric'] and controls['artifact_metadata'], 'missing numeric/metadata evidence')


def seal_bundle(root):
    binding = json.loads((root / 'BINDING.json').read_text())
    validate_results(root, binding)
    files = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'symlink in candidate evidence')
        if path.is_file():
            files[str(path.relative_to(root))] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    require('MANIFEST.json' not in files, 'refuse to reseal an existing bundle')
    (root / 'MANIFEST.json').write_text(json.dumps({'binding': binding, 'files': files}, indent=2) + '\n')


def verify_bundle(root, expected):
    binding = json.loads((root / 'BINDING.json').read_text())
    for key, value in expected.items():
        require(binding[key] == value, 'binding mismatch: ' + key)
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    require(manifest['binding'] == binding, 'manifest binding mismatch')
    actual = {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    require(actual == set(manifest['files']) | {'MANIFEST.json'}, 'bundle coverage mismatch')
    require(not any(p.is_symlink() for p in root.rglob('*')), 'symlink in bundle')
    for name, info in manifest['files'].items():
        path = root / name
        require(sha(path) == info['sha256'] and path.stat().st_size == info['bytes'], 'bundle hash mismatch: ' + name)
    validate_results(root, binding)
    return binding


def unpack_verified_zip(archive, artifact, run, dest, expected):
    require(run['head_sha'] == expected['candidate_sha'] and str(run['id']) == expected['run_id'] and
            str(run['run_attempt']) == expected['run_attempt'], 'wrong workflow run/head/attempt')
    require(run['status'] == 'completed' and run['conclusion'] == 'success', 'workflow did not succeed')
    require(run['path'] == '.github/workflows/ci.yml' and
            run['event'] in ('workflow_dispatch', 'schedule') and
            run['repository']['full_name'] == expected['repository'], 'wrong workflow/repository/event')
    require(str(artifact['id']) == expected['artifact_id'] and not artifact['expired'], 'wrong or expired artifact')
    require(artifact['name'] == artifact_name(expected['candidate_sha'], expected['run_id'], expected['run_attempt']),
            'wrong artifact name')
    require(str(artifact['workflow_run']['id']) == expected['run_id'] and
            artifact['workflow_run']['head_sha'] == expected['candidate_sha'], 'artifact run/head mismatch')
    require(artifact['digest'] == 'sha256:' + sha(archive), 'downloaded ZIP digest mismatch')
    dest.mkdir(mode=0o700, parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        names = [i.filename for i in z.infolist()]
        require(len(names) == len(set(names)), 'duplicate ZIP filename')
        for info in z.infolist():
            parts = Path(info.filename).parts
            require(parts and not Path(info.filename).is_absolute() and '..' not in parts and
                    '\\' not in info.filename and not stat.S_ISLNK(info.external_attr >> 16), 'unsafe ZIP path')
        z.extractall(dest)
    return verify_bundle(dest, {k: v for k, v in expected.items() if k != 'artifact_id'})
