"""Test byte/run bindings with synthetic files, without a package build or CI run."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import tomllib
import unittest
import warnings
import zipfile

from artifact_inventory import sha
from candidate_bundle import binding_for, matrix_evidence_paths, seal_bundle, unpack_verified_zip, verify_bundle
from verify_candidate_artifacts import retain_matrix_evidence


class CandidateBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kensa-bundle-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / 'bundle'
        self.payloads = self.bundle / 'payloads';self.payloads.mkdir(parents=True)
        self.results = self.bundle / 'results';(self.results / 'additional-controls').mkdir(parents=True)
        self.sha = 'a' * 40;self.version = '0.13.0-SNAPSHOT-' + self.sha[:7]
        self.binding = binding_for(self.sha, 'b' * 40, 'Hanalyx/kensa', '123', '2',
                                   'Hanalyx/kensa/.github/workflows/ci.yml@refs/heads/candidate', self.version)
        names = [f'kensa_{self.version}_linux_{arch}{ending}' for arch in ('amd64', 'arm64')
                 for ending in ('.tar.gz', '_with-rules.tar.gz', '.rpm', '.deb')]
        names += [f'kensa-rules_{self.version}_noarch.{kind}' for kind in ('rpm', 'deb')]
        self.names = names
        for name in names:(self.payloads / name).write_bytes(('synthetic file: ' + name).encode())
        sbom = f'kensa_{self.version}_sbom.cdx.json'
        self.write(self.payloads / sbom, {'bomFormat': 'CycloneDX', 'components': [{'name': 'unit-fixture'}]})
        checks = f'kensa_{self.version}_checksums.sha256'
        (self.payloads / checks).write_text(''.join(sha(self.payloads / n) + '  ' + n + '\n' for n in [*names, sbom]))
        hashes = {p.name: sha(p) for p in self.payloads.iterdir()}
        manifest = []
        self.summary = {'candidate_version': self.version, 'published_v012_valid_v1_and_rejects_v2': True,
                        'fixture_and_key_files_unchanged': True, 'binary_files_unchanged': True,
                        'artifact_results': [], 'candidate_cli_runs': 8, 'rpm_digest_records': {}}
        for name in names:
            item = {'artifact': '/runner/dist/' + name, 'artifact_sha256': hashes[name],
                    'contains_cli': not name.startswith('kensa-rules_')}
            if item['contains_cli']:
                arch = 'arm64' if '_arm64' in name else 'amd64'
                item.update(architecture=arch, binary='/runner/extracted/' + name + '/kensa',
                            binary_sha256='c' * 64)
                prefix = ['/usr/bin/qemu-aarch64-static'] if arch == 'arm64' else []
                prefix += [item['binary']]
                record = {'artifact': item,
                          'version': {'argv': prefix + ['version'], 'exit': 0,
                                      'stdout': 'kensa ' + self.version, 'stderr': ''},
                          'help': {'argv': prefix + ['verify', '--help'], 'exit': 0,
                                   'stdout': '--accept-legacy-v1 rollback results', 'stderr': ''},
                          'runs': [{'argv': prefix + ['verify', '/runner/matrix-fixtures/v2-valid.json'],
                                    'exit': 0, 'stdout': '{"valid":true}', 'stderr': ''}]}
                path = self.results / 'matrix-output' / (name + '.json')
                path.parent.mkdir(exist_ok=True);self.write(path, record)
                self.summary['artifact_results'].append({'artifact': name, 'artifact_sha256': hashes[name],
                    'binary_sha256': item['binary_sha256'], 'architecture': arch, 'runs': 1, 'result': 'pass',
                    'evidence': '/runner/matrix-output/' + path.name, 'evidence_sha256': sha(path)})
            manifest.append(item)
            if name.endswith('.rpm'):
                path = self.results / 'extracted' / (name + '.rpm-digests.json')
                path.parent.mkdir(exist_ok=True)
                self.write(path, {'argv': ['rpm', '-Kv', item['artifact']], 'exit': 0,
                                 'stdout': 'Header SHA256 digest: OK\nPayload SHA256 digest: OK', 'stderr': ''})
                self.summary['rpm_digest_records'][path.name] = sha(path)
        self.write(self.results / 'artifact-manifest.json', {'artifacts': manifest})
        fixtures = self.results / 'matrix-fixtures';fixtures.mkdir()
        for schema in ('v1', 'v2'):
            self.write(fixtures / (schema + '-valid.json'), {'fixture': 'synthetic-' + schema})
        self.write(self.results / 'matrix-input-hashes.json', {p.name: sha(p) for p in fixtures.iterdir()})
        self.summary['fixture_hash_inventory_sha256'] = sha(self.results / 'matrix-input-hashes.json')
        pin = tomllib.loads(Path(__file__).with_name('candidate-inputs.toml').read_text())['legacy']
        old_runs = [{'fixture_version': schema, 'argv': ['/runner/released-v0.12.0/extracted/kensa', 'verify',
                    '/runner/matrix-fixtures/' + schema + '-valid.json', '--trust-dir', '/runner/trust', '--format', 'json'],
                    'exit': 0 if schema == 'v1' else 1, 'stdout': json.dumps({'valid': schema == 'v1'}),
                    'stderr': '' if schema == 'v1' else 'unknown schema_version'} for schema in ('v1', 'v2')]
        old = self.results / 'released-v0.12.0/actual-cli-compatibility.json';old.parent.mkdir()
        self.write(old, {'binary_sha256': pin['binary_sha256'], 'runs': old_runs})
        self.summary['published_verifier_evidence_sha256'] = sha(old)
        self.write(self.results / 'artifact-matrix-summary.json', self.summary)
        self.write(self.results / 'additional-controls/results.json',
                   {'status': 'passed', 'numeric_cli': ['synthetic'], 'independent_numeric': ['synthetic'],
                    'artifact_metadata': ['synthetic']})
        self.write(self.results / 'input-provenance.json', {'inputs': {'pins': {'legacy': pin}}})
        self.write(self.results / 'validation.json', {'status': 'passed', 'binding': self.binding, 'artifact_hashes': hashes})
        for name in ('artifact-matrix.log', 'artifact-controls.log'):(self.results / name).write_text('unit fixture\n')
        self.write(self.bundle / 'BINDING.json', self.binding)
        self.expected = {'candidate_sha': self.sha, 'repository': 'Hanalyx/kensa', 'run_id': '123', 'run_attempt': '2'}
        seal_bundle(self.bundle)
        self.archive = self.root / 'bundle.zip';self.zip_bundle()
        self.run = {'head_sha': self.sha, 'id': 123, 'run_attempt': 2, 'status': 'completed', 'conclusion': 'success',
                    'path': '.github/workflows/ci.yml', 'event': 'workflow_dispatch', 'repository': {'full_name': 'Hanalyx/kensa'}}
        self.artifact = {'id': 456, 'name': self.binding['artifact_name'], 'expired': False,
                         'workflow_run': {'id': 123, 'head_sha': self.sha}, 'digest': 'sha256:' + sha(self.archive)}

    def write(self, path, data):path.write_text(json.dumps(data))

    def zip_bundle(self):
        with zipfile.ZipFile(self.archive, 'w') as z:
            for p in sorted(self.bundle.rglob('*')):
                if p.is_file():z.write(p, str(p.relative_to(self.bundle)))

    def unpack(self, artifact=None, run=None):
        return unpack_verified_zip(self.archive, artifact or self.artifact, run or self.run,
                                   self.root / 'download', dict(self.expected, artifact_id='456'))

    def test_positive_exact_ci_identity_and_byte_inventory(self):
        self.assertEqual(self.unpack(), self.binding)

    def test_wrong_zip_digest(self):
        self.archive.write_bytes(self.archive.read_bytes() + b'altered')
        with self.assertRaisesRegex(ValueError, 'ZIP digest'):self.unpack()

    def test_wrong_artifact_id_name_head_and_expiry(self):
        for key, value in [('id', 457), ('name', 'other'), ('expired', True)]:
            altered = copy.deepcopy(self.artifact);altered[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):self.unpack(artifact=altered)
        altered = copy.deepcopy(self.artifact);altered['workflow_run']['head_sha'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'head mismatch'):self.unpack(artifact=altered)

    def test_wrong_run_head_attempt_workflow_conclusion_and_event(self):
        for key, value in [('head_sha', 'f' * 40), ('id', 124), ('run_attempt', 3),
                           ('path', '.github/workflows/release.yml'), ('conclusion', 'failure'), ('event', 'push')]:
            altered = copy.deepcopy(self.run);altered[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):self.unpack(run=altered)

    def test_changed_retained_payload(self):
        (self.payloads / self.names[0]).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):verify_bundle(self.bundle, self.expected)

    def test_missing_and_unlisted_bundle_file(self):
        p = self.bundle / 'unexpected.txt';p.write_text('extra')
        with self.assertRaisesRegex(ValueError, 'coverage'):verify_bundle(self.bundle, self.expected)
        p.unlink();(self.payloads / self.names[0]).unlink()
        with self.assertRaisesRegex(ValueError, 'coverage'):verify_bundle(self.bundle, self.expected)

    def test_missing_required_results_cannot_be_sealed(self):
        (self.bundle / 'MANIFEST.json').unlink();(self.results / 'artifact-controls.log').unlink()
        with self.assertRaisesRegex(ValueError, 'missing verification'):seal_bundle(self.bundle)

    def test_failed_cli_result_cannot_be_sealed(self):
        (self.bundle / 'MANIFEST.json').unlink();self.summary['artifact_results'][0]['result'] = 'failure'
        self.write(self.results / 'artifact-matrix-summary.json', self.summary)
        with self.assertRaisesRegex(ValueError, 'CLI verification failed'):seal_bundle(self.bundle)

    def test_missing_cli_variant_cannot_be_sealed(self):
        (self.bundle / 'MANIFEST.json').unlink();self.summary['artifact_results'].pop()
        self.write(self.results / 'artifact-matrix-summary.json', self.summary)
        with self.assertRaisesRegex(ValueError, 'missing packaged CLI'):seal_bundle(self.bundle)

    def test_failed_numeric_evidence_cannot_be_sealed(self):
        (self.bundle / 'MANIFEST.json').unlink()
        self.write(self.results / 'additional-controls/results.json', {'status': 'failed'})
        with self.assertRaisesRegex(ValueError, 'numeric/metadata'):seal_bundle(self.bundle)


    def unseal(self):
        (self.bundle / 'MANIFEST.json').unlink()

    def save_summary(self):
        self.write(self.results / 'artifact-matrix-summary.json', self.summary)

    def mutate_cli_record(self, edit, rebind=True):
        row = self.summary['artifact_results'][0]
        path = self.results / 'matrix-output' / (row['artifact'] + '.json')
        record = json.loads(path.read_text());edit(record);self.write(path, record)
        if rebind:row['evidence_sha256'] = sha(path)
        self.save_summary()

    def mutate_published_record(self, edit):
        path = self.results / 'released-v0.12.0/actual-cli-compatibility.json'
        record = json.loads(path.read_text());edit(record);self.write(path, record)
        self.summary['published_verifier_evidence_sha256'] = sha(path);self.save_summary()

    def test_copy_retains_required_raw_records_without_extracted_executables(self):
        (self.results / 'extracted/private-executable').write_bytes(b'not evidence')
        dest = self.root / 'copied';dest.mkdir()
        retain_matrix_evidence(self.results, dest)
        manifest = json.loads((self.results / 'artifact-manifest.json').read_text())['artifacts']
        expected = matrix_evidence_paths(manifest)
        self.assertTrue(all((dest / name).is_file() for name in expected), expected)
        for name in expected:
            self.assertEqual((dest / name).read_bytes(), (self.results / name).read_bytes())
        self.assertFalse((dest / 'extracted/private-executable').exists())
        self.assertEqual(len(list((dest / 'matrix-output').glob('*.json'))), 8)
        self.assertEqual(len(list((dest / 'extracted').glob('*.rpm-digests.json'))), 3)

    def test_copy_fails_if_published_verifier_record_is_missing(self):
        (self.results / 'released-v0.12.0/actual-cli-compatibility.json').unlink()
        dest = self.root / 'copied';dest.mkdir()
        with self.assertRaisesRegex(ValueError, 'missing matrix evidence'):
            retain_matrix_evidence(self.results, dest)

    def test_copy_requires_fixture_inventory_and_rpm_records(self):
        paths = [self.results / 'matrix-input-hashes.json',
                 next((self.results / 'extracted').glob('*.rpm-digests.json'))]
        for index, path in enumerate(paths):
            data = path.read_bytes();path.unlink()
            dest = self.root / ('copied-' + str(index));dest.mkdir()
            try:
                with self.subTest(record=path.name), self.assertRaisesRegex(ValueError, 'missing matrix evidence'):
                    retain_matrix_evidence(self.results, dest)
            finally:path.write_bytes(data)

    def test_all_eight_underlying_cli_results_are_required(self):
        self.unseal()
        for path in (self.results / 'matrix-output').glob('*.json'):path.unlink()
        with self.assertRaisesRegex(ValueError, 'missing underlying'):seal_bundle(self.bundle)

    def test_incomplete_but_self_consistent_bundle_manifest_cannot_verify(self):
        path = self.results / 'matrix-output' / (self.names[0] + '.json');path.unlink()
        manifest = json.loads((self.bundle / 'MANIFEST.json').read_text())
        del manifest['files'][str(path.relative_to(self.bundle))]
        self.write(self.bundle / 'MANIFEST.json', manifest)
        with self.assertRaisesRegex(ValueError, 'missing underlying'):verify_bundle(self.bundle, self.expected)

    def test_cli_file_hash_is_bound_to_summary(self):
        self.unseal();self.mutate_cli_record(lambda r: r.update(extra='changed bytes'), rebind=False)
        with self.assertRaisesRegex(ValueError, 'CLI result file hash'):seal_bundle(self.bundle)

    def test_substituted_cli_record_is_rejected_even_with_updated_file_hash(self):
        self.unseal()
        other = json.loads((self.results / 'matrix-output' / (self.names[1] + '.json')).read_text())
        self.mutate_cli_record(lambda r: (r.clear(), r.update(other)))
        with self.assertRaisesRegex(ValueError, 'CLI record artifact binding'):seal_bundle(self.bundle)

    def test_cli_summary_payload_and_binary_hashes_are_required(self):
        self.unseal()
        for field in ('artifact_sha256', 'binary_sha256'):
            row = self.summary['artifact_results'][0];original = row[field];row[field] = 'f' * 64;self.save_summary()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'summary hash binding'):
                seal_bundle(self.bundle)
            row[field] = original

    def test_cli_record_count_must_match_summary(self):
        self.unseal();self.summary['artifact_results'][0]['runs'] = 2;self.save_summary()
        with self.assertRaisesRegex(ValueError, 'CLI result run count'):seal_bundle(self.bundle)

    def test_aggregate_cli_count_must_match_underlying_records(self):
        self.unseal();self.summary['candidate_cli_runs'] = 9;self.save_summary()
        with self.assertRaisesRegex(ValueError, 'aggregate CLI run count'):seal_bundle(self.bundle)

    def test_cli_responses_must_name_the_tested_binary(self):
        self.unseal();self.mutate_cli_record(lambda r: r['runs'][0]['argv'].__setitem__(0, '/substituted/kensa'))
        with self.assertRaisesRegex(ValueError, 'CLI response binding'):seal_bundle(self.bundle)

    def test_cli_version_response_must_match_candidate(self):
        self.unseal();self.mutate_cli_record(lambda r: r['version'].update(stdout='kensa other'))
        with self.assertRaisesRegex(ValueError, 'CLI version record'):seal_bundle(self.bundle)

    def test_initial_fixture_inventory_is_required(self):
        self.unseal();(self.results / 'matrix-input-hashes.json').unlink()
        with self.assertRaisesRegex(ValueError, 'missing verification'):seal_bundle(self.bundle)

    def test_fixture_hash_detects_changed_input(self):
        self.unseal();(self.results / 'matrix-fixtures/v1-valid.json').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'fixture hash mismatch'):seal_bundle(self.bundle)

    def test_fixture_inventory_cannot_omit_a_retained_input(self):
        self.unseal();path = self.results / 'matrix-input-hashes.json'
        hashes = json.loads(path.read_text());del hashes['v1-valid.json'];self.write(path, hashes)
        self.summary['fixture_hash_inventory_sha256'] = sha(path);self.save_summary()
        with self.assertRaisesRegex(ValueError, 'fixture inventory coverage'):seal_bundle(self.bundle)

    def test_rpm_digest_record_is_required(self):
        self.unseal();next((self.results / 'extracted').glob('*.rpm-digests.json')).unlink()
        with self.assertRaisesRegex(ValueError, 'missing underlying'):seal_bundle(self.bundle)

    def test_rpm_record_hash_and_artifact_identity_are_checked(self):
        self.unseal();path = next((self.results / 'extracted').glob('*.rpm-digests.json'))
        record = json.loads(path.read_text());record['argv'][-1] = '/other/package.rpm';self.write(path, record)
        with self.assertRaisesRegex(ValueError, 'RPM digest record hash'):seal_bundle(self.bundle)
        self.summary['rpm_digest_records'][path.name] = sha(path);self.save_summary()
        with self.assertRaisesRegex(ValueError, 'RPM digest record binding'):seal_bundle(self.bundle)

    def test_published_verifier_record_is_required(self):
        self.unseal();(self.results / 'released-v0.12.0/actual-cli-compatibility.json').unlink()
        with self.assertRaisesRegex(ValueError, 'missing verification'):seal_bundle(self.bundle)

    def test_published_verifier_binary_must_match_pin(self):
        self.unseal();self.mutate_published_record(lambda r: r.update(binary_sha256='f' * 64))
        with self.assertRaisesRegex(ValueError, 'published verifier binary binding'):seal_bundle(self.bundle)

    def test_both_published_verifier_responses_are_required(self):
        self.unseal();self.mutate_published_record(lambda r: r['runs'].pop())
        with self.assertRaisesRegex(ValueError, 'published verifier response inventory'):seal_bundle(self.bundle)

    def test_published_verifier_outcome_cannot_disagree_with_summary(self):
        self.unseal();self.mutate_published_record(lambda r: r['runs'][1].update(stdout='{"valid":true}'))
        with self.assertRaisesRegex(ValueError, 'published verifier response outcome'):seal_bundle(self.bundle)

    def test_published_verifier_responds_to_correct_fixture(self):
        self.unseal();self.mutate_published_record(lambda r: r['runs'][1]['argv'].__setitem__(2, '/other/v1-valid.json'))
        with self.assertRaisesRegex(ValueError, 'published verifier response binding'):seal_bundle(self.bundle)


    def test_unsafe_zip_path(self):
        with zipfile.ZipFile(self.archive, 'a') as z:z.writestr('../outside', b'bad')
        self.artifact['digest'] = 'sha256:' + sha(self.archive)
        with self.assertRaisesRegex(ValueError, 'unsafe ZIP'):self.unpack()

    def test_duplicate_zip_entry(self):
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(self.archive, 'a') as z:z.writestr('BINDING.json', '{}')
        self.artifact['digest'] = 'sha256:' + sha(self.archive)
        with self.assertRaisesRegex(ValueError, 'duplicate ZIP'):self.unpack()


if __name__ == '__main__':unittest.main()
