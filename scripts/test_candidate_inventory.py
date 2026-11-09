"""Detect incomplete or malformed release checksum inventories using real files."""
import ast
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from artifact_inventory import verify_checksum_inventory as verify

tree=ast.parse((Path(__file__).parent / "artifact_matrix.py").read_text())
VERSION = '0.13.0-SNAPSHOT-1234567'
# Independent fixture list follows the actual configured release output names.
PAYLOADS = tuple(name.format(v=VERSION) for name in (
    'kensa_{v}_linux_amd64.tar.gz', 'kensa_{v}_linux_arm64.tar.gz',
    'kensa_{v}_linux_amd64_with-rules.tar.gz', 'kensa_{v}_linux_arm64_with-rules.tar.gz',
    'kensa_{v}_linux_amd64.rpm', 'kensa_{v}_linux_arm64.rpm',
    'kensa_{v}_linux_amd64.deb', 'kensa_{v}_linux_arm64.deb',
    'kensa-rules_{v}_noarch.rpm', 'kensa-rules_{v}_noarch.deb',
))
SBOM = f'kensa_{VERSION}_sbom.cdx.json'
CHECKS = f'kensa_{VERSION}_checksums.sha256'
observations = []

class ChecksumInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kensa-checksum-control-')
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name)
        for name in PAYLOADS:
            (self.dist / name).write_bytes(('synthetic inventory fixture: ' + name).encode())
        (self.dist / SBOM).write_text(json.dumps({'bomFormat': 'CycloneDX', 'components': [{'name': 'fixture'}]}))
        self.lines = [hashlib.sha256((self.dist / name).read_bytes()).hexdigest() + '  ' + name for name in (*PAYLOADS, SBOM)]
        self.write(self.lines)

    def write(self, lines):
        (self.dist / CHECKS).write_text('\n'.join(lines) + '\n' if lines else '')

    def reject(self):
        with self.assertRaises((ValueError, AssertionError)) as caught:
            verify(self.dist, VERSION)
        observations.append({'case': self.id(), 'rejected': True, 'reason': str(caught.exception)})

    def test_valid_complete_inventory(self):
        checks, inventory, sbom = verify(self.dist, VERSION)
        self.assertEqual(checks, self.dist / CHECKS)
        self.assertEqual(sbom, self.dist / SBOM)
        self.assertEqual(set(inventory), set(PAYLOADS) | {SBOM})
        self.assertNotIn(CHECKS, inventory)
        observations.append({'case': self.id(), 'accepted': True, 'entries': len(inventory)})

    def test_valid_binary_markers_and_uppercase_digests(self):
        self.write([line[:64].upper() + ' *' + line[66:] for line in self.lines])
        self.assertEqual(len(verify(self.dist, VERSION)[1]), 11)

    def test_omitted_archive(self):
        self.write(self.lines[1:])
        self.reject()

    def test_omitted_package(self):
        self.write([line for line in self.lines if not line.endswith(PAYLOADS[-1])])
        self.reject()

    def test_only_sbom_listed(self):
        self.write(self.lines[-1:])
        self.reject()

    def test_omitted_sbom(self):
        self.write(self.lines[:-1])
        self.reject()

    def test_duplicate_identical_entry(self):
        self.write(self.lines + self.lines[:1])
        self.reject()

    def test_duplicate_conflicting_entry(self):
        self.write(self.lines + ['0' * 64 + '  ' + PAYLOADS[0]])
        self.reject()

    def test_missing_checksum_file(self):
        (self.dist / CHECKS).unlink()
        self.reject()

    def test_multiple_checksum_files(self):
        (self.dist / 'other_checksums.sha256').write_text('\n'.join(self.lines) + '\n')
        self.reject()

    def test_wrong_checksum_filename(self):
        (self.dist / CHECKS).rename(self.dist / 'wrong_checksums.sha256')
        self.reject()

    def test_empty_checksum_inventory(self):
        self.write([])
        self.reject()

    def test_malformed_entries(self):
        good = self.lines[0]
        malformed = [
            'a' * 63 + '  ' + PAYLOADS[0],
            'g' * 64 + '  ' + PAYLOADS[0],
            good[:64] + '\t' + PAYLOADS[0],
            good + ' extra-field',
            '', '# comment', good + ' ', '\\' + good,
            good + '\r', good + '\v' + good,
        ]
        for line in malformed:
            with self.subTest(entry=repr(line)):
                self.write([line] + self.lines[1:])
                self.reject()

    def test_unexpected_filename(self):
        self.write(self.lines + ['0' * 64 + '  unexpected.tar.gz'])
        self.reject()

    def test_path_traversal_entry(self):
        self.write(self.lines + ['0' * 64 + '  ../outside.rpm'])
        self.reject()

    def test_checksum_file_cannot_cover_itself(self):
        self.write(self.lines + ['0' * 64 + '  ' + CHECKS])
        self.reject()

    def test_payload_digest_mismatch(self):
        (self.dist / PAYLOADS[0]).write_bytes(b'changed payload bytes')
        self.reject()

    def test_sbom_digest_mismatch(self):
        (self.dist / SBOM).write_text('{"bomFormat":"CycloneDX","components":[{"name":"changed"}]}')
        self.reject()

    def test_missing_payload_file(self):
        (self.dist / PAYLOADS[0]).unlink()
        self.reject()

    def test_unexpected_payload_file(self):
        (self.dist / 'unexpected.rpm').write_bytes(b'not an expected artifact')
        self.reject()

    def test_wrong_payload_name(self):
        (self.dist / PAYLOADS[0]).rename(self.dist / 'wrong.tar.gz')
        self.reject()

    def test_missing_sbom_file(self):
        (self.dist / SBOM).unlink()
        self.reject()

    def test_multiple_sbom_files(self):
        (self.dist / 'extra_sbom.cdx.json').write_text('{}')
        self.reject()

    def test_helper_invokes_strict_inventory_gate(self):
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                 and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                 and n.value.func.id == 'verify_checksum_inventory']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].targets[0]), '(checks, checksums, sbom)')
        self.assertEqual([ast.unparse(arg) for arg in calls[0].value.args], ['DIST', 'options.version'])

if __name__ == "__main__":
    unittest.main()
