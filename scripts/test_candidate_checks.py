"""Detect weakened packaged CLI policy, numeric and metadata assertions."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from candidate_checks import WARNING, check_cli_result, check_numeric_signature, check_sudoers
from prepare_candidate_inputs import checked_bytes
from verify_candidate_artifacts import run_check

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('lossless', ROOT / 'scripts/verify-envelope-vectors.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class CandidateChecksTests(unittest.TestCase):
    def result(self, version='v2', valid=True, accepted=True):
        warnings = [WARNING] if version == 'v1' and valid else []
        return {'exit': 0 if accepted else 1, 'stderr': '\n'.join(warnings),
                'stdout': json.dumps({'valid': valid, 'accepted': accepted,
                                      'rollback_results_authenticated': version == 'v2' and valid,
                                      'warnings': warnings})}

    def test_valid_v2_and_default_rejected_legacy(self):
        check_cli_result(self.result(), True, True, 'v2', 'json', False)
        check_cli_result(self.result('v1', True, False), True, False, 'v1', 'json', False)
        check_cli_result(self.result('v1'), True, True, 'v1', 'json', False)

    def test_cli_detects_wrong_exit_policy_authentication_warning_and_empty_output(self):
        for field, value in [('valid', False), ('accepted', False), ('rollback_results_authenticated', False)]:
            with self.subTest(field=field):
                result = self.result()
                body = json.loads(result['stdout']);body[field] = value;result['stdout'] = json.dumps(body)
                with self.assertRaises(AssertionError):
                    check_cli_result(result, True, True, 'v2', 'json', False)
        result = self.result();result['exit'] = 1
        with self.assertRaises(AssertionError):
            check_cli_result(result, True, True, 'v2', 'json', False)
        result = self.result('v1');result['stderr'] = ''
        with self.assertRaises(AssertionError):
            check_cli_result(result, True, True, 'v1', 'json', False)
        result = self.result();result['stdout'] = ''
        with self.assertRaises(ValueError):
            check_cli_result(result, True, True, 'v2', 'json', False)

    def test_early_key_errors_have_no_json_body_but_verifier_errors_require_one(self):
        result = {'exit': 1, 'stderr': 'public key not found', 'stdout': ''}
        check_cli_result(result, False, False, 'v2', 'json', False, 'missing-key', 'not found')
        result = {'exit': 1, 'stderr': 'signature does not match', 'stdout': ''}
        with self.assertRaises(ValueError):
            check_cli_result(result, False, False, 'v2', 'json', False, 'bad-signature', 'signature does not match')

    def test_quiet_and_invalid_evidence_assertions_detect_wrong_output(self):
        with self.assertRaises(AssertionError):
            check_cli_result(self.result(), True, True, 'v2', 'json', True)
        result = self.result(valid=False, accepted=False)
        with self.assertRaises(AssertionError):
            check_cli_result(result, False, False, 'v2', 'json', False, reason='signature does not match')

    def test_all_numeric_signatures_and_decimal_tamper_controls(self):
        doc = verifier.loads_lossless((ROOT / 'internal/evidence/testdata/numeric-vectors.json').read_text())
        self.assertEqual(len(doc['vectors']), 18)
        for entry in doc['vectors']:
            with self.subTest(vector=entry['name']):
                check_numeric_signature(entry, verifier)

    def test_numeric_negative_detects_a_verifier_that_discards_the_edit(self):
        doc = verifier.loads_lossless((ROOT / 'internal/evidence/testdata/numeric-vectors.json').read_text())
        for version in ('v1', 'v2'):
            entry = next(e for e in doc['vectors'] if e['name'] == version + '/decimal')
            class IgnoresEdit:
                JSONNumber = verifier.JSONNumber
                canonical = staticmethod(lambda envelope: verifier.canonical(entry['envelope']))
            with self.assertRaisesRegex(AssertionError, 'accepted numeric tampering'):
                check_numeric_signature(entry, IgnoresEdit)

    def test_sudoers_metadata_positive_and_detecting_negatives(self):
        check_sudoers(0o440, 0, 0, True)
        check_sudoers(0o100440, 'root', 'root', True)
        for args in [(0o644, 0, 0, True), (0o4440, 0, 0, True), (0o440, 1, 0, True),
                     (0o440, 0, 1, True), (0o440, 0, 0, False)]:
            with self.subTest(args=args), self.assertRaises(AssertionError):
                check_sudoers(*args)

    def test_download_digest_mismatch_has_no_fallback(self):
        with self.assertRaisesRegex(ValueError, 'no fallback'):
            checked_bytes(b'changed input', '0' * 64)

    def test_failed_verification_propagates_before_a_success_bundle(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError):
                run_check([sys.executable, '-c', 'raise SystemExit(7)'], Path(directory) / 'failed.log')


if __name__ == '__main__':
    unittest.main()
