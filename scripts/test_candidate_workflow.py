"""Detect loss of the single-build snapshot, retention and security boundaries."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


class CandidateWorkflowTests(unittest.TestCase):
    def test_existing_snapshot_is_the_single_candidate_build_and_verification(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        job = text.split('  release-snapshot:\n', 1)[1].split('  vulnerability-scan:\n', 1)[0]
        self.assertIn("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", job)
        self.assertEqual(len(re.findall(r'^        run: .*goreleaser release ', job, re.M)), 1)
        self.assertIn('--snapshot --clean --skip=publish,sign', job)
        self.assertIn('scripts/verify_candidate_artifacts.py', job)
        self.assertIn('scripts/prepare_candidate_inputs.py', job)
        self.assertNotIn('continue-on-error', job)
        self.assertNotIn('secrets.', job)
        self.assertNotIn('release.yml', '\n'.join(line for line in job.split('    steps:', 1)[1].splitlines() if not line.lstrip().startswith('#')))

    def test_retention_cannot_succeed_without_uploaded_evidence(self):
        text = (ROOT / '.github/workflows/ci.yml').read_text()
        job = text.split('  release-snapshot:\n', 1)[1].split('  vulnerability-scan:\n', 1)[0]
        self.assertIn('actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2', job)
        for required in ('retention-days: 90', 'if-no-files-found: error', 'overwrite: false',
                         'include-hidden-files: false', 'candidate-upload.outputs.artifact-id',
                         'candidate-upload.outputs.artifact-digest', 'candidate-upload.outputs.artifact-url'):
            self.assertIn(required, job)
        self.assertLess(job.index('scripts/verify_candidate_artifacts.py'), job.index('actions/upload-artifact@'))
        self.assertIn('Vulnerability Scan (govulncheck)', text)
        self.assertIn('contents: read', text)


if __name__ == '__main__':unittest.main()
