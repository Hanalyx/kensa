# CI snapshot verification

The existing `ci.yml` release-snapshot job builds one unsigned snapshot on a
schedule or workflow dispatch. It uses `VERSION` and the checked-out commit to
name the snapshot. It creates no tag, signature, release or deployment. A
snapshot is verification evidence, not a published release.
The job stops if a check fails. It also stops if the files cannot be saved.

The job keeps the existing GoReleaser, Syft and Go pins. Additional validation
inputs are pinned in `candidate-inputs.toml`: Ubuntu package versions and archive
digests, QEMU's executable digest, and the published v0.12.0 verifier archive and
executable digests. Tools are prepared on the disposable Ubuntu 24.04 runner.
Missing inputs or mismatches fail without fallback. Hashes, versions and the
installed OS package inventory are retained. This is not a hermetic build or a
reproducibility certification. OS dependencies remain part of the runner.

Repository entry points:

- `prepare_candidate_inputs.py` fetches verified inputs and installs pinned tools
  on the disposable runner, using ordinary Ubuntu package dependencies.
- `test_candidate_*.py` supplies detecting unit controls using temporary files
  and synthetic inventories. These do not certify a built package.
- `verify_candidate_artifacts.py` verifies the existing snapshot output, then
  binds and copies the tested bytes without rebuilding.
- `review_candidate_artifact.py` verifies a downloaded artifact's identity,
  ZIP digest and complete payload/result inventory without executing binaries.

Run unit controls with Python 3.12 and cryptography installed:

```bash
python3 -B -m unittest discover -s scripts -p 'test_candidate_*.py' -v
python3 -B -m unittest discover -s scripts -p 'test_verify_envelope_vectors.py' -v
```

The artifact gate requires exactly one checksum file covering four archives,
six packages and one SBOM with unique, well-formed SHA-256 entries. It tests all
eight packaged CLI variants, historical v1 behavior, v2 authentication and
numeric tampering. It checks all four shipped binaries, sudoers metadata,
corpus contents and shipping direct dependencies in the SBOM. Missing or failed
evidence blocks the candidate. Arm64 uses QEMU user emulation; packages are
extracted, not installed. These checks make no managed-host restoration claim.

Only the tested packages, archives, SBOM, checksums, synthetic fixtures and
verification results are uploaded. The checkout, operational keys and source
credentials are excluded. The bundle binds the candidate SHA, source tree,
repository, workflow reference, run ID and attempt. The artifact name includes
the SHA, run ID and attempt. Upload is mandatory; overwriting is disabled.
Retention is 90 days. Required evidence must be retained before expiry.

Use the exact successful run and artifact IDs reported by the upload step:

```bash
gh api "repos/Hanalyx/kensa/actions/runs/$run_id" > run.json
gh api "repos/Hanalyx/kensa/actions/artifacts/$artifact_id" > artifact.json
gh api "repos/Hanalyx/kensa/actions/artifacts/$artifact_id/zip" > candidate.zip
python3 -B scripts/review_candidate_artifact.py \
  --archive candidate.zip --artifact-json artifact.json --run-json run.json \
  --sha "$candidate_sha" --run-id "$run_id" --attempt "$attempt" \
  --artifact-id "$artifact_id" --dest reviewed-candidate
```

The review helper fails on a wrong identity, SHA, attempt, workflow, digest,
missing result or changed payload. It rejects duplicate or unsafe ZIP entries.
Review the retained outputs and actual packages against the exact source.
Routine review does not rebuild. A reproducibility experiment needs a stated
purpose and separate scope.

Full CI, vulnerability scanning, required PR checks and CodeQL remain gates.
Existing pre-commit checks retain source-hygiene responsibility. Snapshot success
grants no merge, release, deployment or consumer-upgrade authority. Publication
needs separate authorization and final signed-release artifact verification.
Consumer notices, migration and rollback arrangements remain release gates.
