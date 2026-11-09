"""Verify an exact CI artifact download locally without executing its binaries."""
import argparse
import json
from pathlib import Path
from candidate_bundle import unpack_verified_zip


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'artifact-json', 'run-json', 'dest'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('sha', 'run-id', 'attempt', 'artifact-id'):
        parser.add_argument('--' + name, required=True)
    a = parser.parse_args()
    expected = {'candidate_sha': a.sha, 'repository': 'Hanalyx/kensa',
                'run_id': a.run_id, 'run_attempt': a.attempt, 'artifact_id': a.artifact_id}
    binding = unpack_verified_zip(a.archive, json.loads(a.artifact_json.read_text()),
                                  json.loads(a.run_json.read_text()), a.dest.resolve(), expected)
    print(json.dumps({'status': 'verified', 'binding': binding, 'artifact_id': a.artifact_id}, indent=2))


if __name__ == '__main__':
    main()
