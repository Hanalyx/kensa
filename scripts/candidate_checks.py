"""Assertions shared by packaged CLI, numeric and metadata validation."""
import base64
import copy
import json

WARNING = 'Legacy v1 signature is valid; rollback results are not authenticated.'
# These failures return before verify.go constructs its result body.
EARLY_ERRORS = {'unsigned-errored', 'unsigned-recovered', 'empty-key-id',
                'malformed-key-id', 'missing-key', 'malformed-pem'}


def check_cli_result(result, valid, accepted, version, fmt, quiet, name='', reason=''):
    assert result['exit'] == (0 if accepted else 1), result
    assert (WARNING in result['stderr']) == (valid and version == 'v1'), result
    if not valid:
        assert reason.lower() in (result['stderr'] + result['stdout']).lower(), result
    if quiet:
        assert result['stdout'] == '', result
    elif fmt == 'json' and name in EARLY_ERRORS:
        assert not valid and not accepted and result['stdout'] == '', result
    elif fmt == 'json':
        # Missing output cannot count as a passing verifier result.
        body = json.loads(result['stdout'])
        assert body['valid'] is valid and body['accepted'] is accepted, result
        assert body['rollback_results_authenticated'] is (valid and version == 'v2'), result
        assert (WARNING in body.get('warnings', [])) == (valid and version == 'v1'), result
        if name == 'key-id-warning':
            assert 'signing_key_id_mismatch' in body.get('warnings', []), result
    elif valid:
        assert 'status:          VALID' in result['stdout'], result
        assert ('accepted:        ' + str(accepted).lower()) in result['stdout'], result
    if not valid:
        assert '"rollback_results_authenticated":true' not in result['stdout'], result


def check_numeric_signature(entry, verifier):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    envelope = entry['envelope']
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(entry['public_key']))
    signature = base64.b64decode(entry['signature'])
    tag = b'kensa-evidence-envelope-' + envelope['schema_version'].encode() + b'\0'
    public.verify(signature, tag + verifier.canonical(envelope))
    changed = copy.deepcopy(envelope)
    token = changed['pre_state_bundle'][0]['Data']['number']
    changed['pre_state_bundle'][0]['Data']['number'] = verifier.JSONNumber(
        '1.00000000000000001' if token == '1.0' else '123456789.123456789012345678901')
    try:
        public.verify(signature, tag + verifier.canonical(changed))
    except InvalidSignature:
        return
    raise AssertionError('Python accepted numeric tampering: ' + entry['name'])


def check_sudoers(mode, owner, group, is_config):
    assert mode & 0o7777 == 0o440, mode
    assert owner in (0, 'root') and group in (0, 'root'), (owner, group)
    assert is_config, 'sudoers fragment must be a config file'
