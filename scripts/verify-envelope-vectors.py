#!/usr/bin/env python3
"""Independently check signing vectors; optionally derive fixed v2 vectors in Python."""
import argparse
import base64
import copy
import datetime
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

FIELDS = ("schema_version", "transaction_id", "rule_id", "host_id", "fleet_id",
          "started_at", "finished_at", "pre_state_bundle", "apply_steps",
          "validator_results", "decision", "severity", "post_state_bundle", "framework_refs")
LISTS = ("pre_state_bundle", "apply_steps", "validator_results", "post_state_bundle", "framework_refs")


class JSONNumber(str):
    """A validated JSON number token, never converted through binary64."""


def reject_constant(value):
    raise ValueError("not a JSON number: " + value)


def loads_lossless(text):
    return json.loads(text, parse_int=JSONNumber, parse_float=JSONNumber,
                      parse_constant=reject_constant)


def dumps_lossless(value):
    """Sorted compact JSON, retaining every number token like Go json.Number.

    The Go signer has already formatted typed floats/integers when it writes
    an envelope. Reformatting those tokens here would change signed bytes.
    This checks the canonical signing contract, not the legacy CLI's float64
    input normalization. Refuse accidental float inputs rather than round.
    """
    if isinstance(value, JSONNumber):
        return str(value)
    if isinstance(value, dict):
        return "{" + ",".join(dumps_lossless(key) + ":" + dumps_lossless(value[key])
                              for key in sorted(value)) + "}"
    if isinstance(value, list):
        return "[" + ",".join(dumps_lossless(entry) for entry in value) + "]"
    if isinstance(value, float):
        raise TypeError("lossy float input; use loads_lossless")
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def utc_nano(value):
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d{1,9})?(Z|[+-]\d\d:\d\d)", value)
    if not match:
        raise ValueError("not RFC3339Nano: " + value)
    whole, fraction, zone = match.groups()
    instant = datetime.datetime.fromisoformat(whole + ("+00:00" if zone == "Z" else zone))
    instant = instant.astimezone(datetime.timezone.utc)
    fraction = (fraction or "").rstrip("0").rstrip(".")
    return (f"{instant.year:04}-{instant.month:02}-{instant.day:02}T"
            f"{instant.hour:02}:{instant.minute:02}:{instant.second:02}{fraction}Z")


def canonical(envelope):
    version = envelope["schema_version"]
    if version not in ("v1", "v2"):
        raise ValueError("unknown version: " + version)
    result = {key: copy.deepcopy(envelope[key]) for key in FIELDS if key in envelope}
    for key in ("fleet_id", "severity"):
        if not result.get(key):
            result.pop(key, None)
    for key in LISTS:
        result[key] = result.get(key) or []
    for key in ("started_at", "finished_at"):
        result[key] = utc_nano(result[key])
    if version == "v2":
        result["rollback_results"] = copy.deepcopy(envelope.get("rollback_results") or [])
        for entry in result["rollback_results"]:
            entry["ExecutedAt"] = utc_nano(entry["ExecutedAt"])
    text = dumps_lossless(result)
    for char, escaped in (("<", r"\u003c"), (">", r"\u003e"), ("&", r"\u0026"), ("\u2028", r"\u2028"), ("\u2029", r"\u2029")):
        text = text.replace(char, escaped)
    return text.encode("utf-8")


def check(path):
    document = loads_lossless(path.read_text(encoding="utf-8"))
    for vector in document["vectors"]:
        envelope = vector["envelope"]
        content = canonical(envelope)
        tagged = b"kensa-evidence-envelope-" + envelope["schema_version"].encode() + b"\x00" + content
        assert content == base64.b64decode(vector["canonical"]), (path, vector["name"], "canonical")
        assert tagged == base64.b64decode(vector["tagged"]), (path, vector["name"], "domain")
        assert hashlib.sha256(content).hexdigest() == vector["hash"], (path, vector["name"], "hash")
        signature = base64.b64decode(vector["signature"])
        assert signature == base64.b64decode(envelope["signature"])
        public = base64.b64decode(vector["public_key"])
        assert hashlib.sha256(public).hexdigest() == envelope["signing_key_id"]
        Ed25519PublicKey.from_public_bytes(public).verify(signature, tagged)
        assert Ed25519PrivateKey.from_private_bytes(bytes.fromhex(document["seed_hex"])).sign(tagged) == signature
        print(f"PASS {path.name}/{vector['name']}: canonical, domain, hash, Ed25519 verification/signing")
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--envelope", type=Path, help="verify an actual engine/CLI envelope")
    parser.add_argument("--public-key", type=Path, help="matching PEM public key")
    parser.add_argument("--generate-v2", type=Path, help="write new Python-derived vectors from one released v1 input file")
    args = parser.parse_args()
    if not args.paths and not args.envelope:
        parser.error("provide vector files or --envelope with --public-key")
    if bool(args.envelope) != bool(args.public_key):
        parser.error("--envelope and --public-key must be supplied together")
    if args.envelope:
        envelope = loads_lossless(args.envelope.read_text(encoding="utf-8"))
        content = canonical(envelope)
        tagged = b"kensa-evidence-envelope-" + envelope["schema_version"].encode() + b"\x00" + content
        public = serialization.load_pem_public_key(args.public_key.read_bytes())
        public.verify(base64.b64decode(envelope["signature"]), tagged)
        print(f"PASS {args.envelope.name}: independent Python Ed25519; canonical SHA256={hashlib.sha256(content).hexdigest()}")
    documents = [check(path) for path in args.paths]
    if args.generate_v2:
        assert len(documents) == 1
        source = documents[0]
        result = copy.deepcopy(source)
        result["source"] = "Independent Python canonicalizer and cryptography Ed25519, derived from fixed released-v1 input envelopes"
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(source["seed_hex"]))
        for vector in result["vectors"]:
            envelope = vector["envelope"]
            assert envelope["schema_version"] == "v1"
            envelope["schema_version"] = "v2"
            content = canonical(envelope)
            tagged = b"kensa-evidence-envelope-v2\x00" + content
            signature = key.sign(tagged)
            envelope["signature"] = base64.b64encode(signature).decode()
            vector.update(canonical=base64.b64encode(content).decode(), tagged=base64.b64encode(tagged).decode(),
                          signature=envelope["signature"], hash=hashlib.sha256(content).hexdigest())
        args.generate_v2.write_text(dumps_lossless(result) + "\n", encoding="utf-8")
        check(args.generate_v2)


if __name__ == "__main__":
    main()
