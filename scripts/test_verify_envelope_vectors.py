"""Detect numeric rewriting in the independent signing-vector verifier."""
import importlib.util
import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-envelope-vectors.py"
SPEC = importlib.util.spec_from_file_location("verifier", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
VECTORS = ROOT / "internal/evidence/testdata/numeric-vectors.json"


class NumericVerificationTests(unittest.TestCase):
    def test_go_signed_numeric_positives(self):
        # Every fixed Go-generated canonical byte, hash and signature must
        # match, including numbers whose spelling Python float would rewrite.
        VERIFIER.check(VECTORS)

    def test_decimal_tamper_both_versions(self):
        # Preserve the raw envelope token for both positive and tampered
        # inputs. Ordinary json.loads is the defect under test, not a fixture
        # preparation step that may erase the tamper before verification.
        raw = VECTORS.read_text()
        document = json.loads(raw)
        for vector in document["vectors"]:
            if not vector["name"].endswith("/decimal"):
                continue
            with self.subTest(version=vector["name"]):
                envelope = json.dumps(vector["envelope"], separators=(",", ":"))
                self.assertIn('"number":1.0', envelope)
                altered = envelope.replace('"number":1.0', '"number":1.00000000000000001')
                public = Ed25519PublicKey.from_public_bytes(base64.b64decode(vector["public_key"]))
                signature = base64.b64decode(vector["signature"])
                tag = b"kensa-evidence-envelope-" + vector["envelope"]["schema_version"].encode() + b"\0"
                # Exercise the same parser as the command (introduced by the
                # correction); until then expose the current lossy behavior.
                parse = getattr(VERIFIER, "loads_lossless", json.loads)
                public.verify(signature, tag + VERIFIER.canonical(parse(envelope)))
                with self.assertRaises(InvalidSignature):
                    public.verify(signature, tag + VERIFIER.canonical(parse(altered)))

    def test_command_rejects_decimal_tamper(self):
        document = json.loads(VECTORS.read_text())
        for vector in document["vectors"]:
            if not vector["name"].endswith("/decimal"):
                continue
            with self.subTest(version=vector["name"]), tempfile.TemporaryDirectory() as tmp:
                public = Ed25519PublicKey.from_public_bytes(base64.b64decode(vector["public_key"]))
                key = Path(tmp) / "key.pub"
                key.write_bytes(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
                envelope = json.dumps(vector["envelope"], separators=(",", ":"))
                path = Path(tmp) / "envelope.json"
                for tamper in (False, True):
                    path.write_text(envelope.replace('"number":1.0', '"number":1.00000000000000001') if tamper else envelope)
                    result = subprocess.run([sys.executable, str(SCRIPT), "--envelope", str(path), "--public-key", str(key)], capture_output=True, text=True)
                    if tamper:
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertNotIn("PASS", result.stdout)
                        self.assertIn("InvalidSignature", result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("PASS", result.stdout)

    def test_generate_v2_preserves_numeric_tokens(self):
        document = VERIFIER.loads_lossless(VECTORS.read_text())
        expected = {v["name"].split("/", 1)[1]: v for v in document["vectors"]
                    if v["name"].startswith("v2/")}
        document["vectors"] = [v for v in document["vectors"] if v["name"].startswith("v1/")]
        with tempfile.TemporaryDirectory() as tmp:
            source, generated = Path(tmp) / "v1.json", Path(tmp) / "v2.json"
            source.write_text(VERIFIER.dumps_lossless(document))
            result = subprocess.run([sys.executable, str(SCRIPT), str(source), "--generate-v2", str(generated)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for actual in VERIFIER.loads_lossless(generated.read_text())["vectors"]:
                control = expected[actual["name"].split("/", 1)[1]]
                for field in ("canonical", "tagged", "hash", "signature", "envelope"):
                    self.assertEqual(actual[field], control[field], (actual["name"], field))

    def test_refuse_lossy_float_inputs(self):
        with self.assertRaises(TypeError):
            VERIFIER.dumps_lossless({"number": 1.00000000000000001})


if __name__ == "__main__":
    unittest.main()
