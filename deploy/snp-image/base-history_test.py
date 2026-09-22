#!/usr/bin/env python3
"""Regression checks for published base evidence and safe history updates."""

import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("base-history.py")
spec = importlib.util.spec_from_file_location("base_history", SCRIPT)
history_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(history_module)


def entry(cloud="gcp"):
    return dict(cloud=cloud, base="snp-base:" + "a" * (64 if cloud == "gcp" else 96),
                base_uki_sha256="b" * 64, sourceCommit="c" * 40,
                kernelCmdline="console=ttyS0,115200",
                base_uki_signature=base64.b64encode(b"test-public-signature").decode())


class BaseHistoryTests(unittest.TestCase):
    def test_latest_entry_cannot_fall_back_to_older_valid_evidence(self):
        old = entry()
        newer = dict(cloud="gcp", base_uki_sha256="d" * 64)
        selected = history_module.select(dict(base_images=[old, newer]), "gcp")
        self.assertEqual(selected, newer)
        with self.assertRaises(ValueError):
            history_module.validate(selected)

    def test_required_metadata(self):
        for field in entry():
            with self.subTest(field=field):
                invalid = entry()
                del invalid[field]
                with self.assertRaises(ValueError):
                    history_module.validate(invalid)

    def test_malformed_metadata(self):
        invalid_values = {
            "cloud": ["other", ""],
            "base": ["snp-base:" + "a" * 96, "a" * 64],
            "base_uki_sha256": ["b" * 63, "z" * 64],
            "sourceCommit": ["--help", "main", "c" * 39, None],
            "kernelCmdline": ["", "console=ttyS0\n", "console=ttyS0\0", None],
            "base_uki_signature": ["", "%%%%", "YQ==\n", "YQ===", "a" * (128 * 1024 + 1), None],
        }
        for field, values in invalid_values.items():
            for value in values:
                with self.subTest(field=field, value=str(value)[:30]):
                    invalid = entry()
                    invalid[field] = value
                    with self.assertRaises(ValueError):
                        history_module.validate(invalid)

    def run_helper(self, action, history, evidence, *digests):
        return subprocess.run([sys.executable, str(SCRIPT), action, str(history), "gcp", str(evidence), *digests],
                              capture_output=True, text=True)

    def test_exact_digest_selection(self):
        old = entry()
        newer = dict(old, base="snp-base:" + "d" * 64, sourceCommit="e" * 40)
        history = dict(base_images=[old, entry("aws"), newer])
        self.assertEqual(history_module.select(history, "gcp"), newer)
        self.assertEqual(history_module.select(history, digest="a" * 64), old)
        self.assertEqual(history_module.select(history, "gcp", "a" * 64), old)
        self.assertEqual(history_module.select(history, digest="a" * 96), entry("aws"))
        with self.assertRaises(ValueError):
            history_module.select(history, "aws", "a" * 64)
        for digest in ("", "bad", "f" * 64, old["base"]):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                history_module.select(history, digest=digest)
        history["base_images"].append(dict(old, sourceCommit="f" * 40))
        with self.assertRaises(ValueError):
            history_module.select(history, digest="a" * 64)

    def test_historical_extraction_uses_selected_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history = root / "history.json"
            old = entry()
            newer = dict(old, base="snp-base:" + "d" * 64, sourceCommit="e" * 40,
                         base_uki_sha256="f" * 64, kernelCmdline="different",
                         base_uki_signature=base64.b64encode(b"new-signature").decode())
            history.write_text(json.dumps(dict(base_images=[old, newer])))
            result = self.run_helper("extract", history, root, "a" * 64)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "commit").read_text(), old["sourceCommit"])
            self.assertEqual((root / "expected-sha256").read_text(), old["base_uki_sha256"])
            self.assertEqual((root / "expected-pcr").read_text(), old["base"])
            self.assertEqual((root / "cmdline").read_text(), old["kernelCmdline"])
            self.assertEqual((root / "base-signature.pk7").read_bytes(), b"test-public-signature")
            del old["base_uki_signature"]
            history.write_text(json.dumps(dict(base_images=[old, newer])))
            result = self.run_helper("extract", history, root, "a" * 64)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("base_uki_signature", result.stderr)

    def test_extraction_and_record_preserve_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history = root / "history.json"
            old = dict(base_images=[dict(cloud="gcp", base_uki_sha256="old"), entry("aws"), entry()],
                       app_images=[dict(version="keep-this-app")])
            history.write_text(json.dumps(old))
            evidence = root / "evidence"
            evidence.mkdir()
            result = self.run_helper("extract", history, evidence)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((evidence / "base-signature.pk7").read_bytes(), b"test-public-signature")
            self.assertEqual((evidence / "commit").read_text(), "c" * 40)
            (evidence / "original-history.json").write_bytes(history.read_bytes())
            (evidence / "actual-sha256").write_text("b" * 64)
            (evidence / "actual-pcr").write_text(entry()["base"])
            result = self.run_helper("record", history, evidence)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(history.read_text()), old)
            # A new release is appended; all old records and app data survive.
            (evidence / "original-history.json").write_bytes(history.read_bytes())
            (evidence / "actual-sha256").write_text("d" * 64)
            result = self.run_helper("record", history, evidence)
            self.assertEqual(result.returncode, 0, result.stderr)
            updated = json.loads(history.read_text())
            self.assertEqual(updated["base_images"][:-1], old["base_images"])
            self.assertEqual(updated["app_images"], old["app_images"])
            self.assertEqual(updated["base_images"][-1]["base_uki_sha256"], "d" * 64)
            # Concurrent history edits must not be overwritten.
            before = history.read_bytes()
            result = self.run_helper("record", history, evidence)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(history.read_bytes(), before)

    def test_invalid_evidence_never_updates_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history = root / "history.json"
            history.write_text(json.dumps(dict(base_images=[entry()], app_images=[])))
            original = history.read_bytes()
            result = self.run_helper("extract", history, root)
            self.assertEqual(result.returncode, 0, result.stderr)
            (root / "original-history.json").write_bytes(original)
            (root / "actual-sha256").write_text("b" * 64)
            (root / "actual-pcr").write_text("")
            result = self.run_helper("record", history, root)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(history.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
