"""Harness-only regression tests. No cryptographic Setup/Extract/Sign calls."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1] / "experiments/research"
spec = importlib.util.spec_from_file_location("cross_version", HERE / "luo_cross_version.py")
cv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cv)


class PinsAndIsolation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="luo-guard-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Disposable inert Git fixtures test source gates, never crypto compatibility.
        for relative in cv.SOURCE_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# inert source-pin fixture\n", encoding="utf-8")
        cv.git(self.root, "init", "-q")
        cv.git(self.root, "-c", "core.autocrlf=false", "add", "--", *cv.SOURCE_FILES)
        cv.git(self.root, "-c", "user.name=Harness test", "-c", "user.email=test@invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(self.root / "no-hooks"),
               "commit", "-qm", "inert source-pin fixture")
        self.pin = cv.snapshot(self.root)

    def test_clean_pins_include_exact_source_hashes(self):
        self.assertEqual(len(self.pin["files"]), 23)
        for relative, info in self.pin["files"].items():
            self.assertEqual(info["sha256"], cv.sha256((self.root / relative).read_bytes()))
            self.assertEqual(len(info["git_blob"]), 40)

    def test_head_prefix_verified(self):
        self.assertEqual(cv.snapshot(self.root, self.pin["head"][:7]), self.pin)
        with self.assertRaisesRegex(cv.GateError, "head_pin_mismatch"):
            cv.snapshot(self.root, "0" * 40)

    def test_dirty_selected_source_rejected(self):
        (self.root / "src/ibme/ibs/luo_module.py").write_text("# changed\n")
        with self.assertRaisesRegex(cv.GateError, "dirty_selected_source"):
            cv.snapshot(self.root)

    def test_staged_change_rejected(self):
        path = "src/ibme/ibs/luo_module.py"
        (self.root / path).write_text("# changed\n")
        cv.git(self.root, "add", "--", path)
        with self.assertRaisesRegex(cv.GateError, "dirty_selected_source"):
            cv.snapshot(self.root)

    def test_untracked_peer_files_are_not_import_candidates(self):
        for name in ("src/ibme/cli.py", "src/ibme/assembly/__init__.py",
                     "src/ibme/ibs/luo_module_profiles.py", "src/ibme/protocol/__init__.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("raise RuntimeError('must never execute')\n")
        self.assertEqual(cv.snapshot(self.root), self.pin)
        finder = cv.PinnedFinder(self.pin)
        for name in ("ibme.cli", "ibme.assembly", "ibme.ibs.luo_module_profiles", "ibme.protocol"):
            with self.assertRaisesRegex(cv.GateError, "forbidden_or_unpinned"):
                finder.find_spec(name)

    def test_loaded_hash_changed_after_pin_rejected(self):
        loader = cv.PinnedFinder(self.pin).find_spec("ibme.ibs.luo_module").loader
        (self.root / "src/ibme/ibs/luo_module.py").write_text("# changed\n")
        with self.assertRaisesRegex(cv.GateError, "source_hash_changed_before_import"):
            loader.get_code("ibme.ibs.luo_module")

    def test_source_loader_bypasses_bytecode_cache(self):
        loader = cv.PinnedFinder(self.pin).find_spec("ibme.ibs.luo_module").loader
        with patch.object(loader, "get_data", side_effect=AssertionError("pyc must not be read")):
            self.assertIsInstance(loader.get_code("ibme.ibs.luo_module"), type(compile("", "", "exec")))

    def test_same_root_rejected(self):
        with self.assertRaisesRegex(cv.GateError, "same_checkout_not_cross_version"):
            cv.validate_pair(self.pin, self.pin)

    def test_worker_ignores_pythonpath_and_user_site(self):
        # No crypto: just import guard + one inert package in a separate interpreter.
        hostile = self.root / "hostile"
        (hostile / "ibme").mkdir(parents=True)
        (hostile / "ibme/__init__.py").write_text("raise RuntimeError('PYTHONPATH leak')\n")
        (hostile / "sitecustomize.py").write_text("raise RuntimeError('site leak')\n")
        program = (
            "import importlib.util,json,sys;"
            "s=importlib.util.spec_from_file_location('cv',sys.argv[1]);"
            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            "p=json.load(sys.stdin);m.install_guard(p);import ibme;"
            "print(json.dumps(m.imported_evidence(p)))")
        done = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", program,
                               str(HERE / "luo_cross_version.py")],
            input=json.dumps(self.pin), capture_output=True, text=True, timeout=15,
            env={**os.environ, "PYTHONPATH": str(hostile), "PYTHONUSERBASE": str(hostile)})
        self.assertEqual(done.returncode, 0, done.stderr)
        evidence = json.loads(done.stdout)
        self.assertEqual(Path(evidence[0]["path"]), self.root / "src/ibme/__init__.py")

    def test_metadata_output_inside_repository_rejected(self):
        with self.assertRaisesRegex(cv.GateError, "output_inside_repository"):
            cv.main(["--old-root", str(self.root), "--new-root", str(HERE),
                     "--output", str(self.root / "report.json")])


class ReportingAndTransport(unittest.TestCase):
    def test_secret_summary_contains_lengths_only(self):
        wires = {n: b"DO_NOT_LOG_PRIVATE_WIRE_123" for n in cv.WIRE_NAMES}
        summary = cv.wire_summary(wires)
        for name in ("master", "signing"):
            self.assertEqual(summary[name], {"bytes": len(wires[name])})
        self.assertNotIn("DO_NOT_LOG_PRIVATE_WIRE", json.dumps(summary))

    def test_unknown_artifact_is_rejected(self):
        with self.assertRaisesRegex(cv.GateError, "unexpected_artifact_set"):
            cv.wire_summary({"extra": b"secret"})

    def test_transport_roundtrip_is_in_memory(self):
        wires = {n: b"\x00\xff" for n in cv.WIRE_NAMES}
        self.assertEqual(cv.decode_wires(cv.encode_wires(wires)), wires)

    def test_bad_base64_is_rejected(self):
        with self.assertRaises(Exception):
            cv.decode_wires({n: "not!base64" for n in cv.WIRE_NAMES})

    def test_missing_root_is_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(cv.GateError, "both_roots_required"):
                cv.main([])

    def test_root_and_head_environment_defaults(self):
        with patch.dict(os.environ, dict(OLD_ROOT="old", NEW_ROOT="new", OLD_HEAD="abcdef0", NEW_HEAD="1234567")):
            args = cv.args_parser().parse_args([])
            self.assertEqual((args.old_root, args.new_root, args.old_head, args.new_head),
                             ("old", "new", "abcdef0", "1234567"))

    def test_worker_failure_never_forwards_streams(self):
        result = subprocess.CompletedProcess([], 3, b"SECRET stdout", b"SECRET stderr")
        with patch.object(cv.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(cv.GateError, "worker_failed_output_suppressed") as caught:
                cv.run_worker({}, "produce")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_unexpected_exception_does_not_disclose_material(self):
        output = io.StringIO()
        with patch.object(cv, "snapshot", side_effect=ValueError("SECRET exception")):
            with contextlib.redirect_stdout(output):
                result = cv.main(["--old-root", "old", "--new-root", "new"])
        self.assertEqual(result, 2)
        self.assertNotIn("SECRET", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "failed_closed")

    def test_explicit_profile_not_default_or_security_override(self):
        self.assertEqual(len(cv.C64B), 17)
        self.assertEqual(cv.C64B["gamma1"], 190000)
        self.assertEqual(cv.C64B["gamma2"], 60000000000)
        self.assertEqual(cv.C64B["gamma3"], (cv.C64B["q"] - 1) // 10)
        self.assertEqual(cv.C64B["identity_max_bytes"], 64)
        self.assertEqual(cv.C64B["max_sign_attempts"], 4096)
        self.assertNotIn("backend_admitted", cv.C64B)


if __name__ == "__main__":
    unittest.main(verbosity=2)
