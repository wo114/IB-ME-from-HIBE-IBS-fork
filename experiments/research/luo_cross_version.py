"""Bounded, isolated Luo C64B wire compatibility test. No repository writes.

Worker stdout/stdin are anonymous, captured pipes carrying ephemeral key material.
Never run --worker by hand or redirect its output. Only the coordinator emits logs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import inspect
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone

C64B = dict(degree=256, k=11, l=10, q=274877844481, root=153250464611,
            eta=1, kappa=64, gamma1=190000, gamma2=60000000000,
            gamma3=27487784448, dropped_bits=28, identity_max_bytes=64,
            message_max_bytes=4096, max_extract_attempts=4096,
            max_sign_attempts=4096, max_uniform_attempts=128,
            max_cached_identities=64)
# A closed dependency scope: no discovery/import of peer-owned new modules.
SOURCE_FILES = tuple("src/ibme/" + p for p in (
    "__init__.py", "core/__init__.py", "core/encoding.py", "core/errors.py",
    "core/hashing.py", "core/lamport_ots.py", "core/randomness.py", "core/types.py",
    "ibs/__init__.py", "ibs/api.py", "ibs/luo.py", "ibs/luo_module.py",
    "ibs/luo_module_codec.py", "ibs/luo_module_math.py", "ibs/luo_reference.py",
    "ibs/mock.py", "ibs/sis_ibs.py", "lattice/__init__.py", "lattice/gadget.py",
    "lattice/gaussian.py", "lattice/modmat.py", "lattice/params.py", "lattice/trapdoor.py"))
WIRE_NAMES = {"params", "public", "master", "signing", "reference", "compact"}
PUBLIC_WIRE_NAMES = WIRE_NAMES - {"master", "signing"}
IDENTITY = b"A" * 64
MESSAGE = b"step23/c64b/wire/v1"
TIMEOUT_SECONDS = 45


class GateError(Exception):
    """Only a fixed, non-secret stage code may appear in reports."""


def require(condition, code):
    if not condition:
        raise GateError(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args, allowed=(0,)):
    done = subprocess.run(["git", "--no-optional-locks", "-C", str(root), *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=15, check=False)
    require(done.returncode in allowed, "git_check_failed")
    return done


def snapshot(root, expected_head=None):
    root = Path(root).resolve(strict=True)
    head = git(root, "rev-parse", "HEAD").stdout.decode().strip()
    if expected_head:
        require(7 <= len(expected_head) <= 40 and
                all(c in "0123456789abcdef" for c in expected_head.lower()) and
                head.startswith(expected_head.lower()), "head_pin_mismatch")
    # Git handles checkout line endings; SHA256 below pins exact loaded bytes.
    require(git(root, "diff", "--quiet", "HEAD", "--", *SOURCE_FILES,
                allowed=(0, 1)).returncode == 0, "dirty_selected_source")
    entries = git(root, "ls-tree", "-r", "HEAD", "--", *SOURCE_FILES).stdout
    blobs = {}
    for line in entries.decode("utf-8").splitlines():
        meta, name = line.split("\t", 1)
        mode, kind, blob = meta.split()
        require(kind == "blob" and mode in ("100644", "100755"), "source_not_regular")
        blobs[name] = blob
    require(set(blobs) == set(SOURCE_FILES), "untracked_or_missing_selected_source")
    files = {}
    for name in SOURCE_FILES:
        path = root / name
        require(path.resolve(strict=True).is_relative_to(root / "src"), "source_path_escape")
        files[name] = dict(sha256=sha256(path.read_bytes()), git_blob=blobs[name])
    # Close the status/hash race before granting an import pin.
    require(git(root, "diff", "--quiet", "HEAD", "--", *SOURCE_FILES,
                allowed=(0, 1)).returncode == 0, "dirty_selected_source")
    require(git(root, "rev-parse", "HEAD").stdout.decode().strip() == head, "head_drift")
    return dict(root=str(root), head=head, files=files,
                source_set_sha256=sha256(json.dumps(files, sort_keys=True).encode()))


def module_name(relative):
    name = relative.removeprefix("src/").removesuffix(".py").replace("/", ".")
    return name.removesuffix(".__init__")


class PinnedLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, name, path, pin):
        super().__init__(name, str(path))
        self.pin = pin

    def get_code(self, fullname):
        # Compile pinned source directly: even existing .pyc files cannot leak in.
        raw = Path(self.path).read_bytes()
        require(sha256(raw) == self.pin, "source_hash_changed_before_import")
        return compile(raw, self.path, "exec", dont_inherit=True)


class PinnedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, pin):
        self.root = Path(pin["root"]).resolve(strict=True)
        self.files = {module_name(p): (p, info) for p, info in pin["files"].items()}

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "ibme" and not fullname.startswith("ibme."):
            return None
        require(fullname in self.files, "forbidden_or_unpinned_ibme_import")
        relative, info = self.files[fullname]
        source = self.root / relative
        require(source.resolve(strict=True).is_relative_to(self.root / "src"),
                "source_path_escape")
        loader = PinnedLoader(fullname, source, info["sha256"])
        return importlib.util.spec_from_file_location(
            fullname, source, loader=loader,
            submodule_search_locations=[str(source.parent)]
            if source.name == "__init__.py" else None)


def install_guard(pin):
    require(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
            "worker_not_isolated")
    require(not any(n == "ibme" or n.startswith("ibme.") for n in sys.modules),
            "ibme_preloaded")
    require(set(pin["files"]) == set(SOURCE_FILES), "unexpected_source_scope")
    sys.meta_path.insert(0, PinnedFinder(pin))


def imported_evidence(pin):
    entries = []
    root = Path(pin["root"]).resolve()
    for name, mod in sorted(sys.modules.items()):
        if name != "ibme" and not name.startswith("ibme."):
            continue
        path = Path(mod.__file__).resolve(strict=True)
        require(path.is_relative_to(root / "src"), "import_origin_mismatch")
        relative = path.relative_to(root).as_posix()
        require(relative in pin["files"], "unlisted_import")
        digest = sha256(path.read_bytes())
        require(digest == pin["files"][relative]["sha256"], "source_drift_after_import")
        entries.append(dict(module=name, path=str(path), sha256=digest))
    return entries


def wire_summary(wires):
    # Explicit allowlist; NO raw material or secret-wire hashes in reports.
    require(set(wires) == WIRE_NAMES, "unexpected_artifact_set")
    return {name: dict(bytes=len(raw), **({"sha256": sha256(raw)}
                   if name in PUBLIC_WIRE_NAMES else {}))
            for name, raw in sorted(wires.items())}


def encode_wires(wires):
    require(set(wires) == WIRE_NAMES, "unexpected_artifact_set")
    return {n: base64.b64encode(raw).decode("ascii") for n, raw in wires.items()}


def decode_wires(bundle):
    require(set(bundle) == WIRE_NAMES, "unexpected_artifact_set")
    require(all(isinstance(v, str) and len(v) <= 24 * 2**20 for v in bundle.values()),
            "artifact_budget_exceeded")
    return {n: base64.b64decode(raw, validate=True) for n, raw in bundle.items()}


class NoEntropy:
    def read(self, count):
        raise GateError("consumer_requested_entropy")


def worker(payload):
    pin = payload["pin"]
    install_guard(pin)
    from ibme.core.encoding import decode_bytes, encode_bytes
    from ibme.core.errors import SerializationError
    from ibme.ibs.luo_module import (LuoModuleIBSBackend, LuoModuleParams,
        LuoModulePublicKey, LuoModuleMasterSecret, LuoModuleSigningKey, MAGIC, VERSION)
    from ibme.ibs.luo_module_codec import (LuoModuleCompactIBSBackend,
        encode_compact, decode_compact, MAGIC_COMPACT, VERSION_COMPACT)

    params = LuoModuleParams(**C64B)  # Explicit profile, no changed global defaults.
    require(params.security_claim == "none" and params.backend_admitted is False,
            "unexpected_security_flags")
    require(LuoModuleIBSBackend.__module__ == "ibme.ibs.luo_module" and
            LuoModuleCompactIBSBackend.__module__ == "ibme.ibs.luo_module_codec",
            "unexpected_backend_class")
    require(LuoModuleIBSBackend.security_claim == "none" and
            LuoModuleIBSBackend.backend_admitted is False, "unexpected_security_flags")
    mode = payload["mode"]
    require(mode in ("produce", "consume"), "unknown_worker_mode")
    algorithms = dict(setup=0, fresh_extract=0, sign=0, cached_extract=0)
    attempts = {}
    if mode == "produce":
        source = LuoModuleIBSBackend()  # Fresh OS randomness, never logged or seeded.
        public, master = source.setup(params)
        algorithms["setup"] = 1
        signing = source.key_extract(master, IDENTITY)
        algorithms["fresh_extract"] = 1
        attempts["extract"] = source.last_extract_attempts
        sig = source.sign(signing, MESSAGE)
        algorithms["sign"] = 1
        attempts["sign"] = source.last_sign_attempts
        wires = dict(params=params.to_bytes(), public=public.to_bytes(),
                     master=master.to_bytes(), signing=signing.to_bytes(),
                     reference=sig.to_bytes(), compact=encode_compact(sig))
    else:
        wires = decode_wires(payload["artifacts"])

    checks = []
    def check(name, good):
        require(good, "check_failed:" + name)
        checks.append(dict(name=name, result="pass"))

    def rejects(name, operation):
        try:
            operation()
        except SerializationError:
            checks.append(dict(name=name, result="rejected", exception="SerializationError"))
        else:
            raise GateError("accepted_invalid:" + name)

    restored_params = LuoModuleParams.from_bytes(wires["params"])
    public = LuoModulePublicKey.from_bytes(wires["public"])
    master = LuoModuleMasterSecret.from_bytes(wires["master"])
    signing = LuoModuleSigningKey.from_bytes(wires["signing"])
    reference = LuoModuleIBSBackend(rng=NoEntropy())
    compact = LuoModuleCompactIBSBackend(rng=NoEntropy())
    ref_sig = reference.load_signature(public, wires["reference"])
    comp_sig = compact.load_signature(public, wires["compact"])
    check("explicit_C64B_parameter_equality", restored_params == params == public.params)
    check("identity_64B_and_cached_identity", signing.identity == IDENTITY and
          master.cached_identities == (IDENTITY,))
    cached = reference.key_extract(master, IDENTITY)
    algorithms["cached_extract"] = 1
    check("cached_extract_no_entropy", cached.to_bytes() == wires["signing"])
    restored = dict(params=restored_params.to_bytes(), public=public.to_bytes(),
                    master=master.to_bytes(), signing=signing.to_bytes(),
                    reference=ref_sig.to_bytes(), compact=comp_sig.to_bytes())
    for name in sorted(WIRE_NAMES):
        check(name + "_canonical_roundtrip", restored[name] == wires[name])
    check("reference_to_compact_identical", encode_compact(ref_sig) == wires["compact"])
    check("compact_to_reference_identical",
          decode_compact(wires["compact"], public).to_bytes() == wires["reference"])
    for label, backend, signature in (("reference", reference, ref_sig),
                                       ("compact", compact, comp_sig)):
        check(label + "_verify", backend.verify(public, IDENTITY, MESSAGE, signature) is True)
        check(label + "_wrong_message", backend.verify(public, IDENTITY, MESSAGE + b"!", signature) is False)
        check(label + "_wrong_identity", backend.verify(public, b"B" * 64, MESSAGE, signature) is False)
    rejects("reference_loader_rejects_compact", lambda: reference.load_signature(public, wires["compact"]))
    rejects("compact_loader_rejects_reference", lambda: compact.load_signature(public, wires["reference"]))
    for label, loader in (("params", LuoModuleParams.from_bytes),
                          ("public", LuoModulePublicKey.from_bytes),
                          ("master", LuoModuleMasterSecret.from_bytes),
                          ("signing", LuoModuleSigningKey.from_bytes),
                          ("reference", lambda x: reference.load_signature(public, x)),
                          ("compact", lambda x: compact.load_signature(public, x))):
        rejects(label + "_truncated", lambda: loader(wires[label][:-1]))
        rejects(label + "_appended", lambda: loader(wires[label] + b"\0"))

    # Only public length-prefix framing is touched, never secret/matrix fields.
    def replace_field(raw, magic, index, replacement):
        fields, pos = [], len(magic)
        while pos < len(raw):
            field, pos = decode_bytes(raw, pos)
            fields.append(field)
        fields[index] = replacement
        return magic + b"".join(encode_bytes(x) for x in fields)

    for label, backend, magic in (("reference", reference, MAGIC),
                                   ("compact", compact, MAGIC_COMPACT)):
        for suffix, index, value in (("unknown_version", 0, b"UNKNOWN/0"),
                                      ("default_params_not_C64B", 2, LuoModuleParams().to_bytes()),
                                      ("wrong_public_context", 3, bytes(64))):
            rejects(label + "_" + suffix, lambda: backend.load_signature(
                public, replace_field(wires[label], magic, index, value)))

    public_api = {}
    for cls in (LuoModuleIBSBackend, LuoModuleCompactIBSBackend):
        public_api[cls.__name__] = {name: str(inspect.signature(getattr(cls, name)))
            for name in ("__init__", "setup", "key_extract", "sign", "verify", "load_signature")}
    for cls in (LuoModuleParams, LuoModulePublicKey, LuoModuleMasterSecret, LuoModuleSigningKey):
        public_api[cls.__name__] = {name: str(inspect.signature(getattr(cls, name)))
                                 for name in ("to_bytes", "from_bytes")}
    evidence = dict(mode=mode, pid=os.getpid(), root=pin["root"], head=pin["head"],
        algorithms=algorithms, attempts=attempts, checks=checks, wires=wire_summary(restored),
        api=public_api, modules=imported_evidence(pin),
        codecs=[VERSION.decode(), VERSION_COMPACT.decode()],
        python=sys.version, executable=sys.executable, isolated=bool(sys.flags.isolated),
        no_site=bool(sys.flags.no_site), dont_write_bytecode=bool(sys.flags.dont_write_bytecode),
        security_claim="none", backend_admitted=False)
    return dict(evidence=evidence, artifacts=encode_wires(restored))


def run_worker(pin, mode, bundle=None):
    command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), "--worker"]
    payload = dict(pin=pin, mode=mode)
    if bundle is not None:
        payload["artifacts"] = bundle
    started = time.monotonic()
    # Never inherit output streams: both can contain sensitive exception/output data.
    done = subprocess.run(command, input=json.dumps(payload).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS,
        cwd=Path(__file__).resolve().parent, check=False)
    require(done.returncode == 0, "worker_failed_output_suppressed")
    require(not done.stderr, "worker_stderr_suppressed")
    reply = json.loads(done.stdout)
    require(set(reply) == {"evidence", "artifacts"}, "unexpected_worker_reply")
    require(reply["evidence"]["root"] == pin["root"] and
            reply["evidence"]["head"] == pin["head"], "worker_pin_mismatch")
    reply["evidence"]["elapsed_seconds"] = round(time.monotonic() - started, 3)
    reply["evidence"]["command"] = command
    return reply


def validate_pair(old, new):
    require(Path(old["root"]) != Path(new["root"]), "same_checkout_not_cross_version")


def coordinate(old, new):
    validate_pair(old, new)
    baseline = run_worker(old, "produce")
    forward = run_worker(new, "consume", baseline["artifacts"])
    require(baseline["artifacts"] == forward["artifacts"], "old_to_new_wire_mismatch")
    backward = run_worker(old, "consume", forward["artifacts"])
    require(forward["artifacts"] == backward["artifacts"], "new_to_old_wire_mismatch")
    require(baseline["evidence"]["api"] == forward["evidence"]["api"] ==
            backward["evidence"]["api"], "public_api_mismatch")
    require(snapshot(old["root"], old["head"]) == old and
            snapshot(new["root"], new["head"]) == new, "source_snapshot_drift")
    # Return ONLY the safe schema. Opaque wires never enter an output artifact.
    return [x["evidence"] for x in (baseline, forward, backward)]


def args_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--old-root", default=os.getenv("OLD_ROOT"))
    p.add_argument("--new-root", default=os.getenv("NEW_ROOT"))
    p.add_argument("--old-head", default=os.getenv("OLD_HEAD"))
    p.add_argument("--new-head", default=os.getenv("NEW_HEAD"))
    p.add_argument("--output", help="New metadata-only JSON; must be outside both repositories")
    return p


def main(argv=None):
    args = args_parser().parse_args(argv)
    require(args.old_root and args.new_root, "both_roots_required")
    old_root, new_root = Path(args.old_root).resolve(), Path(args.new_root).resolve()
    if args.output:
        output = Path(args.output).resolve()
        require(not any(output.is_relative_to(root) for root in (old_root, new_root)),
                "output_inside_repository")
        require(not output.exists(), "output_already_exists")
    report = dict(schema="luo-cross-version/1", status="failed_closed",
        utc=datetime.now(timezone.utc).isoformat(), platform=platform.platform(),
        profile=C64B, identity_bytes=len(IDENTITY), message_bytes=len(MESSAGE),
        rng="fresh OS CSPRNG; seed and secret material not logged",
        security_claim="none", backend_admitted=False,
        scope="one C64B setup/extract/sign; codec/source compatibility, not security or CHKP",
        runner_sha256=sha256(Path(__file__).read_bytes()), worker_timeout_seconds=TIMEOUT_SECONDS)
    try:
        old = snapshot(old_root, args.old_head)
        new = snapshot(new_root, args.new_head)
        report["sources"] = dict(old=old, new=new)
        report["selected_source_sets_identical"] = old["files"] == new["files"]
        report["contexts"] = coordinate(old, new)
        report["status"] = "functional_wire_compatible"
        report["independent_signatures"] = 1
        report["directions"] = ["old generated -> new loaded/reserialized", "new reserialized -> old loaded"]
    except Exception as exc:
        # Do not retain exception strings, tracebacks, stdout or TimeoutExpired data.
        report["failure"] = dict(type=type(exc).__name__,
            code=exc.args[0] if type(exc) is GateError else "details_suppressed")
    raw = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.output:
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(raw)
    print(raw, end="")
    return 0 if report["status"] == "functional_wire_compatible" else 2


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        try:
            # This branch must stay pipe-only; no raw errors or tracebacks escape.
            require(not sys.stdin.isatty() and not sys.stdout.isatty(), "worker_requires_pipes")
            answer = worker(json.loads(sys.stdin.buffer.read(64 * 2**20)))
            sys.stdout.write(json.dumps(answer))
        except BaseException:
            sys.exit(3)
    else:
        try:
            sys.exit(main())
        except Exception as exc:
            print(json.dumps(dict(status="failed_closed", failure_type=type(exc).__name__)))
            sys.exit(2)
