"""One-shot, real author-2011 CHKP 3m and selected IB-ME lifecycle.

Run with WSL ``~/miniconda3/envs/sage/bin/python``. The output directory must
be a new child of ``build/outputs``. It contains private keys: keep it local.
No fixed RNG, public fixture root, zero-noise substitution, or identity retry
is used. Receipts show functional research evidence, never security admission.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from time import perf_counter
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for item in (ROOT, ROOT / "src"):
    if str(item) not in sys.path:
        sys.path.insert(0, str(item))

from ibme.assembly import build_runtime, make_suite, validate_suite
from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import SecureRandom
from ibme.hibe.chkp import CHKPParams
from ibme.hibe.chkp.author2011 import (
    Author2011Ciphertext, Author2011HIBE, Author2011Level1Key,
    Author2011Level2Key, Author2011MasterSecret, Author2011PublicKey,
)
from ibme.protocol.baseline import (
    BOTTOM, DOMAIN_SIGNATURE, Ciphertext, MasterSecret, PublicKey,
    ReceiverKey, SenderKey,
)
from ibme.protocol.byteauth import (
    ByteAuthCiphertext, authenticate_inner, encode_bound_message,
)
from ibme.protocol.hybrid_hibe import HybridMasterSecret, HybridPublicKey

RAW_RECEIVER = b"author2011-direct-receiver-1"
RAW_SENDER = b"author2011-direct-sender-1"
COMBO_RECEIVER = b"author2011-combo-receiver-1"
COMBO_SENDER = b"author2011-combo-sender-1"
OTHER_RECEIVER = b"author2011-other-receiver-1"
OTHER_SENDER = b"author2011-other-sender-1"
MESSAGE = b"author2011-3m-combo"

SOURCE_FILES = (
    "experiments/research/chkp_author2011_lifecycle.py",
    "src/ibme/hibe/chkp/author2011.py",
    "src/ibme/hibe/chkp/backend.py",
    "src/ibme/hibe/chkp/params.py",
    "src/ibme/lattice/chkp/level1_kem.py",
    "src/ibme/lattice/chkp/root_generation.py",
    "src/ibme/assembly/registry.py",
    "src/ibme/protocol/hybrid_hibe.py",
    "src/ibme/ibs/luo_module.py",
    "src/ibme/ibs/luo_module_codec.py",
)


def default_params() -> CHKPParams:
    """Executable small profile from an independently observed one-shot run."""
    return CHKPParams(
        n=1, q=17179869209, m_bar=16, r_width_squared=256,
        root_gs_squared_bound=20160010, parent_width_squared=1935360960,
        leaf_width_squared=19740681792000, alpha_numerator=4,
        alpha_denominator=17179869209, epsilon_bits=16, regularity_bits=8,
        parent_max_vectors=102, max_dimension=153, max_receivers=2,
        tail_bits=64, mass_bits=96, precision_bits=160,
        gaussian_abort_bits=64, lll_policy="checked",
    )


def _json(path: Path, value: object) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _bytes(path: Path, value: object) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(value.to_bytes())
    os.replace(tmp, path)


def _hash(value: bytes) -> str:
    return sha256(value).hexdigest()


def _source_hashes() -> dict[str, str]:
    return {name: _hash((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def _suite(params: CHKPParams):
    return make_suite(
        hibe="chkp-author2011", hibe_params=params, ibs="luo-module",
        ibs_params="research", transport="hybrid", signature_format="compact",
        protocol="byteauth-v1",
    )


def _new_output(raw: str) -> Path:
    root = (ROOT / "build" / "outputs").resolve()
    path = Path(raw)
    path = (path if path.is_absolute() else ROOT / path).resolve()
    if path == root or root not in path.parents:
        raise ValueError("--output must be a new child of build/outputs")
    root.mkdir(parents=True, exist_ok=True)
    path.mkdir(parents=True, exist_ok=False)
    return path


def _existing_output(raw: str) -> Path:
    root = (ROOT / "build" / "outputs").resolve()
    path = Path(raw).resolve()
    if path == root or root not in path.parents or not path.is_dir():
        raise ValueError("restore directory must exist under build/outputs")
    return path


def _params(raw: str | None) -> CHKPParams:
    if raw is None:
        return default_params()
    value = json.loads(Path(raw).read_text(encoding="utf-8"))
    if isinstance(value, dict) and set(value) == {"parameters"}:
        value = value["parameters"]
    if not isinstance(value, dict):
        raise ValueError("parameter JSON must be an object")
    return CHKPParams(**value)


def _signal_timeout(_signum, _frame):
    raise TimeoutError("external SIGTERM interrupted one-shot lifecycle")


def _run(out: Path, params: CHKPParams) -> None:
    started = perf_counter()
    stage = "preflight"
    durations: dict[str, float] = {}
    state: dict[str, object] = {}
    _json(out / "params.json", {"parameters": asdict(params), "security_claim": "none",
                                "backend_admitted": False, "parameters_are_formal": False})
    source_start = _source_hashes()
    _json(out / "source_manifest.json", {"sha256": source_start})
    signal.signal(signal.SIGTERM, _signal_timeout)

    def progress(name: str) -> float:
        nonlocal stage
        stage = name
        _json(out / "progress.json", {"stage": name, "elapsed_seconds": perf_counter() - started,
                                       "identity_retry": False})
        return perf_counter()

    def done(name: str, tick: float) -> None:
        durations[name] = perf_counter() - tick
        print(json.dumps({"stage": name, "seconds": durations[name],
                          "elapsed_seconds": perf_counter() - started}), flush=True)

    try:
        tick = progress(stage)
        suite = _suite(params)
        report = validate_suite(suite)
        _json(out / "preflight.json", {"ok": report.ok, "errors": report.errors,
                                        "capacity": report.capacity, "metadata": report.metadata,
                                        "suite_digest": suite.digest})
        if not report.ok:
            raise ValueError("selected suite preflight rejected: " + "; ".join(report.errors))
        done(stage, tick)

        hibe = Author2011HIBE()
        tick = progress("setup")
        public, master = hibe.setup(params)
        state.update(public=public, master=master)
        _bytes(out / "direct-public.bin", public)
        _bytes(out / "direct-master-setup.bin", master)
        done(stage, tick)

        tick = progress("extract")
        parent = hibe.extract(master, RAW_RECEIVER)
        state["parent"] = parent
        _bytes(out / "direct-parent.bin", parent)
        _bytes(out / "direct-master-after-extract.bin", master)
        done(stage, tick)

        tick = progress("derive")
        leaf = hibe.derive(parent, RAW_SENDER)
        state["leaf"] = leaf
        _bytes(out / "direct-leaf.bin", leaf)
        _bytes(out / "direct-parent-after-derive.bin", parent)
        done(stage, tick)

        tick = progress("level1_seed_kem")
        seed1 = os.urandom(32)
        ct1 = hibe.encrypt_level1(public, RAW_RECEIVER, seed1)
        if hibe.decrypt_level1(parent, ct1) != seed1:
            raise AssertionError("level-one real seed KEM mismatch")
        _bytes(out / "direct-level1-ct.bin", ct1)
        done(stage, tick)

        tick = progress("level2_seed_kem")
        seed2 = os.urandom(32)
        ct2 = hibe.encrypt(public, RAW_RECEIVER, RAW_SENDER, seed2)
        if hibe.decrypt(leaf, ct2) != seed2:
            raise AssertionError("level-two real seed KEM mismatch")
        _bytes(out / "direct-level2-ct.bin", ct2)
        _json(out / "direct-seed-digests.json", {"level1_sha256": _hash(seed1),
                                                 "level2_sha256": _hash(seed2)})
        done(stage, tick)

        tick = progress("selected_luo_setup")
        runtime = build_runtime(suite)
        limits = runtime.hibe_params.limits
        hpk = HybridPublicKey(limits, public)
        hmsk = HybridMasterSecret(hpk, master)
        ipk, imsk = runtime.ibs.setup(runtime.ibs_params)
        combined_public = PublicKey(hpk, ipk)
        combined_master = MasterSecret(hmsk, imsk)
        state["combined_master"] = combined_master
        runtime.validate_master(combined_public, combined_master)
        _bytes(out / "combo-public.bin", combined_public)
        _bytes(out / "combo-master-before-issue.bin", combined_master)
        done(stage, tick)

        tick = progress("selected_sender_key")
        sender = runtime.proto.skgen(combined_master, COMBO_SENDER)
        _bytes(out / "combo-sender.bin", sender)
        done(stage, tick)

        tick = progress("selected_encoded_receiver_key")
        receiver = runtime.proto.rkgen(combined_master, COMBO_RECEIVER)
        state["receiver"] = receiver
        _bytes(out / "combo-receiver-before-derive.bin", receiver)
        _bytes(out / "combo-master-after-issue.bin", combined_master)
        done(stage, tick)

        tick = progress("selected_encrypt")
        combo_ct = runtime.proto.encrypt(combined_public, sender, COMBO_RECEIVER, MESSAGE)
        _bytes(out / "combo-ciphertext.bin", combo_ct)
        done(stage, tick)

        tick = progress("selected_decrypt")
        if runtime.proto.decrypt(combined_public, receiver, COMBO_SENDER, combo_ct) != MESSAGE:
            raise AssertionError("selected Hybrid/BYTEAUTH/Luo honest decryption mismatch")
        _bytes(out / "combo-receiver-after-derive.bin", receiver)
        _bytes(out / "combo-master-after-decrypt.bin", combined_master)
        done(stage, tick)

        tick = progress("fresh_process_restore_and_negatives")
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                "--restore-only", "--output", str(out)],
                               cwd=ROOT, text=True, capture_output=True, check=False)
        (out / "restore-stdout.txt").write_text(child.stdout, encoding="utf-8")
        (out / "restore-stderr.txt").write_text(child.stderr, encoding="utf-8")
        if child.returncode != 0:
            raise AssertionError(f"fresh-process restore/negatives exit {child.returncode}; inspect restore-stderr.txt")
        done(stage, tick)

        if _source_hashes() != source_start:
            raise AssertionError("source files changed during the one-shot run")
        receipt = {
            "status": "passed", "suite_digest": suite.digest,
            "source_sha256": source_start, "parameters": asdict(params),
            "system_csprng": True, "real_root": True, "real_parent_and_leaf": True,
            "level1_seed_match": True, "level2_seed_match": True,
            "selected_combo_roundtrip": True,
            "fresh_process_restore": json.loads((out / "restoration.json").read_text())["status"],
            "negative_checks": json.loads((out / "negatives.json").read_text())["check_count"],
            "stage_seconds": durations, "total_seconds": perf_counter() - started,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False,
            "scope": "one new root; two distinct receiver addresses; one sender per positive path; no retries",
        }
        _json(out / "receipt.json", receipt)
        progress("completed")
        print(json.dumps({"status": "passed", "total_seconds": receipt["total_seconds"],
                          "negative_checks": receipt["negative_checks"]}), flush=True)
    except BaseException as exc:
        # Snapshot the live tombstones; never regenerate a failed address.
        for key, filename in (("master", "direct-master-latest.bin"),
                              ("parent", "direct-parent-latest.bin"),
                              ("combined_master", "combo-master-latest.bin"),
                              ("receiver", "combo-receiver-latest.bin")):
            if key in state:
                try:
                    _bytes(out / filename, state[key])
                except Exception:
                    pass
        failure = {"status": "failed", "stage": stage, "exception": type(exc).__name__,
                   "message": str(exc), "stage_seconds": durations,
                   "total_seconds": perf_counter() - started,
                   "identity_retry": False, "security_claim": "none"}
        _json(out / "failure.json", failure)
        print(json.dumps(failure), flush=True)
        raise


class _NoHIBEEntropy:
    def read(self, _n: int) -> bytes:
        raise AssertionError("restored key unexpectedly sampled a CHKP leaf")


def _restore(out: Path) -> None:
    # Sage's first import initializes its own interpreter RNG. The guard below
    # covers object restoration and direct/honest decapsulation only.
    import sage.all  # noqa: F401

    started = perf_counter()
    params = CHKPParams(**json.loads((out / "params.json").read_text())["parameters"])
    suite = _suite(params)
    runtime = build_runtime(suite)
    if suite.digest != json.loads((out / "preflight.json").read_text())["suite_digest"]:
        raise AssertionError("suite changed across fresh process")
    checks: list[dict[str, object]] = []

    def check(name: str, input_description: str, expected: object, observed: object,
              source: bytes | None = None) -> None:
        value = {"name": name, "input": input_description, "expected": expected,
                 "observed": observed, "passed": observed == expected}
        if source is not None:
            value["input_sha256"] = _hash(source)
        checks.append(value)
        if observed != expected:
            raise AssertionError(f"negative/control check failed: {name}")

    def load(name: str, cls):
        raw = (out / name).read_bytes()
        obj = cls.from_bytes(raw)
        check("canonical-" + name, "fresh-process decode/re-encode", True,
              obj.to_bytes() == raw, raw)
        return obj

    def no_entropy(*_args, **_kwargs):
        raise AssertionError("restoration requested OS/CSPRNG entropy")

    try:
        with patch.object(os, "urandom", no_entropy), patch.object(SecureRandom, "read", no_entropy):
            public = load("direct-public.bin", Author2011PublicKey)
            master = load("direct-master-after-extract.bin", Author2011MasterSecret)
            parent = load("direct-parent-after-derive.bin", Author2011Level1Key)
            leaf = load("direct-leaf.bin", Author2011Level2Key)
            ct1 = load("direct-level1-ct.bin", Author2011Ciphertext)
            ct2 = load("direct-level2-ct.bin", Author2011Ciphertext)
            digests = json.loads((out / "direct-seed-digests.json").read_text())
            hibe = Author2011HIBE()
            check("direct-master-binding", "restored direct master/public binding", True,
                  hibe.validate_key_binding(public, master))
            check("level1-restored", "canonical first-level key and ciphertext; no entropy",
                  digests["level1_sha256"], _hash(hibe.decrypt_level1(parent, ct1)))
            check("level2-restored", "canonical second-level key and ciphertext; no entropy",
                  digests["level2_sha256"], _hash(hibe.decrypt(leaf, ct2)))
            raw_combo_public = (out / "combo-public.bin").read_bytes()
            combo_public = PublicKey.from_bytes(raw_combo_public, runtime.decoders["hpk"],
                                                runtime.decoders["ipk"])
            check("canonical-combo-public", "fresh-process decode/re-encode", True,
                  combo_public.to_bytes() == raw_combo_public, raw_combo_public)
            raw_combo_master = (out / "combo-master-after-decrypt.bin").read_bytes()
            combo_master = MasterSecret.from_bytes(raw_combo_master,
                            runtime.decoders["hmsk"], runtime.decoders["imsk"])
            check("canonical-combo-master", "fresh-process decode/re-encode", True,
                  combo_master.to_bytes() == raw_combo_master, raw_combo_master)
            raw_sender = (out / "combo-sender.bin").read_bytes()
            sender = SenderKey.from_bytes(raw_sender, runtime.decoders["sk"])
            check("canonical-combo-sender", "fresh-process decode/re-encode", True,
                  sender.to_bytes() == raw_sender, raw_sender)
            raw_receiver = (out / "combo-receiver-after-derive.bin").read_bytes()
            receiver = ReceiverKey.from_bytes(raw_receiver, runtime.decoders["sk1"])
            check("canonical-combo-receiver", "fresh-process decode/re-encode", True,
                  receiver.to_bytes() == raw_receiver, raw_receiver)
            raw_ct = (out / "combo-ciphertext.bin").read_bytes()
            combo_ct = runtime.proto.load_ciphertext(raw_ct)
            check("canonical-combo-ciphertext", "fresh-process decode/re-encode", True,
                  combo_ct.to_bytes() == raw_ct, raw_ct)
            runtime.validate_master(combo_public, combo_master)
            runtime.validate_sender(combo_public, sender)
            runtime.validate_receiver(combo_public, receiver)
            plain = runtime.proto.decrypt(combo_public, receiver, sender.identity, combo_ct,
                                          rng=_NoHIBEEntropy())
            check("honest-restored", "same cached real leaf; no OS/HIBE entropy",
                  MESSAGE.hex(), plain.hex() if isinstance(plain, bytes) else repr(plain), raw_ct)
        _json(out / "restoration.json", {"status": "passed", "checks": checks,
                                         "check_count": len(checks),
                                         "guard": "Sage initialized first; OS and SecureRandom blocked over decode/decapsulate",
                                         "seconds": perf_counter() - started})

        neg: list[dict[str, object]] = []
        def reject(name: str, description: str, ct):
            raw = ct if isinstance(ct, bytes) else ct.to_bytes()
            value = runtime.proto.decrypt(combo_public, receiver, sender.identity, ct,
                                          rng=_NoHIBEEntropy())
            item = {"name": name, "input": description, "expected": "BOTTOM",
                    "observed": "BOTTOM" if value is BOTTOM else "plaintext",
                    "passed": value is BOTTOM, "input_sha256": _hash(raw)}
            neg.append(item)
            if not item["passed"]:
                raise AssertionError(f"negative/control check failed: {name}")

        other_sender = runtime.proto.skgen(combo_master, OTHER_SENDER)
        for name, rcv, signer in (
            ("receiver-only-wrong", OTHER_RECEIVER, sender),
            ("sender-only-wrong", receiver.identity, other_sender),
            ("both-wrong", OTHER_RECEIVER, other_sender),
        ):
            ct = runtime.proto.encrypt(combo_public, signer, rcv, MESSAGE)
            reject(name, f"valid ciphertext for ({rcv!r},{signer.identity!r}); decrypt with fixed pair", ct)

        inner = combo_ct.inner_bytes
        changed_inner = inner[:-1] + bytes([inner[-1] ^ 1])
        variants = {
            "ciphertext-bit-tamper": ByteAuthCiphertext(combo_ct.context, combo_ct.ots_key,
                                                         changed_inner, combo_ct.signature).to_bytes(),
            "outer-signature-bit-tamper": raw_ct[:-1] + bytes([raw_ct[-1] ^ 1]),
            "truncated-field": raw_ct[:-1],
            "appended-field": raw_ct + b"\0",
            "repeated-field": raw_ct + encode_bytes(combo_ct.signature),
        }
        for name, raw in variants.items():
            reject(name, "mutation of complete BYTEAUTH wire", raw)
        reject("authenticated-inner-ciphertext-tamper",
               "changed inner ciphertext with valid fresh outer OTS",
               authenticate_inner(combo_public, changed_inner, generate_lamport_key()))

        for name in ("inner-signature-bit-tamper", "random-forged-signature"):
            ots = generate_lamport_key()
            envelope = encode_bound_message(ots.public_key.commitment(), MESSAGE)
            legitimate = runtime.ibs.sign(sender.signing_key,
                         encode_message(receiver.identity, envelope)).to_bytes()
            bad = (legitimate[:-1] + bytes([legitimate[-1] ^ 1])
                   if name == "inner-signature-bit-tamper" else os.urandom(len(legitimate)))
            payload = DOMAIN_SIGNATURE + encode_bytes(bad) + encode_bytes(envelope)
            inner_ct = runtime.hibe.encrypt(combo_public.hpk, receiver.identity,
                                            sender.identity, payload)
            wrapped = authenticate_inner(combo_public, Ciphertext(inner_ct).to_bytes(), ots)
            reject(name, "fresh valid outer OTS and AEAD; altered Luo signature bytes", wrapped)

        _json(out / "negatives.json", {"status": "passed", "checks": neg,
                                       "check_count": len(neg),
                                       "new_hibe_private_sampling": False,
                                       "seconds": perf_counter() - started})
        print(json.dumps({"status": "passed", "restored": len(checks),
                          "negative_checks": len(neg)}), flush=True)
    except BaseException as exc:
        _json(out / "restore-failure.json", {"status": "failed", "exception": type(exc).__name__,
                                             "message": str(exc), "checks": checks,
                                             "seconds": perf_counter() - started})
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True,
                        help="new directory under repository build/outputs; contains private keys")
    parser.add_argument("--params", help="optional CHKPParams JSON; default is n=1 research profile")
    parser.add_argument("--restore-only", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.restore_only:
        _restore(_existing_output(args.output))
        return
    out = _new_output(args.output)
    try:
        params = _params(args.params)
    except BaseException as exc:
        _json(out / "failure.json", {"status": "failed", "stage": "parameter_parse",
                                     "exception": type(exc).__name__, "message": str(exc),
                                     "identity_retry": False})
        raise
    _run(out, params)


if __name__ == "__main__":
    main()
