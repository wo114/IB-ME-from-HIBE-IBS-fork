"""Bounded real Wang--PW issuer execution; publish metadata, never secrets.

Source mode and an offline installed-wheel mode both exercise real sampling.
Temporary private directories live outside the checkout and are not exported.
Failed requested attempts are recorded; this runner never retries until success.
"""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
from time import perf_counter

from ibme.core.errors import SerializationError
from ibme.ibs.wang_pw_service import FixedIssuer, STATE_FILE
from experiments.research.candidates.wang_pw import Backend, Params, PublicKey, SigningKey


class NoEntropy:
    def read(self, size):
        raise AssertionError("cached issuance/verification unexpectedly requested entropy")


_RECOVER = r'''
import hashlib,json,sys
from ibme.ibs.wang_pw_service import FixedIssuer
from experiments.research.candidates.wang_pw import Backend
class NoEntropy:
    def read(self,n): raise AssertionError("cache requested entropy")
issuer=FixedIssuer(sys.argv[1],Backend(rng=NoEntropy()))
key=issuer.key_extract(bytes.fromhex(sys.argv[2])); public=issuer.public_key()
backend=Backend(); sig=backend.sign(key,b"fresh-process-message")
assert backend.verify(public,key.identity,b"fresh-process-message",sig)
print(json.dumps(dict(key_digest=hashlib.sha256(key.to_bytes()).hexdigest(),verified=True)))
'''


def _hashes(root):
    ibme = root / "src" / "ibme" if (root / "src" / "ibme").is_dir() else root / "ibme"
    files = list((root / "experiments/research/candidates/wang_pw").glob("*.py"))
    files += list((ibme / "lattice/chkp").rglob("*.py"))
    files += list((ibme / "lattice/research").rglob("*.py"))
    files += list((ibme / "core").glob("*.py"))
    files += [ibme / "ibs/wang_pw_service.py", ibme / "cli_state.py", Path(__file__).resolve()]
    files += list((root / "experiments/research").glob("*gaussian_reference.py"))
    files += list((root / "experiments/research").glob("*mp12_reference.py"))
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(files)) if p.is_file()}


def run(attempts=3):
    if type(attempts) is not int or not 1 <= attempts <= 20:
        raise ValueError("attempts must be in 1..20")
    from experiments.research.candidates.wang_pw.audit import public_debug_forgery
    from sage.env import SAGE_VERSION

    root = Path(__file__).resolve().parents[2]
    before = _hashes(root)
    params, rows = Params(), []
    identities, messages = (b"Alice", b"Bob"), (b"", b"hello", bytes(range(16)))
    timings = {name: [] for name in ("initialize", "key_extract", "cached_extract", "sign", "verify", "restore_key")}
    sizes = {name: [] for name in ("public_key", "issuer_snapshot", "signing_key", "signature")}
    counts = dict(roots=0, users=0, signatures=0, verifications=0, cached_recoveries=0,
                  restored_key_signatures=0, fresh_process_signatures=0,
                  wrong_identity_accepts=0, wrong_message_accepts=0,
                  wrong_context_rejects=0, truncated_rejects=0, public_forgery_accepts=0)

    def timed(name, operation):
        start = perf_counter()
        try:
            return operation()
        finally:
            timings[name].append(perf_counter() - start)

    for attempt in range(attempts):
        stage, completed = "initialize", 0
        try:
            with tempfile.TemporaryDirectory(prefix="wang-pw-private-audit-") as temporary:
                directory = Path(temporary) / "issuer"
                issuer = FixedIssuer(directory)
                public = timed(stage, lambda: issuer.initialize(params, max_users=2))
                counts["roots"] += 1
                sizes["public_key"].append(len(public.to_bytes()))
                verifier = Backend(rng=NoEntropy())
                for identity in identities:
                    stage = "key_extract"
                    key = timed(stage, lambda: issuer.key_extract(identity))
                    counts["users"] += 1
                    sizes["signing_key"].append(len(key.to_bytes()))
                    stage = "cached_extract"
                    saved_digest = hashlib.sha256((directory / STATE_FILE).read_bytes()).digest()
                    recovered = FixedIssuer(directory, Backend(rng=NoEntropy()))
                    cached = timed(stage, lambda: recovered.key_extract(identity))
                    assert cached.to_bytes() == key.to_bytes()
                    assert cached.identity_salt == key.identity_salt
                    assert hashlib.sha256((directory / STATE_FILE).read_bytes()).digest() == saved_digest
                    assert recovered.public_key().to_bytes() == public.to_bytes()
                    counts["cached_recoveries"] += 1
                    stage = "restore_key"
                    restored = timed(stage, lambda: SigningKey.from_bytes(key.to_bytes()))
                    for message in messages:
                        stage = "sign"
                        signature = timed(stage, lambda: issuer.backend.sign(key, message))
                        counts["signatures"] += 1
                        sizes["signature"].append(len(signature.to_bytes()))
                        stage = "verify"
                        assert timed(stage, lambda: verifier.verify(public, identity, message, signature))
                        counts["verifications"] += 1
                        completed += 1
                        assert verifier.verify(PublicKey.from_bytes(public.to_bytes()), identity, message,
                            verifier.load_signature(public, signature.to_bytes()))
                        counts["wrong_identity_accepts"] += verifier.verify(public, b"Other", message, signature)
                        counts["wrong_message_accepts"] += verifier.verify(public, identity, message + b"!", signature)
                        assert not verifier.verify(public, identity, message, replace(signature,
                            context=bytes(x ^ 255 for x in signature.context)))
                        counts["wrong_context_rejects"] += 1
                        try:
                            verifier.load_signature(public, signature.to_bytes()[:-1])
                        except SerializationError:
                            counts["truncated_rejects"] += 1
                        else:
                            raise AssertionError("truncated signature accepted")
                    stage = "restored_sign"
                    resumed = issuer.backend.sign(restored, b"restored-key-message")
                    assert verifier.verify(public, identity, b"restored-key-message", resumed)
                    assert resumed.identity_salt == key.identity_salt
                    counts["restored_key_signatures"] += 1
                    stage = "fresh_process_recovery"
                    child = subprocess.run([sys.executable, "-B", "-c", _RECOVER,
                        str(directory), identity.hex()], cwd=root,
                        env=os.environ.copy(), capture_output=True, text=True, timeout=120)
                    if child.returncode:
                        raise RuntimeError("private recovery child failed")
                    reply = json.loads(child.stdout)
                    assert reply["verified"] is True
                    assert reply["key_digest"] == hashlib.sha256(key.to_bytes()).hexdigest()
                    counts["fresh_process_signatures"] += 1
                sizes["issuer_snapshot"].append((directory / STATE_FILE).stat().st_size)
                stage = "public_forgery_negative_control"
                forged = public_debug_forgery(public, b"Unissued", b"public forgery",
                    identity_salt=bytes(params.salt_bytes), message_salt=bytes(params.salt_bytes))
                assert verifier.verify(public, b"Unissued", b"public forgery", forged)
                counts["public_forgery_accepts"] += 1
                rows.append(dict(attempt=attempt + 1, status="completed", honest_signatures=completed))
        except Exception as exc:
            # Exception messages/traces and temporary paths can expose secrets.
            rows.append(dict(attempt=attempt + 1, status="failed", stage=stage,
                             exception_type=type(exc).__name__, honest_signatures=completed))
    if before != _hashes(root):
        raise RuntimeError("source changed during evidence collection")
    return dict(schema="IBME/WangPW-FIXED-ISSUER-AUDIT/1", parameters=params.record(),
        attempts=rows, counts=counts, all_requested_attempts_completed=all(r["status"] == "completed" for r in rows),
        security_claim="none", backend_admitted=False, parameters_are_formal=False,
        randomness="OS CSPRNG; fixed requested independent roots, no reroll; SHAKE instantiation with classical ROM claims conditional",
        identity_bytes=[len(i) for i in identities], message_bytes=[len(m) for m in messages],
        max_users=2, sizes_bytes=sizes, source_sha256=before,
        timings_seconds={name: dict(samples=values, median=statistics.median(values) if values else None)
                         for name, values in timings.items()},
        environment=dict(os=platform.platform(), machine=platform.machine(), processor=platform.processor(),
            logical_cpus=os.cpu_count(), python=platform.python_version(), sage=SAGE_VERSION,
            constant_time=False, acceleration="No algorithm-specific acceleration; Sage exact arithmetic"),
        limitations=["q=17,n=1 debug profile is publicly forgeable; fixed issuance does not repair it",
            "Wrong identity/message acceptance is measured, never hidden by a service whitelist",
            "Local measurements include validation/storage and are not secure-parameter benchmark rankings",
            "Snapshot, keys, salts, random seeds, actual signatures and secret-derived digests are not exported",
            "Formal parameters, root near-uniformity, fixed-service security mapping and all HIBE pairings remain separate",
            "Trusted local plaintext storage; no malicious rollback, NFS or mixed Windows/WSL writer guarantee"])


_INSTALLED = r'''
import hashlib,json,sys
from pathlib import Path
from experiments.research.wang_pw_service_audit import run
target=Path(sys.argv[1]).resolve(); result=run(1)
assert result["all_requested_attempts_completed"]
providers={}
for name,module in tuple(sys.modules.items()):
    if name=="ibme" or name.startswith("ibme.") or name=="experiments" or name.startswith("experiments.research"):
        file=getattr(module,"__file__",None)
        if file is not None:
            path=Path(file).resolve(); assert path.is_relative_to(target)
            providers[name]=dict(file=path.relative_to(target).as_posix(),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
assert "ibme.ibs.wang_pw_service" in providers
result.update(status="passed",source_providers=providers)
print(json.dumps(result))
'''


def run_installed(wheel):
    wheel = Path(wheel).resolve()
    with tempfile.TemporaryDirectory(prefix="wang-pw-installed-") as temporary:
        root, target = Path(temporary), Path(temporary) / "site"
        installed = subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
            "--target", str(target), str(wheel)], cwd=root, capture_output=True, text=True, timeout=120)
        if installed.returncode:
            raise RuntimeError("offline wheel installation failed")
        child = subprocess.run([sys.executable, "-B", "-c", _INSTALLED, str(target)], cwd=root,
            env={**os.environ, "PYTHONPATH": str(target), "PYTHONNOUSERSITE": "1"},
            capture_output=True, text=True, timeout=300)
        if child.returncode:
            raise RuntimeError(f"installed issuer execution failed, exit={child.returncode}")
        result = json.loads(child.stdout)
        result.update(wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
            installation="temporary --target outside repository; no index or dependency installation")
        return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--wheel", type=Path)
    arguments = parser.parse_args()
    result = run_installed(arguments.wheel) if arguments.wheel else run(arguments.attempts)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("all_requested_attempts_completed", "attempts", "counts")}))
    raise SystemExit(0 if result["all_requested_attempts_completed"] else 1)
