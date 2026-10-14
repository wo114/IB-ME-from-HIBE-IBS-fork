"""System-entropy Foo--Li lifecycle receipt; never exports key/seed/signature data."""
from dataclasses import asdict
import hashlib
import json
import platform
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

from ibme.ibs.foo_li import FooLiIBS, FooLiParams, PublicKey, MasterSecret, SigningKey, Signature


class NoEntropy:
    def read(self, count): raise AssertionError("fresh entropy forbidden in recovery")


def run():
    params = FooLiParams()
    identities = (b"Sender-0", b"Sender-1")
    messages = (b"", b"hello", b"a\0b", bytes(32), bytes(range(256)), b"m"*4096)
    timing = {name: [] for name in ("setup", "key_extract", "cached_extract", "sign", "verify", "restore_master", "restore_signing")}
    sizes = {name: [] for name in ("public_key", "master_secret", "signing_key", "signature")}
    counts = {"roots": 0, "users": 0, "signatures": 0, "verifications": 0,
              "recovery_replays": 0, "wrong_identity_accepts": 0, "wrong_message_accepts": 0,
              "random_vector_accepts": 0, "altered_public_context_rejects": 0,
              "truncated_rejects": 0, "fresh_process_recoveries": 0}

    def timed(name, call):
        start = time.perf_counter()
        value = call()
        timing[name].append(time.perf_counter()-start)
        return value

    for _ in range(3):
        backend = FooLiIBS()
        pk, master = timed("setup", lambda: backend.setup(params))
        counts["roots"] += 1
        sizes["public_key"].append(len(pk.to_bytes()))
        keys = [timed("key_extract", lambda identity=i: backend.key_extract(master, identity)) for i in identities]
        counts["users"] += len(keys)
        restored_master = timed("restore_master", lambda: MasterSecret.from_bytes(master.to_bytes()))
        sizes["master_secret"].append(len(master.to_bytes()))
        for key in keys:
            restored = timed("restore_signing", lambda: SigningKey.from_bytes(key.to_bytes()))
            assert timed("cached_extract", lambda: FooLiIBS(NoEntropy()).key_extract(restored_master, key.identity)) == key
            sizes["signing_key"].append(len(key.to_bytes()))
            for message in messages:
                sig = timed("sign", lambda: backend.sign(key, message))
                counts["signatures"] += 1
                assert timed("verify", lambda: FooLiIBS(NoEntropy()).verify(pk, key.identity, message, sig))
                counts["verifications"] += 1
                sizes["signature"].append(len(sig.to_bytes()))
                assert backend.load_signature(pk, sig.to_bytes()) == sig
                assert FooLiIBS(NoEntropy()).sign(restored, message) == sig
                counts["recovery_replays"] += 1
                counts["wrong_identity_accepts"] += backend.verify(pk, b"Other", message, sig)
                counts["wrong_message_accepts"] += backend.verify(pk, key.identity, b"altered", sig)
                # A public random-looking vector is not produced by Sign.
                raw = hashlib.shake_256(message+key.identity).digest(params.dimension)
                random_sig = Signature(pk.context, tuple(x % params.q for x in raw), 0)
                counts["random_vector_accepts"] += backend.verify(pk, key.identity, message, random_sig)
                foreign = PublicKey(params, b"other-epoch", pk.coefficients)
                assert not backend.verify(foreign, key.identity, message, sig)
                counts["altered_public_context_rejects"] += 1
                from ibme.core.errors import SerializationError
                try:
                    backend.load_signature(pk, sig.to_bytes()[:-1])
                except SerializationError:
                    counts["truncated_rejects"] += 1
                else:
                    raise AssertionError("truncated signature accepted")
        # Private files exist only in an automatically cleaned temporary folder.
        with tempfile.TemporaryDirectory(prefix="foo-li-recovery-") as folder:
            path = Path(folder)
            (path/"master").write_bytes(master.to_bytes())
            (path/"key").write_bytes(keys[0].to_bytes())
            child = '''
from pathlib import Path
import sys
from ibme.ibs.foo_li import FooLiIBS,MasterSecret,SigningKey
class NoEntropy:
    def read(self,n): raise AssertionError("fresh entropy forbidden")
p=Path(sys.argv[1]); b=FooLiIBS(NoEntropy())
m=MasterSecret.from_bytes((p/"master").read_bytes())
k=SigningKey.from_bytes((p/"key").read_bytes())
assert b.key_extract(m,k.identity)==k
s=b.sign(k,b"new message after recovery")
assert b.verify(m.public_key,k.identity,b"new message after recovery",s)
'''
            subprocess.run([sys.executable, "-c", child, folder], check=True, timeout=90)
            counts["fresh_process_recoveries"] += 1

    repo = Path(__file__).resolve().parents[2]
    sources = sorted((repo/"src/ibme/ibs/foo_li").glob("*.py")) + [Path(__file__).resolve()]
    for name in ("foo_li_runtime_reference.py", "foo_li_public_verifier.py", "foo_li_initialization.py",
                 "online_mp12_reference.py", "online_gaussian_reference.py"):
        sources.append(repo/"experiments/research"/name)
    return {"status": "research_functional_pass", "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "parameters": asdict(params), "rng": "system CSPRNG for setup and per-user seeds",
        "oracle": "finite deterministic SHAKE candidate; not a QROM theorem",
        "identity_bytes": [len(x) for x in identities], "message_bytes": [len(x) for x in messages],
        "counts": counts, "sizes_bytes": sizes,
        "timing_seconds": {k: {"samples": v, "median": statistics.median(v),
            "quartiles_inclusive": statistics.quantiles(v, n=4, method="inclusive")} for k,v in timing.items()},
        "environment": {"system": platform.platform(), "machine": platform.machine(), "python": platform.python_version()},
        "source_sha256": {str(p.relative_to(repo)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "limits": ["q=3 is publicly forgeable; wrong-message/identity acceptance is retained",
            "No HIBE combination, comparable secure-parameter benchmark, or formal security admission",
            "No persisted secret, seed, private snapshot or actual signature is included"]}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "counts": receipt["counts"]}))
