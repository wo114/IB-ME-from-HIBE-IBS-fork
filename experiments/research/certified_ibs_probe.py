"""System-random independent IBS lifecycle and fresh-process saved-state reuse.

Private keys stay in an exclusive private directory; only receipt.json may be
copied into delivery docs. This is not an IBME combination or security proof.
"""
import argparse
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time
import traceback
from unittest.mock import patch

from ibme.core.randomness import SecureRandom
from ibme.ibs import certified
from ibme.ibs.certified import (CertifiedIBS, CertifiedIBSParams, CertifiedPublicKey,
                               CertifiedMasterSecret, CertifiedSigningKey)
from ibme.ibs.certified.mldsa import MLDSA

IDENTITIES = (b"A" * 63 + b"0", b"A" * 63 + b"1")
MESSAGE = hashlib.sha256(b"independent certification IBS real lifecycle").digest()


class CountedSystem:
    def __init__(self):
        self.bytes = 0

    def read(self, size):
        value = SecureRandom().read(size)
        self.bytes += len(value)
        return value


def save(path, value):
    if type(value) is not bytes:
        value = (json.dumps(value, indent=2) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(value)
    os.replace(temporary, path)


def fingerprints():
    package = Path(certified.__file__).parent
    paths = [p for p in package.rglob("*") if p.suffix in (".py", ".c", ".h", ".json")
             or p.name in ("LICENSE", "AUTHORS.md")]
    result = {"ibme/ibs/certified/" + p.relative_to(package).as_posix():
              hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
    core = package.parents[1] / "core"
    for name in ("errors.py", "types.py", "hashing.py", "randomness.py"):
        result["ibme/core/" + name] = hashlib.sha256((core/name).read_bytes()).hexdigest()
    result["experiments/research/certified_ibs_probe.py"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


def restore(directory):
    operations = []
    original = MLDSA._run
    def no_entropy(*args, **kwargs):
        raise AssertionError("restore consumed entropy")
    def checked(engine, operation, data):
        if operation in ("keypair", "sign"):
            raise AssertionError("restore regenerated private material")
        operations.append(operation)
        return original(engine, operation, data)
    with patch.object(SecureRandom, "read", no_entropy), patch.object(MLDSA, "_run", checked):
        backend = CertifiedIBS()
        pk = CertifiedPublicKey.from_bytes((directory/"public.bin").read_bytes())
        params = CertifiedIBSParams.from_bytes((directory/"params.bin").read_bytes())
        master_raw = (directory/"master.bin").read_bytes()
        master = CertifiedMasterSecret.from_bytes(master_raw)
        if pk.params != params or master.public_key != pk:
            raise ValueError("restored parameter/public context mismatch")
        for i, identity in enumerate(IDENTITIES):
            saved = (directory/f"key-{i}.bin").read_bytes()
            key = backend.key_extract(master, identity)
            if key.to_bytes() != saved or CertifiedSigningKey.from_bytes(saved) != key:
                raise ValueError("restored fixed key differs")
        for i in range(32):
            signature = backend.load_signature(pk, (directory/f"signature-{i}.bin").read_bytes())
            if not backend.verify(pk, IDENTITIES[i % 2], MESSAGE, signature):
                raise ValueError("saved signature invalid after restoration")
        if master.to_bytes() != master_raw:
            raise ValueError("restore changed private snapshot")
    return dict(status="passed", fresh_process=True, external_entropy_calls=0,
                key_generations=0, new_signatures=0, matched_verifications=32,
                native_operation_counts={op:operations.count(op) for op in sorted(set(operations))},
                provider_path=str(Path(certified.__file__).resolve()))


def run(args):
    directory = args.private_directory.resolve()
    if args.restore_only:
        print(json.dumps(restore(directory)))
        return
    os.umask(0o077)
    directory.mkdir(parents=True, mode=0o700)
    params = CertifiedIBSParams(base_algorithm=args.algorithm)
    rng = CountedSystem()
    backend = CertifiedIBS(rng)
    report = dict(schema="CERTIFIED-IBS-REAL/1", status="started", source_commit=args.source_commit,
        parameters=asdict(params), repetitions=1, identities=2, identity_bytes=64, message_bytes=32,
        entropy="system CSPRNG; 32 B per keygen and hedged ML-DSA signing operation",
        standalone_IBS=True, HIBE_IBS_combination=False, security_claim="none", backend_admitted=False,
        parameters_are_formal=False, teaching_parameters=False,
        random_oracle_model="ML-DSA SHAKE instantiation; no complete IBS QROM/strong-UF mapping claimed",
        environment=dict(python=sys.version.split()[0], platform=platform.platform(),
            cpu=next((line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name")), "unknown")),
        source_sha256_before=fingerprints(), stages=[])
    start = time.monotonic()
    def stage(name, operation):
        before = rng.bytes
        t = time.monotonic()
        value = operation()
        report["stages"].append(dict(name=name, seconds=time.monotonic()-t, entropy_bytes=rng.bytes-before))
        return value
    try:
        engine = MLDSA(params.base_algorithm)
        report["native"] = dict(metadata=engine.metadata, binary_sha256=engine.binary_sha256)
        pk, master = stage("authority-keygen", lambda: backend.setup(params))
        save(directory/"public.bin", pk.to_bytes())
        save(directory/"params.bin", params.to_bytes())
        master.persist_callback = lambda state: save(directory/"master.bin", state.to_bytes())
        keys = [stage(f"identity-keygen-and-certificate-{i}", lambda identity=identity:
                      backend.key_extract(master, identity)) for i, identity in enumerate(IDENTITIES)]
        for i,key in enumerate(keys):
            save(directory/f"key-{i}.bin", key.to_bytes())
        def signatures():
            result = []
            for i in range(32):
                # A restored private key also produces an actual fresh signature.
                key = keys[i%2] if i != 1 else CertifiedSigningKey.from_bytes(keys[1].to_bytes())
                sig = backend.sign(key, MESSAGE)
                save(directory/f"signature-{i}.bin", sig.to_bytes())
                if not backend.verify(pk, key.identity, MESSAGE, sig):
                    raise ValueError("matching verification failed")
                if backend.verify(pk, IDENTITIES[1-i%2], MESSAGE, sig):
                    raise ValueError("wrong identity accepted")
                if backend.verify(pk, key.identity, bytes(32), sig):
                    raise ValueError("wrong message accepted")
                result.append(sig)
            return result
        sigs = stage("32-fresh-signatures-and-public-only-verification", signatures)
        # Swap real components from the second issued user; change the outer
        # public context on parameter replay to test the certificate equation.
        attacks = [replace(sigs[0], user_public=keys[1].user_public),
                   replace(sigs[0], certificate=keys[1].certificate),
                   replace(sigs[0], message_signature=sigs[1].message_signature)]
        for sig in attacks:
            if backend.verify(pk, IDENTITIES[0], MESSAGE, sig):
                raise ValueError("component replacement accepted")
        altered = replace(pk, params=replace(params, timeout_seconds=31))
        if backend.verify(altered, IDENTITIES[0], MESSAGE, replace(sigs[0],context=altered.context)):
            raise ValueError("parameter replay accepted")
        def new_process():
            result = subprocess.run([sys.executable,"-m","experiments.research.certified_ibs_probe",
                "--private-directory",str(directory),"--restore-only"], capture_output=True,timeout=60)
            if result.returncode:
                save(directory/"private-restore-error.txt", result.stderr)
                raise RuntimeError("fresh-process restoration failed")
            return json.loads(result.stdout)
        report["restore"] = stage("fresh-process-zero-entropy-restoration",new_process)
        report.update(status="passed", checks=dict(fresh_signatures=32, matching_verifications=32,
            wrong_identity_rejected=32, wrong_message_rejected=32, real_component_replacements_rejected=3,
            full_parameter_replay_rejected=1), objects=dict(public_bytes=len(pk.to_bytes()),
            master_with_two_users_bytes=len(master.to_bytes()), signing_key_bytes=[len(k.to_bytes()) for k in keys],
            complete_IBS_signature_bytes=len(sigs[0].to_bytes()), user_public_bytes=len(keys[0].user_public),
            certificate_bytes=len(keys[0].certificate), user_signature_bytes=len(sigs[0].message_signature)),
            public_key_sha256=hashlib.sha256(pk.to_bytes()).hexdigest())
        if len({s.to_bytes() for s in sigs}) != 32:
            raise ValueError("hedged signatures unexpectedly repeated")
        if MLDSA(params.base_algorithm).binary_sha256 != report["native"]["binary_sha256"]:
            raise ValueError("native executable changed during lifecycle")
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, automatic_retry=False)
        save(directory/"private-error.txt",traceback.format_exc().encode())
        raise
    finally:
        report.update(seconds=time.monotonic()-start, entropy_bytes=rng.bytes,
            source_sha256_after=fingerprints(), parent_peak_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            maximum_observed_child_RSS_KiB=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        report["source_unchanged"] = report["source_sha256_before"] == report["source_sha256_after"]
        if not report["source_unchanged"]:
            report["status"] = "failed"
        save(directory/"receipt.json",report)
    if report["status"] != "passed":
        raise RuntimeError("source changed during lifecycle")
    print(json.dumps(dict(status="passed",algorithm=args.algorithm,seconds=report["seconds"],
                          entropy_bytes=rng.bytes,signature_bytes=report["objects"]["complete_IBS_signature_bytes"])))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory",required=True,type=Path)
    parser.add_argument("--algorithm",choices=("ml-dsa-44","ml-dsa-65","ml-dsa-87"),default="ml-dsa-44")
    parser.add_argument("--source-commit",default="uncommitted")
    parser.add_argument("--restore-only",action="store_true")
    run(parser.parse_args())


if __name__=="__main__":
    main()
