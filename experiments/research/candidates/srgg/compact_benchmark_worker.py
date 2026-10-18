"""Private worker; exports only allowlisted timings, lengths and booleans."""
import argparse
from dataclasses import asdict
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import time
from unittest.mock import patch


class NoRead:
    def read(self, count):
        raise RuntimeError("unexpected entropy request")


class CountingSource:
    def __init__(self, source):
        self.source, self.bytes, self.requests = source, 0, 0

    def read(self, count):
        value = self.source.read(count)
        self.bytes += len(value)
        self.requests += 1
        return value


class Worker:
    def __init__(self, path):
        self.path = Path(path)
        self.report = {"status": "running", "phases": [], "checks": {},
                       "private_material_exported": False}

    def phase(self, name, action):
        start, cpu = time.monotonic_ns(), time.process_time_ns()
        row = {"name": name, "start_ns": start, "status": "failed"}
        try:
            value = action()
            row["status"] = "passed"
            return value
        finally:
            row.update(end_ns=time.monotonic_ns(), cpu_seconds=(time.process_time_ns()-cpu)/1e9)
            row["seconds"] = (row["end_ns"]-start)/1e9
            self.report["phases"].append(row)

    def require(self, name, condition):
        self.report["checks"][name] = bool(condition)
        if not condition:
            raise RuntimeError("benchmark check failed")


def run(worker, profile, mode, warm_repetitions, codec_repetitions):
    def imports():
        from sage.version import version
        from ibme.core.randomness import SecureRandom
        from . import paper_compact as compact, paper_objects as objects
        from .paper_parameters import PaperParams
        from .paper_schur_backend import SourceSchurBackend
        return version, SecureRandom, compact, objects, PaperParams, SourceSchurBackend
    version, SecureRandom, compact, objects, PaperParams, Backend = worker.phase("imports", imports)
    params = PaperParams(profile, "table-standard-deviation")
    if sha256(Path(params.source.source_pdf).read_bytes()).hexdigest() != params.source.source_sha256:
        raise ValueError("paper source binding mismatch")
    rng = CountingSource(SecureRandom())
    backend = Backend(rng=rng)
    worker.rng, worker.backend = rng, backend
    identity, message = b"SRGG benchmark identity".ljust(64, b"."), b"SRGG benchmark message".ljust(32, b".")
    worker.report.update(profile=params.record(), published_inputs=params.source.record(), mode=mode,
        sage=version, identity_bytes=len(identity), message_bytes=len(message), randomness="SecureRandom",
        numerical_options={"series": asdict(backend.series_options), "scalar": asdict(backend.scalar_options)},
        security_claim="none", backend_admitted=False, parameters_are_formal=False,
        nist_security_category=None, warm_repetitions=warm_repetitions, codec_repetitions=codec_repetitions)
    if mode == "generate":
        public, master = worker.phase("setup", lambda: backend.setup(params))
        key = worker.phase("extract", lambda: backend.key_extract(master, identity))
        signature = worker.phase("sign-first", lambda: backend.sign(key, message))
        worker.report["phases"][-1]["sign_attempts"] = backend.sign_attempts
        worker.require("first-verify", worker.phase("verify-first", lambda: backend.verify(public, identity, message, signature)))
        for index in range(warm_repetitions):
            attempts = backend.sign_attempts
            current = worker.phase(f"sign-warm-{index}", lambda: backend.sign(key, message))
            worker.report["phases"][-1]["sign_attempts"] = backend.sign_attempts-attempts
            worker.require(f"warm-verify-{index}", worker.phase(f"verify-warm-{index}",
                lambda: backend.verify(public, identity, message, current)))
            del current
        values = {"public": public, "master": master, "key": key, "signature": signature}
        encoders = {"public": compact.dump_public, "master": compact.dump_master,
                    "key": compact.dump_key, "signature": lambda value: compact.dump_signature(public, value)}
        decoders = {"public": compact.load_public,
                    "master": lambda raw: compact.load_master(raw, expected_public=public),
                    "key": lambda raw: compact.load_key(raw, expected_public=public),
                    "signature": lambda raw: compact.load_signature(public, raw)}
        worker.report["object_sizes_bytes"] = {}
        before = rng.requests
        with patch.object(SecureRandom, "read", side_effect=RuntimeError("codec requested entropy")):
            for name, value in values.items():
                reference, packed = value.to_bytes(), encoders[name](value)
                worker.report["object_sizes_bytes"][name] = {"json": len(reference), "compact": len(packed)}
                worker.require(name+"-compact-json-equality", decoders[name](packed).to_bytes() == reference)
                for variant, raw in (("json", reference), ("compact", packed)):
                    path = worker.path/(name+"."+variant)
                    path.write_bytes(raw)
                    path.chmod(0o600)
                for index in range(codec_repetitions):
                    variants = ("json", "compact") if index % 2 == 0 else ("compact", "json")
                    for variant in variants:
                        gc.collect()
                        encode = value.to_bytes if variant == "json" else lambda: encoders[name](value)
                        decode = type(value).from_bytes if variant == "json" else decoders[name]
                        raw = worker.phase(f"codec-{name}-{variant}-encode-{index}", encode)
                        restored = worker.phase(f"codec-{name}-{variant}-decode-{index}", lambda: decode(raw))
                        worker.require(f"{name}-{variant}-roundtrip-{index}", restored.to_bytes() == reference)
                        del restored, raw
                del reference, packed
        worker.require("codecs-zero-entropy", rng.requests == before)
        worker.report["dense_coefficient_matrix_materialized"] = backend.last_master_certificate[
            "dense_coefficient_matrix_materialized"]
    else:
        variant = mode.removeprefix("restore-")
        raw = worker.phase("read-snapshots", lambda: {
            name: (worker.path/(name+"."+variant)).read_bytes()
            for name in ("public", "master", "key", "signature")})
        public = worker.phase("restore-public", lambda: compact.load_public(raw["public"]) if variant == "compact"
                              else objects.PublicKey.from_bytes(raw["public"]))
        master = worker.phase("restore-master", lambda: compact.load_master(raw["master"], expected_public=public)
                              if variant == "compact" else objects.MasterSecret.from_bytes(raw["master"]))
        key = worker.phase("restore-key", lambda: compact.load_key(raw["key"], expected_public=public)
                           if variant == "compact" else objects.SigningKey.from_bytes(raw["key"]))
        signature = worker.phase("restore-signature", lambda: compact.load_signature(public, raw["signature"])
                                 if variant == "compact" else objects.Signature.from_bytes(raw["signature"]))
        cached = worker.phase("cached-key-reuse", lambda: Backend(rng=NoRead()).key_extract(master, identity))
        worker.require("cached-key-zero-entropy", cached.to_bytes() == key.to_bytes())
        worker.require("restored-old-signature-valid", backend.verify(public, identity, message, signature))
        again = worker.phase("sign-after-restore", lambda: backend.sign(key, message))
        worker.require("restored-key-resigned", worker.phase("verify-after-restore",
            lambda: backend.verify(public, identity, message, again)))
    worker.report["status"] = "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-directory", type=Path, required=True)
    parser.add_argument("--profile", choices=("PARAM-I", "PARAM-II", "PARAM-III"), required=True)
    parser.add_argument("--mode", choices=("generate", "restore-json", "restore-compact"), required=True)
    parser.add_argument("--warm-repetitions", type=int, default=3)
    parser.add_argument("--codec-repetitions", type=int, default=5)
    args = parser.parse_args()
    os.umask(0o077)
    worker = Worker(args.private_directory)
    try:
        if not (0 <= args.warm_repetitions <= 16 and 1 <= args.codec_repetitions <= 32):
            raise ValueError("benchmark repeat limit")
        run(worker, args.profile, args.mode, args.warm_repetitions, args.codec_repetitions)
    except BaseException as error:
        worker.report.update(status="failed", error_type=type(error).__name__,
                             private_diagnostics_exported=False)
    finally:
        worker.report["kernel_lifetime_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
        if hasattr(worker, "rng"):
            worker.report.update(entropy_bytes_returned=worker.rng.bytes,
                entropy_read_requests=worker.rng.requests, setup_attempts=worker.backend.setup_attempts,
                extraction_calls=worker.backend.extract_calls, sign_attempts=worker.backend.sign_attempts)
    worker.path.joinpath("worker.json").write_text(json.dumps(worker.report, sort_keys=True, indent=2)+"\n")
    raise SystemExit(0 if worker.report["status"] == "passed" else 1)


if __name__ == "__main__":
    main()
