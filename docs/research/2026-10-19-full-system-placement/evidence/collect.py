"""Export allowlisted public receipts; never read serialized secret keys."""
import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

from experiments.research.wsl_wheel_runtime import wheel_manifest


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generation", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generation = json.loads((args.generation / "receipt.json").read_bytes())
    cli = json.loads((args.cli / "receipt.json").read_bytes())
    assert generation["status"] == cli["status"] == "passed"
    summary = {key: generation[key] for key in ("schema", "status", "source_commit", "suite", "environment",
        "repetitions", "warm_repetitions_per_state", "message_bytes", "identity_bytes", "randomness",
        "timing_seconds", "security_claim", "backend_admitted", "parameters_are_formal", "uses_ROM")}
    summary["original_receipt_sha256"] = hashlib.sha256((args.generation / "receipt.json").read_bytes()).hexdigest()
    summary["states"] = []
    for index, record in enumerate(generation["records"]):
        summary["states"].append(dict(index=index,
            public_key_sha256=hashlib.sha256((args.generation / f"repetition-{index}/public.bin").read_bytes()).hexdigest(),
            generation_status=record["generation"]["status"], restore_status=record["restore"]["status"],
            restore_entropy_bytes=record["restore"]["entropy_bytes"],
            generation_done=(args.generation / f"repetition-{index}/generation.done").is_file(),
            sizes=record["generation"]["sizes"]))
    write(args.output / "generation.json", summary)
    # CLI receipts already exclude command stdout/stderr and all secret bytes.
    write(args.output / "cli.json", cli)
    manifest = wheel_manifest(args.wheel)
    write(args.output / "wheel-manifest.json", dict(files=manifest,
        wheel_sha256=hashlib.sha256(args.wheel.read_bytes()).hexdigest(), file_count=len(manifest)))
    from ibme.hibe.latte.engine import Native
    from ibme.hibe.latte.params import LATTEParams
    from ibme.ibs.certified.mldsa import MLDSA
    latte = Native(LATTEParams(**cli["parameters"]["hibe_params"]))
    mldsa = MLDSA("ml-dsa-44", timeout=30)
    native = dict(latte=dict(binary_sha256=latte.binary_sha256,
                            metadata=json.loads(latte.call("meta", b""))),
                  mldsa=dict(binary_sha256=mldsa.binary_sha256, metadata=mldsa.metadata),
                  scope="post-run static metadata/hash query; no key generation, sampling or signing")
    write(args.output / "native.json", native)
    names = ("placement.json", "profile-source.json", "profile-wsl.json", "cli.json",
             "generation.json", "wheel-manifest.json", "native.json")
    provenance = dict(collected_utc=datetime.now(timezone.utc).isoformat(),
        measurement_source_commit=json.loads((args.output / "placement.json").read_bytes())["source_commit"],
        generation_source_commit=generation["source_commit"],
        wheel_sha256=hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
        artifacts={name: hashlib.sha256((args.output / name).read_bytes()).hexdigest() for name in names},
        private_inputs_not_published=True,
        memory_note="placement uses only per-process lifetime kernel ru_maxrss; generic environment.rss_method mentions a sampler which this experiment did not start",
        profile_note="cProfile is diagnostic; the formal placement observations are unprofiled; an earlier WSL diagnostic was replaced after a possible process overlap, with keys unchanged",
        development_note="initial counter hook and legacy module-alias checks were fixed; the three successful generation states from 58102d1 were retained, not resampled")
    write(args.output / "provenance.json", provenance)
    print(json.dumps(dict(status="collected", public_artifacts=len(names), verified_wheel_files=len(manifest))))


if __name__ == "__main__":
    main()
