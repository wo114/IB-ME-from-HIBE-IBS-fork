"""Profile complete public IB-ME operations using an existing private CLI state.

The output contains function names/times and public configuration only. Private
objects, cProfile locals and serialized keys are never exported. Profiling times
are diagnostic and must not be used as uninstrumented performance measurements.
"""

import argparse
import cProfile
import hashlib
import json
from pathlib import Path
import pstats

from .runtime_metrics import environment


def load_state(directory):
    from ibme.assembly import SuiteConfig, build_runtime
    from ibme.cli import _read_state_object, _load_state_meta
    from ibme.protocol.baseline import PublicKey, SenderKey, ReceiverKey

    state = directory / "state"
    metadata = _load_state_meta(state)
    config = SuiteConfig.from_dict(metadata["suite"])
    runtime = build_runtime(config)
    decoders = runtime.decoders
    public = PublicKey.from_bytes(_read_state_object(state / "mpk.bin", metadata, "mpk"), decoders["hpk"], decoders["ipk"])
    # This existing CLI probe uses 64-byte A/B identities. Load through public
    # decoders; never inspect the primitive's internal key material.
    sender_id, receiver_id = b"A" * 64, b"B" * 64
    tag = lambda identity: hashlib.sha256(identity).hexdigest()[:16]
    sender = SenderKey.from_bytes(_read_state_object(state / f"sender-{tag(sender_id)}.bin", metadata, "sender"), decoders["sk"])
    receiver = ReceiverKey.from_bytes(_read_state_object(state / f"receiver-{tag(receiver_id)}.bin", metadata, "receiver"), decoders["sk1"])
    runtime.validate_sender(public, sender)
    runtime.validate_receiver(public, receiver)
    message = (directory / "message.bin").read_bytes()
    wire = (directory / "cipher.bin").read_bytes()
    if runtime.proto.decrypt(public, receiver, sender_id, wire) != message:
        raise AssertionError("existing state/ciphertext mismatch")
    return config, runtime, public, sender, receiver, message


def profile(directory, repetitions):
    config, runtime, public, sender, receiver, message = load_state(directory)
    phases = {}
    for operation in ("encrypt", "decrypt"):
        profiler = cProfile.Profile()
        for _ in range(repetitions):
            if operation == "encrypt":
                # Include complete wire encoding, fresh system entropy each time.
                wire = profiler.runcall(lambda: runtime.proto.encrypt(
                    public, sender, receiver.identity, message).to_bytes())
            else:
                recovered = profiler.runcall(runtime.proto.decrypt, public, receiver, sender.identity, wire)
                if recovered != message:
                    raise AssertionError("profiled decrypt mismatch")
        stats = pstats.Stats(profiler)
        rows = []
        for (filename, line, name), (primitive, total, own, cumulative, _callers) in stats.stats.items():
            # Paths are public source provenance, not file contents.
            if "/ibme/" in filename or "subprocess" in filename or "pathlib" in filename or name in ("read", "open"):
                rows.append(dict(file=filename, line=line, function=name, calls=total,
                                 primitive_calls=primitive, own_seconds=own, cumulative_seconds=cumulative))
        phases[operation] = dict(total_seconds=stats.total_tt,
            top_cumulative=sorted(rows, key=lambda row: row["cumulative_seconds"], reverse=True)[:35],
            top_self=sorted(rows, key=lambda row: row["own_seconds"], reverse=True)[:15])
    return dict(schema="FULL-IBME-HOTSPOTS/1", status="passed", suite=config.to_dict(),
                suite_digest=config.digest, environment=environment(), repetitions=repetitions,
                identity_bytes=len(sender.identity), message_bytes=len(message), phases=phases,
                timing_scope="cProfile diagnostic only; full public API and wire encoding/decoding",
                randomness="fresh system CSPRNG for every encryption; no outer retry",
                security_claim="none", backend_admitted=False, parameters_are_formal=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    if not 3 <= args.repetitions <= 31:
        parser.error("use 3..31 profile repetitions")
    result = profile(args.state_directory, args.repetitions)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({operation: values["top_cumulative"][:8]
                      for operation, values in result["phases"].items()}, indent=2))


if __name__ == "__main__":
    main()
