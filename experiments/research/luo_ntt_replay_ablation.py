"""Supplemental full-protocol common-randomness experiment, NOT production RNG.

Replay each fresh CSPRNG seed through TEST-ONLY deterministic streams in both
arms. This holds signature rejection work constant. A pair must yield identical
ciphertext and consume identical entropy. Pairs have distinct seeds/OTS keys.
Reuses the original three roots; does not add independent root observations.
Run this standalone against the pinned installed package, outside checkout.
"""
import argparse
import hashlib
import json
from pathlib import Path


def run(args):
    from ibme.assembly import SuiteConfig, build_runtime
    from ibme.core.randomness import DeterministicRandom, SecureRandom
    from ibme.protocol.baseline import PublicKey, SenderKey, ReceiverKey
    from experiments.research.backend_optimization_probe import assert_installed_providers, summarize_pairs, expected_suite
    from experiments.research.full_system_benchmark import source_providers
    from experiments.research.runtime_metrics import measured_phase, environment

    manifest = json.loads(args.manifest.read_bytes())
    root = args.installed_root.resolve()
    for relative, digest in manifest["files"].items():
        path = (root/relative).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("installed source differs from pinned manifest")

    class Counted:
        def __init__(self, seed, role):
            self.rng = DeterministicRandom(hashlib.sha256(b"TEST-ONLY-LUO-REPLAY:"+role+seed).digest())
            self.bytes = self.reads = 0

        def read(self, count):
            self.bytes += count
            self.reads += 1
            return self.rng.read(count)

    class NoEntropy:
        def read(self, count):
            raise AssertionError("cached receiver restoration unexpectedly requested entropy")

    records = []
    for index in range(3):
        directory = args.private_source/f"root-{index}"
        paths = [directory/name for name in ("public.bin", "sender.bin", "receiver-prepared.bin")]
        before = [hashlib.sha256(p.read_bytes()).digest() for p in paths]
        config = SuiteConfig.from_json((directory/"suite.json").read_bytes())
        if config.to_dict() != expected_suite("Luo").to_dict():
            raise ValueError("only the existing LATTE/Luo roots are allowed")
        loader = build_runtime(config)
        dec = loader.decoders
        public = PublicKey.from_bytes(paths[0].read_bytes(), dec["hpk"], dec["ipk"])
        sender = SenderKey.from_bytes(paths[1].read_bytes(), dec["sk"])
        receiver = ReceiverKey.from_bytes(paths[2].read_bytes(), dec["sk1"])
        phases = []
        for repetition in range(3):
            seed = SecureRandom().read(32)
            results, entropy = {}, {}
            modes = ("off", "on") if (index+repetition)%2 == 0 else ("on", "off")
            for mode in modes:
                sources = {role:Counted(seed, role.encode()) for role in ("ibs", "ots", "hibe")}
                runtime = build_runtime(config, ibs_rng=sources["ibs"], ots_rng=sources["ots"])
                runtime.ibs.configure_ntt_preparation(mode == "on")
                with measured_phase("encrypt", phases) as row:
                    row.update(mode=mode, pair=repetition)
                    wire = runtime.proto.encrypt(public, sender, receiver.identity, bytes(range(32)), rng=sources["hibe"]).to_bytes()
                with measured_phase("decrypt", phases) as row:
                    row.update(mode=mode, pair=repetition)
                    recovered = runtime.proto.decrypt(public, receiver, sender.identity, wire, rng=NoEntropy())
                    if recovered != bytes(range(32)):
                        raise AssertionError("honest replay decrypt failed")
                results[mode] = wire
                entropy[mode] = {role:dict(bytes=source.bytes, reads=source.reads) for role,source in sources.items()}
            if results["off"] != results["on"] or entropy["off"] != entropy["on"]:
                raise AssertionError("prepared NTT changed outputs or random consumption")
            phases[-1]["pair_ciphertext_and_entropy_equal"] = True
            phases[-1]["pair_entropy"] = entropy["on"]
        if before != [hashlib.sha256(p.read_bytes()).digest() for p in paths]:
            raise AssertionError("original private state changed")
        records.append(dict(root=index, status="passed", phases=phases, input_files_unchanged=True))
        print(json.dumps(dict(root=index, status="passed")), flush=True)
    providers = source_providers()
    assert_installed_providers(providers, root)
    report = dict(schema="IBME-LUO-COMMON-RANDOMNESS/1", status="passed", records=records,
        source_commit=manifest["source_commit"], wheel_sha256=manifest["wheel_sha256"], providers=providers,
        driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), environment=environment(),
        suite=config.to_dict(), summary=summarize_pairs(records), reused_independent_roots=3, new_roots=0,
        pairs_per_root=3, identity_bytes=64, message_bytes=32,
        randomness="fresh CSPRNG seed per pair; TEST-ONLY domain streams replayed across arms; not production independent signatures",
        timing_scope="full Suite, wire, Hybrid, BYTEAUTH and IBS; identical rejection work; installed source fixed",
        **{name:config.to_dict()[name] for name in ("security_claim", "backend_admitted", "parameters_are_formal")})
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-source", type=Path, required=True)
    parser.add_argument("--installed-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
