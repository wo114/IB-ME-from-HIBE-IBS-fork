"""Read-only, pinned target-checkout smoke for explicit C64B shared assembly.

Emit non-secret JSON only. Not a framework audit, CLI test or CHKP experiment.
Run in a fresh Python process; private state stays in memory.
"""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

STAGE = "source-pin"


class GateFailure(Exception):
    """Fixed public diagnostic code, never secret object content."""


def require(value, code):
    if not value:
        raise GateFailure(code)


def main():
    global STAGE
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target-root", type=Path, required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--profile-json", type=Path, required=True)
    args = ap.parse_args()
    root = args.target_root.resolve(strict=True)
    def git(*argv):
        return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), *argv])
    require(git("rev-parse", "HEAD").decode().strip() == args.head, "head_mismatch")
    # The peer is independently merging CLI state; this API smoke does not
    # import those files. Pin every other committed source, not a dirty CLI.
    excluded = {"src/ibme/cli.py", "src/ibme/cli_state.py"}
    selected = [x for x in git("ls-tree", "-r", "--name-only", args.head, "src").decode().splitlines()
                if x not in excluded]
    require(not git("diff", "HEAD", "--", *selected), "dirty_target_src")
    sys.dont_write_bytecode = True
    require(not any(x == "ibme" or x.startswith("ibme.") for x in sys.modules), "preloaded_ibme")
    sys.path.insert(0, str(root / "src"))
    raw_profile = args.profile_json.read_bytes()
    fields = json.loads(raw_profile)["params"]
    from ibme.assembly import make_suite, validate_suite, build_runtime, SuiteConfig
    from ibme.core.errors import InvalidParameterError, SerializationError
    from ibme.core.randomness import DeterministicRandom
    from ibme.ibs.luo_module import LuoModuleParams
    from ibme.protocol.baseline import PublicKey, MasterSecret, SenderKey, ReceiverKey, BOTTOM, BaselineIBME, parse_payload

    p = LuoModuleParams(**fields)
    STAGE = "preflight"
    checks = []
    def check(name, condition):
        require(condition, name)
        checks.append(name)
    def rejects(name, fn, exception):
        try:
            fn()
        except exception:
            checks.append(name)
        else:
            raise GateFailure(name)
    class NoEntropy:
        def read(self, count):
            raise RuntimeError("unexpected_entropy")
    def rng(label):
        return DeterministicRandom(b"public-test/step23/assembly/" + label)

    started = time.monotonic()
    capacities = {}
    for fmt, size in (("reference", 29455), ("compact", 16383)):
        config = make_suite(hibe="abb10", ibs="luo-module", ibs_params=p,
                            transport="hybrid", signature_format=fmt)
        report = validate_suite(config)
        check(fmt+"_preflight", report.ok)
        check(fmt+"_signature_capacity", report.capacity["signature_max_bytes"] == size)
        check(fmt+"_application_capacity", report.capacity["max_application_bytes"] == 3924)
        check(fmt+"_inner_contract", report.capacity["inner_hibe_identity_bytes"] == 86 and
              report.capacity["inner_hibe_payload_bytes"] == 32)
        check(fmt+"_canonical_config", SuiteConfig.from_json(config.to_json()) == config)
        build_runtime(config, ibs_rng=NoEntropy(), ots_rng=NoEntropy())
        checks.append(fmt+"_build_without_entropy")
        capacities[fmt] = report.capacity
    # Use the genuinely implemented assembly; no shim or copied peer source.
    runtime = build_runtime(config, ibs_rng=rng(b"ibs"), ots_rng=rng(b"ots"))
    proto = runtime.proto
    rejects("wrong_setup_snapshot", lambda: proto.setup(runtime.hibe_params,
        ibs_params=LuoModuleParams(), rng=NoEntropy()), InvalidParameterError)
    STAGE = "setup-keygen"
    public, master = proto.setup(runtime.hibe_params, ibs_params=runtime.ibs_params, rng=rng(b"setup"))
    sender = proto.skgen(master, b"Alice")
    receiver = proto.rkgen(master, b"Bob", rng=rng(b"receiver"))
    message = b"M" * 3924
    STAGE = "encrypt-decrypt"
    ct = proto.encrypt(public, sender, b"Bob", message, rng=rng(b"encrypt"))
    check("max_message_roundtrip", proto.decrypt(public, receiver, b"Alice", ct, rng=rng(b"decrypt")) == message)
    readers = runtime.decoders
    STAGE = "restore"
    rp = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
    rm = MasterSecret.from_bytes(master.to_bytes(), readers["hmsk"], readers["imsk"])
    rs = SenderKey.from_bytes(sender.to_bytes(), readers["sk"])
    rr = ReceiverKey.from_bytes(receiver.to_bytes(), readers["sk1"])
    runtime.validate_master(rp, rm)
    runtime.validate_sender(rp, rs)
    runtime.validate_receiver(rp, rr)
    check("canonical_all_state", all(a.to_bytes() == b.to_bytes() for a,b in
          ((rp,public),(rm,master),(rs,sender),(rr,receiver))))
    no_entropy = build_runtime(config, ibs_rng=NoEntropy(), ots_rng=NoEntropy())
    check("restored_fixed_key_cache", no_entropy.proto.skgen(rm,b"Alice").to_bytes() == rs.to_bytes())
    check("restored_decrypt", no_entropy.proto.decrypt(rp,rr,b"Alice",ct,rng=rng(b"restore-dec")) == message)
    rejects("oversize_before_entropy", lambda: no_entropy.proto.encrypt(rp,rs,b"Bob",b"x"*3925,
            rng=NoEntropy()), InvalidParameterError)
    wrong = proto.rkgen(master,b"Other",rng=rng(b"other"))
    STAGE = "negative-cases"
    for label, key, identity in (("wrong_sender",receiver,b"Other"),
                                 ("wrong_receiver",wrong,b"Alice"), ("both_wrong",wrong,b"Other")):
        check(label, proto.decrypt(public,key,identity,ct,rng=rng(label.encode())) is BOTTOM)
    damaged = replace(ct,signature=bytes([ct.signature[0]^1])+ct.signature[1:])
    check("byteauth_mutation", no_entropy.proto.decrypt(rp,rr,b"Alice",damaged,rng=NoEntropy()) is BOTTOM)
    old = build_runtime(make_suite(hibe="abb10",ibs="luo-module",transport="hybrid"),
                        ibs_rng=NoEntropy(),ots_rng=NoEntropy())
    rejects("default_decoder_rejects_C64B", lambda: old.decoders["ipk"].from_bytes(public.ipk.to_bytes()), SerializationError)
    baseline = BaselineIBME(runtime.hibe,runtime.ibs)
    STAGE = "measure-payload"
    inner = baseline.load_ciphertext(ct.inner_bytes)
    child = runtime.hibe.derive(receiver.level1_key,b"Alice",rng=rng(b"measure"))
    payload = runtime.hibe.decrypt(child,inner.hibe_ct,rng=rng(b"measure-dec"))
    signature, envelope = parse_payload(payload)
    check("actual_compact_signature_size", len(signature) == 16383)
    check("actual_teaching_outer_payload", len(payload) == 20415)
    modules = {}
    STAGE = "final-source-pin"
    for name, module in sorted(sys.modules.items()):
        if name == "ibme" or name.startswith("ibme."):
            path = Path(module.__file__).resolve(strict=True)
            require(path.is_relative_to(root / "src"), "wrong_import_root")
            relative = path.relative_to(root).as_posix()
            require(relative in selected, "unexpected_or_cli_import")
            # Loaded source must still equal the pinned committed version.
            committed = git("show", args.head+":"+relative)
            require(path.read_bytes().replace(b"\r\n", b"\n") == committed.replace(b"\r\n", b"\n"), "loaded_source_changed")
            modules[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    require(git("rev-parse", "HEAD").decode().strip() == args.head, "head_drift")
    require(not git("diff", "HEAD", "--", *selected), "target_changed")
    print(json.dumps(dict(status="functional_teaching_assembly_pass",target_head=args.head,
        profile_sha256=hashlib.sha256(raw_profile).hexdigest(),checks=checks,capacity=capacities,
        signature_bytes=len(signature),outer_payload_bytes=len(payload),application_bytes=len(message),
        private_artifacts_saved=False,source_sha256=modules,elapsed_seconds=time.monotonic()-started,
        python=sys.version,security_claim="none",backend_admitted=False,parameters_are_formal=False,
        scope="C64B compact teaching ABB10 Hybrid and BYTEAUTH; reference preflight only; no CLI/CHKP"), indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Do not print traceback/locals that might contain opaque test keys.
        print(json.dumps(dict(status="failed_closed", error_type=type(exc).__name__,
            stage=STAGE, code=exc.args[0] if type(exc) is GateFailure else "details_suppressed")))
        raise SystemExit(2)
