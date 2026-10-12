"""Small public-interface checks. Never generates keys, preimages, or ciphertext.

The n=2 oracle root and zero vectors below are explicit invalid/format fixtures.
They are not CHKP setup, independent sampling, an integration, or a smoke run.
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from preflight import DEFAULT_REPO, METHOD_ARGS, backend_problems

PACKAGE = Path("C:/Users/A/.dsh/deliverables/CHKP-step7-codex-rework")


def run(repo=DEFAULT_REPO, package=PACKAGE):
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(repo / "src"), str(repo)]
    from ibme.hibe.abb10 import ABB10HIBE
    from ibme.hibe.mock import MockHIBE
    from ibme.protocol.hybrid_hibe import HybridLimits, HybridHIBEParams, encoded_identity, SEED_BYTES
    from ibme.protocol.luo_hybrid import MAX_APPLICATION_BYTES, make_hybrid_abb10
    from experiments.research.first_suite.identity import ROHIBEContext, SEED_BITS
    from experiments.research.first_suite.leaf_state import SeedScope, SeedPlan, FixedSeedKey
    from experiments.research.first_suite.seed_kem import encapsulate_seed, decapsulate_seed
    limits = HybridLimits()
    receiver, sender = b"Bob", b"Alice"
    parent = encoded_identity(receiver, limits, b"P")
    child = encoded_identity(sender, limits, b"C")
    checks = []

    def record(name, ok, **details):
        checks.append({"name": name, "passed": bool(ok), **details})
        if not ok:
            raise AssertionError(name)

    record("ordered_identity_seed_contract", len(parent) == len(child) == 86 and SEED_BYTES == 32,
           parent_role="rcv", child_role="phi", raw_identity_lengths=[3, 5], inner_lengths=[86, 86, 32])
    record("role_separation", encoded_identity(b"same", limits, b"P") != encoded_identity(b"same", limits, b"C"))
    record("max_raw_identity_fixed_width", len(encoded_identity(b"x" * 64, limits, b"P")) == 86)
    from ibme.core.errors import EncodingError, InvalidParameterError
    try:
        encoded_identity(b"x" * 65, limits, b"P")
    except EncodingError:
        record("oversized_raw_identity_rejected", True)
    else:
        record("oversized_raw_identity_rejected", False)
    for id_len, payload_len in ((85, 32), (87, 32), (86, 31)):
        try:
            HybridHIBEParams(SimpleNamespace(identity_bytes=id_len, max_message_bytes=payload_len))
        except InvalidParameterError:
            record("invalid_inner_capacity_%d_%d" % (id_len, payload_len), True)
        else:
            record("invalid_inner_capacity_%d_%d" % (id_len, payload_len), False)
    params = SimpleNamespace(identity_bytes=86, max_message_bytes=32, security_claim="none", backend_admitted=False)
    HybridHIBEParams(params)
    record("none_does_not_block_functional_parameter_check", True)
    for backend in (ABB10HIBE(), MockHIBE()):
        reasons = backend_problems(backend, repo)
        record("reject_" + type(backend).__name__, "MOCK_OR_TEACHING_BACKEND" in reasons, blockers=reasons)
    current = make_hybrid_abb10()
    record("existing_hybrid_factory_is_teaching_abb10", type(current.inner_backend) is ABB10HIBE)
    record("application_capacity_not_seed_capacity", MAX_APPLICATION_BYTES == 3924, application_max_bytes=MAX_APPLICATION_BYTES)

    # Public H/G only; this root is a declared diagnostic fixture, not GenBasis.
    oracle = ROHIBEContext(2, 2, 65537, ((1, 0), (0, 1)), b"SIDECAR-PUBLIC-API-FIXTURE")
    plan = SeedPlan(SeedScope(oracle, parent, 4, b"NO-SAMPLING"), child)
    record("first_suite_has_same_leaf_256_addresses", SEED_BITS == 256 and len(plan.targets) == 256)
    record("positions_use_ordered_public_G", all(plan.targets[j] == oracle.g((parent, child), j) for j in range(256)),
           independence_proved=False, preimages_generated=0,
           note="256 distinct input positions; output collisions are allowed. This checks no sampling distribution.")
    try:
        FixedSeedKey(plan, ((0,) * 6,) * 32)
    except InvalidParameterError:
        record("first_suite_rejects_32_preimages", True)
    else:
        record("first_suite_rejects_32_preimages", False)
    record("seed_kem_is_functions_not_HIBE_backend", callable(encapsulate_seed) and callable(decapsulate_seed),
           encapsulate_signature=str(inspect.signature(encapsulate_seed)),
           decapsulate_signature=str(inspect.signature(decapsulate_seed)))

    # One direct boundary demonstration, not a replay of the historical package.
    sys.path.insert(0, str(package / "a_contract"))
    wire = importlib.import_module("wire_reference")
    profile = dict(s1_squared="1", s2_squared="4", alpha="1/1024", tau="unset",
                   K1=4, K2=4, epsilon_bits=32, use_lll=True, identity_bytes=86,
                   max_message_bytes=65536, cache_identity_entries=8, target_capacity=32)
    pk = wire.serialize_pk(wire.encode_context(2, 1, 65537, 2, profile, ((1,), (2,))))
    for count in (33, 256):
        try:
            wire.serialize_sk2(pk, parent, child, 0, ((0, 0, 0),) * count)
        except wire.SerializationError as exc:
            record("step7_cap32_rejects_%d" % count, str(exc) == "invalid leaf range", exception=str(exc))
        else:
            record("step7_cap32_rejects_%d" % count, False)
    return {"scope": "public-interface boundary checks; no CHKP/Luo composition executed",
            "checks": checks, "passed": len(checks), "preimages_generated": 0,
            "seed_encapsulations": 0, "smoke_executed": False,
            "security_claim": "none", "backend_admitted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--package", type=Path, default=PACKAGE)
    args = parser.parse_args()
    print(json.dumps(run(args.repo.resolve(), args.package.resolve()), indent=2))
