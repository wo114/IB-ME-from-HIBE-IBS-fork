"""Reproducible functional audit, persistence replay and toy forgery control."""

from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from itertools import combinations, product
import json
from math import comb
from pathlib import Path
import platform
import sys

from experiments.research.luo_matrix_reference import (
    MatrixParams, MasterState, PublicKey, Signature, SigningKey,
    hash_h1, hash_h2, key_extract, setup, sign, sign_for_identity, verify,
)
from ibme.core.randomness import DeterministicRandom
from ibme.lattice.modmat import ModMatrix, ModVector


def wide_challenge_params():
    """Additional hand-selected functional profile, still very small SIS dimension."""
    return MatrixParams(k=32, kappa=8, q=2**31 - 1, gamma1=4096, gamma2=131072)


def forge_tiny_challenge(public: PublicKey, identity: bytes, *, message_attempts=16):
    """Public-only fixed-point search when the complete challenge space is tiny.

    No signing key, key-generation oracle or signature oracle is used. This is
    a negative control on hand-selected toy parameters, not on secure parameters.
    """
    p = public.params
    space = comb(p.k, p.kappa) * 2**p.kappa
    if space > 4096 or not 1 <= message_attempts <= 64:
        raise ValueError("public enumeration is restricted to tiny challenges")
    W = ModMatrix.zeros(p.n, p.k, p.q)
    user_public = public.T @ ModMatrix(hash_h1(public, identity, W), p.q)
    queries = 0
    for attempt in range(message_attempts):
        message = b"public-forgery:" + str(attempt).encode("ascii")
        for positions in combinations(range(p.k), p.kappa):
            for signs in product((-1, 1), repeat=p.kappa):
                c = [0] * p.k
                for position, value in zip(positions, signs):
                    c[position] = value
                commitment = -(user_public @ ModVector(c, p.q))
                queries += 1
                if tuple(c) == hash_h2(public, identity, commitment, message):
                    sig = Signature(public.context, (0,) * p.m, tuple(c), W)
                    if not verify(public, identity, message, sig):
                        raise RuntimeError("public equation and verifier disagree")
                    return message, sig, queries
    raise RuntimeError("no fixed point in this finite negative-control budget")


def audit() -> dict:
    cases, signatures, negative_rejections, persistence = [], 0, 0, 0
    messages = [b"", b"\x00", b"same", b"same", bytes(range(16)), b"x" * 32,
                "测试".encode("utf-8"), b"final"]
    for profile, params, setup_count, identities, selected_messages in (
        ("r1-tiny", MatrixParams(), 3, [b"Alice", b"Bob"], messages[:4]),
        ("wide-functional", wide_challenge_params(), 2,
         [b"Alice", b"Bob", "发送方".encode("utf-8")], messages),
    ):
        for index in range(setup_count):
            seed = f"luo-m1:{profile}:{index}".encode("ascii")
            random = DeterministicRandom(seed)
            public, master = setup(params, rng=random)
            public_encoded = public.to_bytes()
            if PublicKey.from_bytes(public_encoded).to_bytes() != public_encoded:
                raise RuntimeError("public serialization roundtrip failed")
            sig_sizes = Counter()
            key_sizes = []
            transcript = sha256()
            for identity in identities:
                key = key_extract(master, identity, rng=random)
                key_before = key.to_bytes()
                if SigningKey.from_bytes(key_before).to_bytes() != key_before:
                    raise RuntimeError("private user key roundtrip failed")
                key_sizes.append(len(key_before))
                for message in selected_messages:
                    sig = sign_for_identity(master, identity, message, rng=random)
                    encoded = sig.to_bytes()
                    loaded = Signature.from_bytes(public, encoded)
                    if not verify(PublicKey.from_bytes(public_encoded), identity, message, loaded):
                        raise RuntimeError("honest signature did not verify")
                    if key_extract(master, identity).to_bytes() != key_before:
                        raise RuntimeError("identity key changed after signing")
                    signatures += 1
                    sig_sizes[len(encoded)] += 1
                    transcript.update(encoded)
                    if profile == "wide-functional":
                        changed_message = (bytes([message[0] ^ 1]) + message[1:]) if message else b"\x01"
                        checks = (verify(public, b"WrongSender", message, loaded),
                                  verify(public, identity, changed_message, loaded))
                        if any(checks):
                            raise RuntimeError("selected identity/message mutation unexpectedly verified")
                        negative_rejections += len(checks)
            encoded_master = master.to_bytes()
            restored = MasterState.from_bytes(encoded_master)
            if restored.to_bytes() != encoded_master:
                raise RuntimeError("master cache serialization changed")
            for identity in identities:
                if key_extract(restored, identity).to_bytes() != key_extract(master, identity).to_bytes():
                    raise RuntimeError("cached identity not preserved across restore")
                persistence += 1
            cases.append(dict(profile=profile, setup_index=index,
                              public_key_bytes=len(public_encoded),
                              user_private_key_bytes=key_sizes,
                              master_snapshot_bytes=len(encoded_master),
                              signature_size_counts=dict(sig_sizes),
                              public_context_hex=public.context.hex(),
                              public_transcript_sha256=transcript.hexdigest(),
                              identity_lengths=[len(x) for x in identities],
                              message_lengths=[len(x) for x in selected_messages]))
    public, master = setup(rng=DeterministicRandom(b"luo-m1:public-attack-control"))
    identity = b"Unissued"
    message, forged, queries = forge_tiny_challenge(public, identity)
    if master.cached_identities:
        raise RuntimeError("public-only attack unexpectedly issued a user key")
    return dict(
        security_claim="none", backend_admitted=False,
        algorithm_instances=1, parameter_profiles=2, complete_ibme_instances=0,
        python=sys.version, platform=platform.platform(),
        entropy="Explicit deterministic streams for reproducibility only",
        hash_instantiation="Domain-separated SHAKE-256; no ROM/QROM implementation proof",
        source="Luo et al., ICICS 2024, Section 3 Algorithms 1-4; R1 cached-oracle interpretation",
        total_setups=6, functional_setups=5, negative_control_setups=1,
        honest_signatures_verified=signatures,
        selected_wide_profile_mutations_rejected=negative_rejections,
        restored_identity_keys_checked=persistence,
        cases=cases,
        educational_public_forgery=dict(
            challenge_space=24, private_key_access=False, key_extraction_queries=0,
            signing_queries=0, attack_h1_matrix_queries=1,
            attack_h2_queries=queries, verified=True,
            identity_hex=identity.hex(), message_hex=message.hex(),
            public_key_hex=public.to_bytes().hex(), signature_hex=forged.to_bytes().hex()),
        notes=["No HIBE or production backend changed.",
               "Persistence snapshots contain private material; this artifact includes only lengths/digests.",
               "Toy public forgery is expected: neither functional profile establishes SIS hardness.",
               "No algorithm performance claim and no security theorem are inferred from these tests."],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit()
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({k: result[k] for k in ("honest_signatures_verified",
                         "restored_identity_keys_checked", "security_claim")}, ensure_ascii=False))
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
