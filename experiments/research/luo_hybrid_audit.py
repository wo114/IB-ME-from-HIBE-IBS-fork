"""Real hybrid/lattice IBME audit with a public-only Sage linear subpath probe.

Only public transcripts, digests, counts and sizes leave memory. No private
key, random seed, mask or DEM key is written to the result.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys

import cryptography
from cryptography.hazmat.backends import default_backend

from ibme.core.encoding import encode_bytes, encode_message
from ibme.core.lamport_ots import generate_lamport_key
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import LuoModuleSignature, challenge, identity_challenge
from ibme.protocol.baseline import BaselineIBME, BOTTOM, Ciphertext, encode_signature, parse_payload
from ibme.protocol.byteauth import authenticate_inner, encode_bound_message
from ibme.protocol.luo_hybrid import (make_research_runtime, RESEARCH_HIBE_PARAMS,
                                     RESEARCH_IBS_PARAMS, MAX_APPLICATION_BYTES)


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def random(label): return DeterministicRandom(b"luo-hybrid-audit:" + label)


def processor_model():
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unavailable"


def linear_zero_commitment_probe(public):
    """An exact public Az=t*c_id*c target, not rounded Verify or general MSIS."""
    from sage.all import GF, matrix, vector
    p, field = public.params, GF(public.params.q)
    zeros = ((0,) * p.degree,) * p.k
    cid = identity_challenge(public, zeros, b"Unissued")
    c = challenge(p, b"IBME:HYBRID:AUDIT:LINEAR:v1", b"fixed public target")
    rows = []
    for root_index in (0, 1, 127, 255):
        point = field(pow(p.root, 2 * root_index + 1, p.q))
        powers = [point**i for i in range(p.degree)]
        evaluate = lambda poly: sum((field(value) * power for value, power in zip(poly, powers)), field(0))
        a = matrix(field, [[evaluate(poly) for poly in row] for row in public.A])
        scale = evaluate(cid) * evaluate(c)
        require(scale != 0, "selected linear-probe challenge vanishes at evaluation")
        target = vector(field, [evaluate(poly) * scale for poly in public.t])
        rank, augmented = int(a.rank()), int(a.augment(matrix(field, p.k, 1, list(target))).rank())
        require(rank == p.l and augmented > rank, "selected exact linear target unexpectedly solvable")
        try:
            a.solve_right(target)
        except ValueError:
            no_solution = True
        else:
            no_solution = False
        require(no_solution, "Sage exact public solve disagrees with rank obstruction")
        rows.append(dict(root_index=root_index, matrix_rank=rank, augmented_rank=augmented,
                         nonzero_challenge_scale=True, exact_solution_exists=False))
    return dict(private_key_access=False, extract_queries=0, sign_queries=0, rows=rows,
                scope="Fixed h=0 exact v=0 linear subpath only. Rounded low-bit targets, other w1/h, lattice attacks and adaptive forgeries are not excluded.")


def public_forgery_probe(protocol, public, receiver):
    attacker = generate_lamport_key(rng=random(b"public-forgery-ots"))
    envelope = encode_bound_message(attacker.public_key.commitment(), b"unissued public forgery")
    signed, p = encode_message(b"Bob", envelope), public.ipk.params
    zeros_l, zeros_k = ((0,) * p.degree,) * p.l, ((0,) * p.degree,) * p.k
    first = None
    for index in range(64):
        c = challenge(p, b"IBME:HYBRID:AUDIT:GUESS:v1", index.to_bytes(2, "big"))
        sig = LuoModuleSignature(p, public.ipk.context, zeros_l, c, zeros_k, zeros_k)
        loaded = protocol.ibs_backend.load_signature(public.ipk, sig.to_bytes())
        require(loaded.to_bytes() == sig.to_bytes(), "public candidate is not canonical new format")
        require(not protocol.ibs_backend.verify(public.ipk, b"Unissued", signed, loaded), "finite public signature guess accepted")
        if first is None:
            first = loaded
    inner = Ciphertext(protocol.hibe_backend.encrypt(public.hpk, b"Bob", b"Unissued",
            encode_signature(first) + encode_bytes(envelope), rng=random(b"public-forgery-enc")))
    forged = authenticate_inner(public, inner.to_bytes(), attacker)
    require(forged.ots_key.verify(forged.signed_body(), forged.signature), "forgery positive OTS control failed")
    require(protocol.decrypt(public, receiver, b"Unissued", forged, rng=random(b"public-forgery-dec")) is BOTTOM,
            "unissued sender ciphertext accepted")
    return dict(candidate_signatures=64, canonical_new_signature_type=True, accepted=0,
                valid_outer_ots=True, full_unissued_sender_ciphertext_rejected=True,
                sender_key_issued=False, notes="Finite public guessing and one complete attack ciphertext, not a security proof.")


def recipient_reencrypt_probe(protocol, public, receiver, cipher):
    hibe = protocol.hibe_backend
    baseline = BaselineIBME(hibe, protocol.ibs_backend)
    inner = baseline.load_ciphertext(cipher.inner_bytes)
    child = hibe.derive(receiver.level1_key, b"Alice", rng=random(b"recipient-child"))
    payload = hibe.decrypt(child, inner.hibe_ct, rng=random(b"recipient-payload"))
    require(isinstance(payload, bytes), "recipient honest payload prerequisite")
    sig_raw, envelope = parse_payload(payload)
    reencrypted = Ciphertext(hibe.encrypt(public.hpk, b"Bob", b"Alice", payload, rng=random(b"recipient-reencrypt")))
    require(baseline.decrypt(public, receiver, b"Alice", reencrypted, rng=random(b"recipient-baseline")) == envelope,
            "recipient re-encryption baseline control")
    attacker = generate_lamport_key(rng=random(b"recipient-new-ots"))
    resigned = authenticate_inner(public, reencrypted.to_bytes(), attacker)
    require(resigned.ots_key.verify(resigned.signed_body(), resigned.signature), "recipient new OTS control")
    require(protocol.decrypt(public, receiver, b"Alice", resigned, rng=random(b"recipient-reject")) is BOTTOM,
            "recipient new-vk re-encryption accepted")
    second_attacker = generate_lamport_key(rng=random(b"recipient-rebind-ots"))
    changed_envelope = encode_bound_message(second_attacker.public_key.commitment(), b"recipient-forged-content")
    signature = protocol.ibs_backend.load_signature(public.ipk, sig_raw)
    require(not protocol.ibs_backend.verify(public.ipk, b"Alice", encode_message(b"Bob", changed_envelope), signature),
            "recipient changed payload accepted by IBS")
    changed_inner = Ciphertext(hibe.encrypt(public.hpk, b"Bob", b"Alice",
               encode_signature(signature) + encode_bytes(changed_envelope), rng=random(b"recipient-rebind-enc")))
    rebound = authenticate_inner(public, changed_inner.to_bytes(), second_attacker)
    require(rebound.ots_key.verify(rebound.signed_body(), rebound.signature), "recipient rebound OTS control")
    require(protocol.decrypt(public, receiver, b"Alice", rebound, rng=random(b"recipient-rebind-dec")) is BOTTOM,
            "recipient changed message accepted by protocol")
    return dict(recipient_private_key=True, sender_private_key=False, legitimate_payload_reencrypted=True,
                baseline_control_accepts_same_envelope=True, valid_new_ots=True,
                new_vk_branch_rejected=True, changed_envelope_rejected=True, signature_bytes=len(sig_raw))


def low_bit_probe(protocol, public, receiver, cipher):
    hibe = protocol.hibe_backend
    baseline = BaselineIBME(hibe, protocol.ibs_backend)
    hybrid_ct = baseline.load_ciphertext(cipher.inner_bytes).hibe_ct
    changed_bytes = hybrid_ct.capsule[:-1] + bytes([hybrid_ct.capsule[-1] ^ 1])
    original = hibe.inner_backend.load_ciphertext(hybrid_ct.capsule)
    changed = hibe.inner_backend.load_ciphertext(changed_bytes)
    require(original.c1[-1] ^ changed.c1[-1] == 1, "mutation is not c1 low-bit")
    child = hibe.derive(receiver.level1_key, b"Alice", rng=random(b"low-bit-child"))
    seed = hibe.inner_backend.decrypt(child.inner, original, rng=random(b"low-bit-seed"))
    require(isinstance(seed, bytes) and len(seed) == 32, "honest short-seed prerequisite")
    require(hibe.inner_backend.decrypt(child.inner, changed, rng=random(b"low-bit-seed")) == seed,
            "raw HIBE tolerance negative control")
    altered_hybrid = replace(hybrid_ct, capsule=changed_bytes)
    require(hibe.decrypt(child, altered_hybrid, rng=random(b"low-bit-seed")) is None,
            "same-key altered capsule accepted by GCM")
    outer = replace(cipher, inner_bytes=Ciphertext(altered_hybrid).to_bytes())
    require(protocol.decrypt(public, receiver, b"Alice", outer) is BOTTOM, "altered complete ciphertext accepted")
    return dict(c1_xor=1, raw_hibe_restores_same_seed=True, hybrid_aad_rejects=True, byteauth_rejects=True)


def audit():
    from sage.env import SAGE_VERSION
    protocol, readers = make_research_runtime(ibs_rng=random(b"ibs"), ots_rng=random(b"ots"))
    public, master = protocol.setup(RESEARCH_HIBE_PARAMS, ibs_params=RESEARCH_IBS_PARAMS, rng=random(b"setup"))
    sender = protocol.skgen(master, b"Alice")
    receiver = protocol.rkgen(master, b"Bob", rng=random(b"rk"))
    baseline = BaselineIBME(protocol.hibe_backend, protocol.ibs_backend)
    rows, honest, wrong = [], 0, 0
    first = None
    messages = (b"", bytes(range(32)), b"x" * MAX_APPLICATION_BYTES)
    for index, message in enumerate(messages):
        cipher = protocol.encrypt(public, sender, b"Bob", message, rng=random(f"enc:{index}".encode()))
        require(protocol.decrypt(public, receiver, b"Alice", cipher.to_bytes(), rng=random(f"dec:{index}".encode())) == message,
                "full real protocol honest roundtrip")
        require(cipher.ots_key.verify(cipher.signed_body(), cipher.signature), "honest outer OTS")
        hybrid_ct = baseline.load_ciphertext(cipher.inner_bytes).hibe_ct
        rows.append(dict(message_bytes=len(message), complete_ciphertext_bytes=len(cipher.to_bytes()),
                         baseline_bytes=len(cipher.inner_bytes), hybrid_bytes=len(hybrid_ct.to_bytes()),
                         capsule_bytes=len(hybrid_ct.capsule), dem_bytes=len(hybrid_ct.body),
                         public_ciphertext_sha256=sha256(cipher.to_bytes()).hexdigest()))
        honest += 1
        if first is None:
            first = cipher
    other_receiver = protocol.rkgen(master, b"Carol", rng=random(b"other-rk"))
    for rk, identity in ((receiver, b"Carol"), (other_receiver, b"Alice"), (other_receiver, b"Carol")):
        require(protocol.decrypt(public, rk, identity, first, rng=random(b"mismatch")) is BOTTOM, "identity mismatch accepted")
        wrong += 1
    # Private bytes exist only in memory while checking persistence.
    from ibme.protocol.baseline import MasterSecret
    saved = master.to_bytes()
    restored = MasterSecret.from_bytes(saved, readers["hmsk"], readers["imsk"])
    require(restored.to_bytes() == saved and protocol.skgen(restored, b"Alice").to_bytes() == sender.to_bytes(), "cache restore")
    from ibme.protocol.baseline import ReceiverKey, PublicKey
    loaded_receiver = ReceiverKey.from_bytes(receiver.to_bytes(), readers["sk1"])
    loaded_public = PublicKey.from_bytes(public.to_bytes(), readers["hpk"], readers["ipk"])
    require(protocol.decrypt(loaded_public, loaded_receiver, b"Alice", first, rng=random(b"restored-decode")) == b"", "restored keys decrypt")
    linear = linear_zero_commitment_probe(public.ipk)
    require(b"Unissued" not in master.imsk.cached_identities, "target sender was issued before attack")
    public_attack = public_forgery_probe(protocol, public, receiver)
    require(b"Unissued" not in master.imsk.cached_identities, "target sender was issued during attack")
    recipient = recipient_reencrypt_probe(protocol, public, receiver, first)
    tamper = low_bit_probe(protocol, public, receiver, first)
    root = Path(__file__).resolve().parents[2]
    files = ("src/ibme/protocol/hybrid_hibe.py", "src/ibme/protocol/luo_hybrid.py", "src/ibme/cli.py",
             "src/ibme/protocol/byteauth.py", "src/ibme/core/lamport_ots.py", "src/ibme/ibs/luo_module.py",
             "experiments/research/luo_hybrid_audit.py")
    return dict(security_claim="none", backend_admitted=False,
                real_component_functional_combination=True, admitted_secure_combinations=0,
                python=sys.version, sage=SAGE_VERSION, cryptography=cryptography.__version__,
                openssl=default_backend().openssl_version_text(), platform=platform.platform(),
                processor=processor_model(), entropy="Deterministic test streams only",
                rom="No new ROM/QROM or CCA proof; inherited assumptions require admission",
                hybrid_limits=asdict(RESEARCH_HIBE_PARAMS.limits) | {"backend_id": RESEARCH_HIBE_PARAMS.limits.backend_id.decode("ascii")},
                inner_hibe_params=asdict(RESEARCH_HIBE_PARAMS.inner_params), ibs_params=asdict(RESEARCH_IBS_PARAMS),
                max_application_bytes=MAX_APPLICATION_BYTES, sender_bytes=5, receiver_bytes=3,
                repeats=1, setups=1, honest_roundtrips=honest, restored_roundtrips=1, mismatches_rejected=wrong,
                public_key_bytes=len(public.to_bytes()), sender_key_bytes=len(sender.to_bytes()),
                receiver_key_bytes=len(receiver.to_bytes()), master_snapshot_bytes=len(saved),
                signature_bytes=recipient["signature_bytes"], ciphertext_rows=rows,
                linear_public_subpath=linear, public_forgery=public_attack,
                recipient_resigning=recipient, original_c1_tamper=tamper,
                source_sha256={name: sha256((root / name).read_bytes()).hexdigest() for name in files},
                notes=["A real functional combination is not an admitted secure instance; inner HIBE is educational.",
                       "No private snapshots, seed, DEM key or signing mask is exported.",
                       "Ciphertext sizes are measurements; no comparison of end-to-end speed or A+B<C.",
                       "Signature guesses and exact linear rank obstruction do not exclude all adaptive/lattice attacks.",
                       "The existing education profile still reproduces the two old authentication vulnerabilities."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit()
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({name: result[name] for name in ("honest_roundtrips", "mismatches_rejected", "security_claim")}))
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
