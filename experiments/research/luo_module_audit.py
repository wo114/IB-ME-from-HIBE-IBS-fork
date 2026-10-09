"""Independent Sage polynomial/rounding audit of Luo MODULE-REF/1.

Run in the designated WSL Sage environment. Private state stays in memory;
the result exports public transcripts, counts and dimensions only.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import asdict
from hashlib import sha256, shake_256
from itertools import product
import json
from math import comb
from pathlib import Path
import platform
import sys

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module import (
    DOMAIN_H1, DOMAIN_H2, DOMAIN_PUBLIC, HASH_BYTES, LuoModuleIBSBackend,
    LuoModuleMasterSecret, LuoModuleParams, LuoModulePublicKey,
    LuoModuleSignature, LuoModuleSigningKey, challenge,
)
from ibme.ibs.luo_module_math import NegacyclicRing, Rounding, sparse_product


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def balanced(value, modulus):
    # Even moduli: the paper's (-modulus/2, modulus/2] convention.
    return (value + modulus // 2 - 1) % modulus - modulus // 2 + 1


def power_round(value, p):
    r = value % p.q
    return (r - balanced(r, 2**p.dropped_bits)) // 2**p.dropped_bits


def decompose(value, q, alpha):
    r = value % q
    low = balanced(r, alpha)
    return (0, low - 1) if r - low == q - 1 else ((r - low) // alpha, low)


def use_hint(hint, value, q, alpha):
    high, low = decompose(value, q, alpha)
    return high if not hint else (high + (1 if low > 0 else -1)) % ((q - 1) // alpha)


def lp(value): return len(value).to_bytes(4, "big") + value


def pack(vector): return b"".join(x.to_bytes(8, "big") for poly in vector for x in poly)


def independent_challenge(p, domain, encoded):
    # Independent hashlib input/framing/sampler implementation, without calling
    # the production hash functions or uniform sampler.
    raw, offset = shake_256(lp(domain) + encoded).digest(HASH_BYTES), 0

    def draw(bound):
        nonlocal offset
        width = max(1, ((bound - 1).bit_length() + 7) // 8)
        ceiling = 2**(8 * width)
        for _ in range(p.max_uniform_attempts):
            require(offset + width <= len(raw), "independent challenge byte budget")
            value = int.from_bytes(raw[offset:offset + width], "big")
            offset += width
            if value < ceiling - ceiling % bound:
                return value % bound
        raise RuntimeError("independent challenge sampling budget")

    positions, result = list(range(p.degree)), [0] * p.degree
    for index in range(p.kappa):
        selected = index + draw(p.degree - index)
        positions[index], positions[selected] = positions[selected], positions[index]
        result[positions[index]] = 1 if draw(2) else -1
    return tuple(result)


def cid(public, high, identity):
    return independent_challenge(public.params, DOMAIN_H1, lp(public.context) + lp(pack(high)) + lp(identity))


def cmsg(public, high, identity, message):
    return independent_challenge(public.params, DOMAIN_H2,
                                 lp(public.context) + lp(identity) + lp(pack(high)) + lp(message))


def vector_map(vector, function): return tuple(tuple(function(x) for x in poly) for poly in vector)


def plus(a, b, q=None):
    return tuple(tuple(x + y if q is None else (x + y) % q for x, y in zip(u, v)) for u, v in zip(a, b))


def negative(a): return tuple(tuple(-x for x in poly) for poly in a)


def norm(a): return max(abs(x) for poly in a for x in poly)


class SagePolynomialOracle:
    """Sage quotient rings provide the independent arithmetic oracle."""

    def __init__(self, degree, q):
        from sage.all import PolynomialRing, ZZ, Zmod
        self.degree = degree
        integer_poly = PolynomialRing(ZZ, "x")
        mod_poly = PolynomialRing(Zmod(q), "x")
        self.integer = integer_poly.quotient(integer_poly.gen()**degree + 1, "a")
        self.modular = mod_poly.quotient(mod_poly.gen()**degree + 1, "b")

    def coefficients(self, element):
        lifted = element.lift()
        return tuple(int(lifted[i]) for i in range(self.degree))

    def multiply(self, a, b, *, integer=False):
        ring = self.integer if integer else self.modular
        return self.coefficients(ring(list(a)) * ring(list(b)))

    def matvec(self, matrix, vector):
        ring = self.modular
        columns = [ring(list(poly)) for poly in vector]
        return tuple(self.coefficients(sum((ring(list(poly)) * x for poly, x in zip(row, columns)), ring(0))) for row in matrix)

    def sparse_vector(self, vector, c, *, integer=False):
        return tuple(self.multiply(poly, c, integer=integer) for poly in vector)


def mathematical_checks():
    from sage.all import GF, is_prime
    p = LuoModuleParams()
    require(bool(is_prime(p.q)), "selected q is not prime")
    require(int(GF(p.q)(p.root).multiplicative_order()) == 2 * p.degree, "selected root order")
    require((p.q - 1) % (2 * p.gamma3) == 0 and p.q > 4 * p.gamma3, "rounding divisibility/range")
    products = 0
    # Independent exact quotient multiplication on every ternary degree-2 pair.
    oracle, ring = SagePolynomialOracle(2, 17), NegacyclicRing(2, 17, 4)
    for a, b in product(product((-1, 0, 1), repeat=2), repeat=2):
        require(ring.multiply(a, b) == oracle.multiply(a, b), "tiny Sage/NTT product")
        require(sparse_product(a, b) == oracle.multiply(a, b, integer=True), "tiny Sage signed product")
        products += 1
    # Includes signed coefficients and products beyond both uint32 and int64.
    oracle, ring = SagePolynomialOracle(p.degree, p.q), p.ring()
    random = DeterministicRandom(b"luo-module-audit:arithmetic")
    for _ in range(16):
        a = tuple(int.from_bytes(random.read(8), "big") - 2**63 for _ in range(p.degree))
        b = tuple(int.from_bytes(random.read(8), "big") - 2**63 for _ in range(p.degree))
        require(ring.multiply(a, b) == oracle.multiply(a, b), "large Sage/NTT product")
        require(ring.inverse_ntt(ring.ntt(a)) == tuple(x % p.q for x in a), "large NTT inverse")
        c = challenge(p, b"IBME:LUO:AUDIT:SPARSE:v1", pack((tuple(x % p.q for x in a),)))
        require(sparse_product(a, c) == oracle.multiply(a, c, integer=True), "large Sage signed sparse product")
        products += 1
    rounding_inputs, hint_inputs, lemma_inputs = 0, 0, 0
    for q in (17, 31, 41, 97):
        for alpha in range(2, q // 2 + 1, 2):
            if (q - 1) % alpha:
                continue
            rounding = Rounding(q, alpha, 3)
            for r in range(q):
                expected = decompose(r, q, alpha)
                require(rounding.decompose(r) == expected, "independent Decompose")
                require(rounding.power2round_pair(r) == ((r - balanced(r, 8)) // 8, balanced(r, 8)), "independent Power2Round")
                rounding_inputs += 1
                for shift in range(1 - alpha // 2, alpha // 2):
                    h = int(decompose(r + shift, q, alpha)[0] != expected[0])
                    require(rounding.make_hint(shift, r) == h, "independent MakeHint")
                    require(rounding.use_hint(h, r) == decompose(r + shift, q, alpha)[0], "Lemma 1")
                    require(use_hint(h, r, q, alpha) == rounding.use_hint(h, r), "independent UseHint")
                    hint_inputs += 1
                    for beta in range(abs(shift), alpha // 2):
                        if abs(expected[1]) < alpha // 2 - beta:
                            require(decompose(r + shift, q, alpha)[0] == expected[0], "Lemma 2")
                        require(abs(decompose(r + shift, q, alpha)[1]) <= abs(expected[1]) + beta, "Lemma 3")
                        lemma_inputs += 1
    require(p.rounding().decompose(p.q - 1) == (0, -1), "q-1 special case")
    require(power_round(p.q - 1, p) == p.max_w1 == 1024, "Power2Round high encoding boundary")
    return dict(prime=True, root_order=2 * p.degree, sage_product_pairs=products,
                rounding_inputs=rounding_inputs, hint_inputs=hint_inputs, lemma_beta_inputs=lemma_inputs,
                q_minus_1_decompose=[0, -1], power_round_max=1024)


def signature_checks(oracle, public, key, signature, identity, message):
    p, alpha = public.params, 2 * public.params.gamma3
    w1 = vector_map(key.w, lambda x: power_round(x, p))
    require(w1 == signature.w1, "identity commitment compression")
    identity_hash = cid(public, w1, identity)
    require(plus(oracle.matvec(public.A, key.z1), key.z2, p.q)
            == plus(key.w, oracle.sparse_vector(public.t, identity_hash), p.q), "Sage identity-key equation")
    # Recover the accepted signing mask solely in memory for an independent
    # correctness check. No mask/private vector or digest is exported.
    y = plus(signature.z, negative(oracle.sparse_vector(key.z1, signature.c, integer=True)))
    require(norm(y) <= p.gamma2, "accepted uniform-mask support")
    w = oracle.matvec(public.A, y)
    high_w = vector_map(w, lambda x: decompose(x, p.q, alpha)[0])
    require(signature.c == cmsg(public, high_w, identity, message), "independent H2 challenge")
    r = plus(w, negative(oracle.sparse_vector(key.z2, signature.c)), p.q)
    w0 = plus(key.w, negative(vector_map(w1, lambda x: x * 2**p.dropped_bits)))
    w0c = oracle.sparse_vector(w0, signature.c, integer=True)
    r0 = vector_map(r, lambda x: decompose(x, p.q, alpha)[1])
    require(norm(signature.z) < p.gamma2 - p.beta2 and norm(r0) < p.gamma3 - p.beta2 and norm(w0c) < p.gamma3,
            "Algorithm 15 accepted rejection bounds")
    candidate = plus(oracle.matvec(public.A, signature.z), negative(oracle.sparse_vector(
        plus(vector_map(signature.w1, lambda x: x * 2**p.dropped_bits),
             oracle.sparse_vector(public.t, identity_hash), p.q), signature.c)), p.q)
    require(candidate == plus(r, w0c, p.q), "Sage Verify algebra")
    hints = tuple(tuple(int(decompose(value - shift, p.q, alpha)[0] != decompose(value, p.q, alpha)[0])
                        for value, shift in zip(poly, shifts)) for poly, shifts in zip(candidate, w0c))
    require(hints == signature.h, "independent MakeHint signature")
    high = tuple(tuple(use_hint(h, value, p.q, alpha) for h, value in zip(hints, poly))
                 for hints, poly in zip(signature.h, candidate))
    require(high == high_w and cmsg(public, high, identity, message) == signature.c, "Sage Verify/UseHint/H2")
    return y, dict(z_infinity_norm=norm(signature.z), hint_weight=sum(sum(poly) for poly in signature.h))


def public_guess_control(public, *, exhaustive):
    """Zero-response fixed-point guesses; no secret/oracle arguments."""
    p, verifier = public.params, LuoModuleIBSBackend()
    zeros_l, zeros_k = ((0,) * p.degree,) * p.l, ((0,) * p.degree,) * p.k
    guesses = 0
    for index in range(64):
        message = b"module-public-guess:" + index.to_bytes(2, "big")
        if exhaustive:
            candidates = (tuple(sign if j == position else 0 for j in range(p.degree))
                          for position in range(p.degree) for sign in (-1, 1))
        else:
            candidates = (independent_challenge(p, b"IBME:LUO:AUDIT:GUESS:v1", message),)
        for c in candidates:
            sig = LuoModuleSignature(p, public.context, zeros_l, c, zeros_k, zeros_k)
            guesses += 1
            if verifier.verify(public, b"never-issued", message, sig):
                return dict(guesses=guesses, accepted=1, identity_hex=b"never-issued".hex(), message_hex=message.hex(),
                            signature_base64=base64.b64encode(sig.to_bytes()).decode("ascii"))
    return dict(guesses=guesses, accepted=0)


def audit():
    from sage.env import SAGE_VERSION
    p, rows, setups = LuoModuleParams(), [], []
    identities, messages = [b"Alice", b"Bob", "发送者".encode("utf-8")], [b"", bytes(range(32)), b"x" * 256]
    oracle, public_transcript, mutations, persistence, seen_masks = SagePolynomialOracle(p.degree, p.q), None, 0, 0, set()
    for index in range(2):
        b = LuoModuleIBSBackend(rng=DeterministicRandom(f"luo-module-audit:{index}".encode()))
        pk, master = b.setup(p)
        require(plus(oracle.matvec(pk.A, master.s1), master.s2, p.q) == pk.t, "Sage Setup equation")
        public = LuoModulePublicKey.from_bytes(pk.to_bytes())
        require(public.to_bytes() == pk.to_bytes(), "canonical public roundtrip")
        require(public.context == shake_256(lp(DOMAIN_PUBLIC) + public.to_bytes()).digest(64), "independent public context")
        sizes, extraction_attempts = [], []
        verifier = LuoModuleIBSBackend()  # Does not receive master, keys or RNG.
        for identity in identities:
            key = b.key_extract(master, identity)
            extraction_attempts.append(b.last_extract_attempts)
            private_bytes = key.to_bytes()  # Memory only.
            sizes.append(len(private_bytes))
            require(LuoModuleSigningKey.from_bytes(private_bytes).to_bytes() == private_bytes, "private-key roundtrip")
            for message in messages:
                sig = b.sign(key, message)
                loaded = verifier.load_signature(public, sig.to_bytes())
                require(loaded.to_bytes() == sig.to_bytes() and verifier.verify(public, identity, message, loaded), "public-only canonical Verify")
                y, metrics = signature_checks(oracle, public, key, loaded, identity, message)
                mask_fingerprint = sha256(repr(y).encode()).digest()
                require(mask_fingerprint not in seen_masks, "reused signing mask in audit")
                seen_masks.add(mask_fingerprint)
                require(not verifier.verify(public, b"wrong-sender", message, loaded), "wrong-sender rejection")
                require(not verifier.verify(public, identity, message + b"changed", loaded), "changed-message rejection")
                mutations += 2
                rows.append(dict(setup_index=index, identity_bytes=len(identity), message_bytes=len(message),
                                 signature_bytes=len(sig.to_bytes()), sign_attempts=b.last_sign_attempts, **metrics))
                require(b.key_extract(master, identity).to_bytes() == private_bytes and b.last_extract_attempts == 0, "fixed identity key")
                if public_transcript is None:
                    public_transcript = dict(public_key_base64=base64.b64encode(public.to_bytes()).decode("ascii"),
                                             signature_base64=base64.b64encode(loaded.to_bytes()).decode("ascii"),
                                             identity_hex=identity.hex(), message_hex=message.hex())
        snapshot = master.to_bytes()  # Never written to the output artifact.
        restored = LuoModuleMasterSecret.from_bytes(snapshot)
        require(restored.to_bytes() == snapshot, "canonical master restore")
        for identity in identities:
            key = b.key_extract(restored, identity)
            require(key.to_bytes() == b.key_extract(master, identity).to_bytes(), "restored fixed identity")
            sig = b.sign(key, b"after-restore")
            require(verifier.verify(public, identity, b"after-restore", sig), "sign after restore")
            signature_checks(oracle, public, key, sig, identity, b"after-restore")
            persistence += 1
        setups.append(dict(public_key_bytes=len(public.to_bytes()), identity_private_key_bytes=sizes,
                           master_snapshot_bytes=len(snapshot), extract_attempts=extraction_attempts))
    large_guesses = public_guess_control(public, exhaustive=False)
    require(large_guesses["accepted"] == 0 and large_guesses["guesses"] == 64, "large public finite-guess regression")
    tiny = LuoModuleParams(degree=8, k=2, l=1, q=769, root=27, kappa=1,
                           gamma1=16, gamma2=256, gamma3=128, dropped_bits=3)
    tiny_public, unused_master = LuoModuleIBSBackend(rng=DeterministicRandom(b"luo-module-audit:tiny-control")).setup(tiny)
    tiny_guesses = public_guess_control(LuoModulePublicKey.from_bytes(tiny_public.to_bytes()), exhaustive=True)
    require(tiny_guesses["accepted"] == 1 and not unused_master.cached_identities, "toy public forgery negative control")
    tiny_guesses.update(challenge_space=16, private_key_access=False, extract_queries=0, sign_queries=0,
                        public_key_base64=base64.b64encode(tiny_public.to_bytes()).decode("ascii"))
    root = Path(__file__).resolve().parents[2]
    files = ("src/ibme/ibs/luo_module.py", "src/ibme/ibs/luo_module_math.py", "experiments/research/luo_module_audit.py",
             "papers/2024_ibs_without_trapdoors_luo.pdf")
    return dict(security_claim="none", backend_admitted=False, complete_secure_ibme_instances=0,
                python=sys.version, sage=SAGE_VERSION, platform=platform.platform(),
                processor="Intel Core Ultra 9 275HX; WSL2", params=asdict(p),
                source="Luo et al., ICICS 2024, Section 4 Algorithms 7-16; R1 cached identity state",
                source_sha256={name: sha256((root / name).read_bytes()).hexdigest() for name in files},
                entropy="DeterministicRandom test streams only; never production keys",
                model="Published ROM/QROM sketch is not a proof of this SHAKE instantiation or parameter variant",
                challenge_space_size=comb(p.degree, p.kappa) * 2**p.kappa,
                mathematics=mathematical_checks(), real_setups=2, identity_keys=6,
                fresh_masks_checked=len(seen_masks), honest_signature_checks=24, mutation_rejections=mutations,
                restored_keys_checked=persistence, setups=setups, signature_rows=rows,
                public_transcript=public_transcript, toy_public_forgery=tiny_guesses,
                large_public_guess_control=large_guesses,
                notes=["Only public objects and aggregate counts/dimensions are exported; private snapshots/masks remain in memory.",
                       "A is explicitly uniform, without the paper's SHAKE128 public seed compression.",
                       "No speed, constant-time, NIST, full MSIS/MLWE or complete IBME security claim.",
                       "64 rejected public guesses are a finite regression, not a forgery resistance proof.",
                       "The accepted tiny public forgery is an intentional insecure negative control."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit()  # Any failed check raises and prevents a success artifact.
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
        print(json.dumps({name: result[name] for name in ("honest_signature_checks", "mutation_rejections",
                                                       "restored_keys_checked", "security_claim")}, ensure_ascii=False))
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
