"""Lai PLWE security-parameter candidates (research screening).

The estimator numbers below are pinned heuristic Core-SVP outputs for the
PLWE coefficient LWE instance, not a NIST category or a HIBE security proof.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json

from ibme.hibe.lai import codec
from ibme.hibe.lai.params import LaiParams, _is_prime


@dataclass(frozen=True)
class Candidate:
    name: str
    n: int
    q: int
    k: int
    l: int = 2
    p: int = 2
    sigma: float = 2.0
    sigma_r: float = 1.0
    note: str = ""

    @property
    def params(self) -> LaiParams:
        return LaiParams(q=self.q, n=self.n, k=self.k, l=self.l, p=self.p,
                         sigma=self.sigma, sigma_r=self.sigma_r,
                         identity_bytes=86, max_message_bytes=32)


CANDIDATES = (
    Candidate("a-point-256-2p31", 256, 2147484161, 32,
              note="research A point; not a security parameter"),
    Candidate("c1-1024-2p35", 1024, 34359754753, 36,
              note="estimated below 128-bit; rejected"),
    Candidate("c2-2048-2p38", 2048, 274877976577, 39,
              note="selected: first validated >=128-bit candidate"),
    Candidate("c3-2048-2p39", 2048, 549755904001, 40,
              note="not selected; fallback only, not lifecycle-tested"),
)
SELECTED = "c2-2048-2p38"

# Pinned lattice-estimator 53da598, ADPS16 classical 0.292 / quantum 0.265,
# LGSA, PLWE coefficient instance: n secret dimension, m=(l+k)n samples,
# Xs=D(sigma), Xe=D(p*sigma).  Standard usvp/bdd/dual attacks only; the
# heuristic hybrid variants hit an estimator domain error at these q and are
# not claimed.
SECURITY_BITS = {
    "a-point-256-2p31": {"classical": 11.7, "quantum": 10.6},
    "c1-1024-2p35": {"classical": 74.2, "quantum": 67.3},
    "c2-2048-2p38": {"classical": 169.9, "quantum": 154.2},
    "c3-2048-2p39": {"classical": 164.1, "quantum": 148.9},
}
SECURITY_MODEL = dict(
    estimator="malb/lattice-estimator",
    commit="53da5982597709ba0fdf94ea37a84d822310fd84",
    problem="PLWE coefficient LWE: n secret dimension, m=(l+k)n samples",
    secret="discrete Gaussian sigma",
    error="discrete Gaussian p*sigma",
    cost_model="ADPS16 Core-SVP classical 0.292 / quantum 0.265, LGSA",
    attacks="usvp, bdd, dual",
    excluded="bdd_hybrid/bdd_mitm_hybrid/dual_hybrid (estimator math-domain error at these q)",
    scope="heuristic screening; not a NIST level or HIBE security proof",
)

BASELINE_Q_MIN = 2 ** 30 * (279958552 / 248524837)  # q=2^30 probe failed by 13%


def validate_candidate(candidate: Candidate) -> dict:
    p = candidate.params
    if not _is_prime(candidate.q):
        raise ValueError(f"{candidate.name}: q is not prime")
    if candidate.q % (2 * candidate.n) != 1:
        raise ValueError(f"{candidate.name}: q != 1 mod 2n")
    if candidate.q >= 2 ** 40:
        raise ValueError(f"{candidate.name}: q exceeds 5-byte codec")
    if candidate.k != candidate.q.bit_length():
        raise ValueError(f"{candidate.name}: k != ceil(log2 q)")
    return dict(name=candidate.name, n=p.n, q=str(p.q), q_bits=p.q.bit_length(),
                k=p.k, coefficient_bytes=p.coefficient_bytes,
                q_is_prime=True, q_mod_2n=p.q % (2 * p.n), note=candidate.note)


def sizes(candidate: Candidate, identity_bytes: int = 86) -> dict:
    p = candidate.params
    ring = p.coefficient_bytes * p.n
    params_len = len(codec.params_bytes(p))
    l, k = p.l, p.k
    public_body = (params_len + (2 + (l + k) * ring) + 2
                   + 3 * (2 + k * ring))
    pk = 8 + public_body
    msk = 8 + public_body + 4 + l * k * ring
    sk1 = (8 + public_body + (2 + identity_bytes) + ring
           + (2 + (l + k) * ring) + (2 + k * ring)
           + (4 + (l + k) * k * ring))
    sk2 = (8 + public_body + 2 * (2 + identity_bytes) + ring
           + (2 + (l + 2 * k) * ring) + (2 + k * ring)
           + (4 + (l + 2 * k) * k * ring))
    ct = (8 + params_len + 1 + ring
          + (2 + (l + 2 * k) * ring) + (2 + k * ring))
    return dict(ring_element=ring, params=params_len, public_key=pk,
                master_secret=msk, level1_secret=sk1, level2_secret=sk2,
                ciphertext=ct, scope="formula for 86 B identities; framing +/- few bytes")


def margin_proxy(candidate: Candidate) -> float:
    p = candidate.params
    required = BASELINE_Q_MIN * (p.n / 256) ** 1.9 * (p.k / 31) ** 2 * (p.sigma / 2) ** 3
    return p.q / required


def audit() -> dict:
    rows = []
    for candidate in CANDIDATES:
        row = validate_candidate(candidate)
        row["sizes"] = sizes(candidate)
        row["correctness_margin_proxy"] = round(margin_proxy(candidate), 2)
        row["security_bits"] = SECURITY_BITS[candidate.name]
        row["selected"] = candidate.name == SELECTED
        rows.append(row)
    return dict(schema="IBME/LAI/PLWE-PARAMS/1", target_bits=128,
                security_model=SECURITY_MODEL, selected=SELECTED,
                correctness_scope=("scaled from the measured n=256 q=2^30 failure "
                                   "and n=256 q=2^31 pass; not a proof"),
                rows=rows, security_claim="none", backend_admitted=False,
                parameters_are_formal=False)


if __name__ == "__main__":
    print(json.dumps(audit(), ensure_ascii=False, indent=2))
