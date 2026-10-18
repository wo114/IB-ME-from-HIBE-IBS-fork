"""Reproducible Lai target-scale lifecycle probe (Sage required).

Example (selected candidate)::

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
        -m experiments.research.candidates.lai.target_probe
"""
from __future__ import annotations

import argparse
import json
from time import perf_counter

from ibme.core.randomness import DeterministicRandom
from ibme.hibe.lai import LaiHIBE, LaiParams


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=2048)
    parser.add_argument("--q", type=int, default=274877976577)
    parser.add_argument("--k", type=int, default=39)
    parser.add_argument("--sigma", type=float, default=2.0)
    parser.add_argument("--identity-bytes", type=int, default=86)
    parser.add_argument("--message-bytes", type=int, default=32)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    params = LaiParams(q=args.q, n=args.n, k=args.k, l=2, p=2,
                       sigma=args.sigma, sigma_r=1.0,
                       identity_bytes=args.identity_bytes,
                       max_message_bytes=args.message_bytes)
    backend = LaiHIBE()
    rng = lambda tag: DeterministicRandom(f"seed{args.seed}-{tag}".encode())
    parent = b"r" * args.identity_bytes
    child = b"s" * args.identity_bytes
    message = bytes(range(args.message_bytes))

    report = {"params": dict(q=params.q, n=params.n, k=params.k,
                             l=params.l, p=params.p, sigma=params.sigma),
              "seed": args.seed, "message_bytes": len(message), "identity_bytes": args.identity_bytes,
              "security_claim": "none", "ok": False}
    t0 = perf_counter()
    pk, msk = backend.setup(params, rng=rng("target-setup"))
    report["setup_s"] = round(perf_counter() - t0, 2)
    report["sizes"] = {"pk": len(pk.to_bytes()), "msk": len(msk.to_bytes())}
    t0 = perf_counter()
    sk1 = backend.extract(msk, parent, rng=rng("target-extract"))
    report["extract_s"] = round(perf_counter() - t0, 2)
    report["sizes"]["sk1"] = len(sk1.to_bytes())
    t0 = perf_counter()
    sk2 = backend.derive(sk1, child, rng=rng("target-derive"))
    report["derive_s"] = round(perf_counter() - t0, 2)
    report["sizes"]["sk2"] = len(sk2.to_bytes())
    t0 = perf_counter()
    ct = backend.encrypt(pk, parent, child, message, rng=rng("target-encrypt"))
    report["encrypt_s"] = round(perf_counter() - t0, 2)
    report["sizes"]["ct"] = len(ct.to_bytes())
    t0 = perf_counter()
    report["ok"] = backend.decrypt(sk2, ct) == message
    report["decrypt_s"] = round(perf_counter() - t0, 2)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
