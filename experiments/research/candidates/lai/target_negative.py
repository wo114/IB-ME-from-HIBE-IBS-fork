"""C2 target-level negative tests (Sage, long-running).

Checks: wrong child key, wrong parent ciphertext, tampered h'/u/v, non-unit
target tag, truncated/appended ciphertext.  Not a security proof.
"""
from __future__ import annotations

import json
from dataclasses import replace
from time import perf_counter

from sage.all import GF

from ibme.core.errors import SerializationError
from ibme.hibe.lai import LaiCiphertext, LaiHIBE
from ibme.hibe.lai.engine import LaiEngine
from ibme.hibe.lai.params import TARGET_CANDIDATE_PARAMS

params = TARGET_CANDIDATE_PARAMS
backend = LaiHIBE()
from ibme.core.randomness import DeterministicRandom

rng = lambda tag: DeterministicRandom(tag)
parent = b"r" * params.identity_bytes
child = b"s" * params.identity_bytes
wrong_child = b"t" * params.identity_bytes
wrong_parent = b"u" * params.identity_bytes
message = bytes(range(32))

report = {"params": dict(q=params.q, n=params.n, k=params.k), "checks": {},
          "security_claim": "none"}


def check(name, fn):
    t0 = perf_counter()
    try:
        ok = fn() is True
    except Exception as exc:  # pragma: no cover - reported as failure
        ok = False
        report["checks"][name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                                  "seconds": round(perf_counter() - t0, 2)}
        print(name, "FAIL", type(exc).__name__, exc, flush=True)
        return
    report["checks"][name] = {"ok": ok, "seconds": round(perf_counter() - t0, 2)}
    print(name, "ok" if ok else "FAIL", round(perf_counter() - t0, 2), flush=True)


t0 = perf_counter()
pk, msk = backend.setup(params, rng=rng(b"neg-setup"))
report["setup_s"] = round(perf_counter() - t0, 2)
t0 = perf_counter()
sk1 = backend.extract(msk, parent, rng=rng(b"neg-extract"))
report["extract_s"] = round(perf_counter() - t0, 2)
t0 = perf_counter()
sk2 = backend.derive(sk1, child, rng=rng(b"neg-derive"))
report["derive_s"] = round(perf_counter() - t0, 2)
t0 = perf_counter()
ct = backend.encrypt(pk, parent, child, message, rng=rng(b"neg-encrypt"))
report["encrypt_s"] = round(perf_counter() - t0, 2)
report["ct_bytes"] = len(ct.to_bytes())
t0 = perf_counter()
report["honest_ok"] = backend.decrypt(sk2, ct) == message
report["honest_decrypt_s"] = round(perf_counter() - t0, 2)
print("honest", report["honest_ok"], flush=True)

check("wrong_child_key", lambda: backend.decrypt(
    backend.derive(sk1, wrong_child, rng=rng(b"neg-wrong-child")), ct) is None)

check("wrong_parent_ciphertext", lambda: backend.decrypt(
    sk2, backend.encrypt(pk, wrong_parent, child, message,
                         rng=rng(b"neg-wrong-parent"))) is None)


def tamper_h():
    value = list(ct.hprime)
    value[0] = (value[0] + 1) % params.q
    return backend.decrypt(sk2, replace(ct, hprime=tuple(value))) is None


def tamper_u():
    value = list(ct.u[0])
    value[0] = (value[0] + 1) % params.q
    return backend.decrypt(sk2, replace(ct, u=(tuple(value),) + ct.u[1:])) is None


def tamper_v():
    value = list(ct.v[0])
    value[0] = (value[0] + 1) % params.q
    out = backend.decrypt(sk2, replace(ct, v=(tuple(value),) + ct.v[1:]))
    # Raw HIBE has no CCA/integrity: an in-range v tamper may yield a
    # different plaintext instead of None.  Both are negative evidence for
    # the raw primitive; outer BYTEAUTH is what must reject it.
    report["tampered_v0_result"] = (
        "none" if out is None else "same" if out == message else "different")
    return report["tampered_v0_result"] != "same"


check("tampered_hprime", tamper_h)
check("tampered_u0", tamper_u)
check("tampered_v0", tamper_v)


def nonunit_target():
    engine = LaiEngine(params)
    ring = engine.ring
    generator = GF(params.q).multiplicative_generator()
    root = int(generator ** ((params.q - 1) // (2 * params.n)))
    assert pow(root, params.n, params.q) == params.q - 1
    nonunit = ring.elem([(-root) % params.q, 1] + [0] * (params.n - 2))
    assert not nonunit.is_unit()
    hprime = engine._t(nonunit - engine._e(sk2.tag))
    return backend.decrypt(sk2, replace(ct, hprime=hprime)) is None


check("nonunit_target_tag", nonunit_target)


def serialization_rejects():
    blob = ct.to_bytes()
    for bad in (blob[:-1], blob + b"\x00", blob[:8] + b"\x00" * (len(blob) - 8)):
        try:
            LaiCiphertext.from_bytes(bad)
        except SerializationError:
            continue
        return False
    return True


check("truncated_appended_rejected", serialization_rejects)
report["all_ok"] = report["honest_ok"] and all(
    item["ok"] for item in report["checks"].values())

with open("/tmp/lai-target-negative.json", "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, ensure_ascii=False)
print(json.dumps(report, indent=2, ensure_ascii=False), flush=True)
raise SystemExit(0 if report["all_ok"] else 1)
