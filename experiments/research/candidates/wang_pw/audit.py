"""Execute real research signatures; publish metrics only, never secret state."""
import argparse
import json
from pathlib import Path
import platform
import sys
from time import perf_counter

from sage.all import GF, ZZ, matrix, vector
from sage.version import version as sage_version

from experiments.research.online_gaussian_reference import OnlineOptions
from experiments.research.online_mp12_reference import sampler_for_quality
from .backend import Backend
from .hashing import inner_identity, inner_message, identity_matrix, message_vector
from .objects import Signature, SigningKey
from .params import Params


def _public_classes(p):
    """Use PUBLIC zero probes; no certificate of an actual secret is exposed."""
    result = {}
    for name, columns, quality in (("master", p.m_bar, p.master_quality), ("user", p.m, p.user_quality)):
        status, probe = sampler_for_quality(p.q, matrix(ZZ, p.n, columns), matrix(ZZ, columns, p.w),
            quality, r_squared=p.r_squared, gamma=p.gamma, options=OnlineOptions(**p.online_options()))
        certificate = probe.certificate()
        result[name] = {"quality_class_upper": quality,
                       "spherical_width_squared": str(p.r_squared*status["stage"]["Sigma_scalar"]),
                       "public_byte_budget": probe.random_tape_bytes,
                       "per_sample_tv_upper_including_abort": certificate["tv_upper_including_abort"],
                       "independent_uniform_bytes_assumed": True}
    return result


def public_debug_forgery(pk, identity, message, *, identity_salt, message_salt):
    """Public linear solve NEGATIVE CONTROL; not a signing implementation."""
    p = pk.params
    x, y = inner_identity(p, identity, identity_salt), inner_message(p, message, message_salt)
    f = matrix(GF(p.q), tuple(a+b for a, b in zip(pk.a, identity_matrix(pk, x))))
    z = tuple(int(v) for v in f.solve_right(vector(GF(p.q), message_vector(pk, x, y))))
    if not any(z): z = tuple(int(v) for v in f.right_kernel().basis()[0])
    return Signature(pk.context, identity_salt, message_salt, z)


def audit_report(*, repetitions=16, rng=None):
    if type(repetitions) is not int or not 1 <= repetitions <= 64:
        raise ValueError("repetitions must be 1..64; no unbounded benchmark")
    p, backend, samples = Params(), Backend(rng=rng), []
    before = perf_counter()
    pk, master = backend.setup(p)
    setup_time = perf_counter()-before
    before = perf_counter()
    key = backend.key_extract(master, b"Alice")
    extract_time = perf_counter()-before
    signing, verifying, signatures = [], [], []
    for i in range(repetitions):
        message = b"competition-research:"+i.to_bytes(4, "big")
        before = perf_counter()
        sig = backend.sign(key, message)
        signing.append(perf_counter()-before)
        before = perf_counter()
        verified = backend.verify(pk, key.identity, message, sig)
        verifying.append(perf_counter()-before)
        samples.append({"message_bytes": len(message), "signature_bytes": len(sig.to_bytes()),
                        "norm_squared": sum(z*z for z in sig.z), "verified": verified,
                        "wrong_message_accepted": backend.verify(pk, key.identity, message+b"wrong", sig)})
        signatures.append(sig)
    restored = SigningKey.from_bytes(key.to_bytes())
    resumed = Backend(rng=rng)
    recovered = resumed.sign(restored, b"after restart")
    forged = public_debug_forgery(pk, b"Unissued", b"public forgery",
        identity_salt=signatures[0].identity_salt, message_salt=signatures[0].message_salt)
    return {"schema_version": 1, "algorithm": "Wang Figure 4 + PW Figure 5 / MP12 Algorithms 1,3,4",
            "parameters": p.record(),
            "environment": {"python": sys.version.split()[0], "sage": sage_version,
                            "platform": platform.platform(), "rng": "SecureRandom" if rng is None else type(rng).__name__},
            "input": {"identity_bytes": len(key.identity), "repetitions": repetitions,
                      "mode": "same issued identity; fresh message salts and SampleD draws"},
            "timings_seconds": {"setup": setup_time, "key_extract": extract_time,
                                 "sign": signing, "verify": verifying},
            "wire_bytes": {"public_key": len(pk.to_bytes()), "master_secret": len(master.to_bytes()),
                           "user_key": len(key.to_bytes()), "signature_min": min(s["signature_bytes"] for s in samples),
                           "signature_max": max(s["signature_bytes"] for s in samples)},
            "samples": samples, "honest_verified": sum(s["verified"] for s in samples),
            "restored_key_verified": resumed.verify(pk, key.identity, b"after restart", recovered),
            "debug_public_forgery_accepted": backend.verify(pk, b"Unissued", b"public forgery", forged),
            "sampler_classes": _public_classes(p), "security_claim": "none", "backend_admitted": False,
            "limitations": ["UNSAFE debug profile: B_verify >> q; successful public forgery expected",
                            "n=1,q=17: message-oracle collisions can accept incorrect messages",
                            "root public-matrix near-uniformity not certified; no SIS security level",
                            "SHAKE candidate is not an ideal random oracle; fixed-service reduction remains conditional",
                            "variable time; finite sampling errors/aborts; fresh independent uniform bytes assumed",
                            "timings are local research measurements, not a secure-parameter performance comparison",
                            "wire sizes are actual canonical JSON research objects; secrets stay in process memory"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=16)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit_report(repetitions=args.repetitions)
    serialized = json.dumps(report, ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    print(json.dumps({name: report[name] for name in ("honest_verified", "restored_key_verified",
        "debug_public_forgery_accepted", "wire_bytes", "security_claim", "backend_admitted")}, ensure_ascii=False))


if __name__ == "__main__": main()
