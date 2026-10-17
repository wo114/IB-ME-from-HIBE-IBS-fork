"""Real SRGG research lifecycles at two small, explicitly insecure profiles.

No root or identity is retried after a failure. Export only public parameters,
counts, sizes and timings. The public forgery is an intentional negative control.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
from itertools import product
import json
from pathlib import Path
import platform
import sys
import tempfile
from time import perf_counter

from ibme.core.errors import SerializationError
from ibme.ibs.srgg_service import FixedIssuer
from .algebra import recover_commitment
from .backend import Backend
from .config import Config
from .hashing import identity_target, message_challenge
from .objects import SigningKey, Signature


def profiles():
    return {
        "baseline-n8": Config(),
        "density-width3-n8": replace(Config(), digits=4, r_squared=9,
            signature_first_squared=2**38, signature_second_squared=2**38,
            precision_bits=256, ticket_bits=192, scalar_tail_bits=64,
            scalar_mass_bits=96, gadget_tail_bits=64),
    }


class NoEntropy:
    def read(self, size):
        raise AssertionError("cached restart unexpectedly requested fresh entropy")


def _public_state_size(root):
    return (root/"master.bin").stat().st_size


@contextmanager
def _temporary_root(row):
    try:
        folder = tempfile.TemporaryDirectory(prefix="srgg-qualification-")
    except Exception as exc:
        row["workspace_creation_failure_class"] = type(exc).__name__
        yield None
        return
    try:
        yield Path(folder.name)/"issuer"
    finally:
        try:
            folder.cleanup()
        except Exception as exc:
            row["workspace_cleanup_failure_class"] = type(exc).__name__


def public_forgery(backend, public):
    """Bounded exhaustive small-challenge negative control, using no secret."""
    p = public.config.algebra
    zero = ((0,)*p.degree,)*(p.columns+1)
    target = identity_target(public, b"Unissued-negative-control")
    evaluated = 0
    for counter in range(16):
        msg = b"public-forgery:"+counter.to_bytes(2, "big")
        for challenge in product((0, 1), repeat=p.degree):
            evaluated += 1
            commitment = recover_commitment(public.public, target, zero, challenge)
            if message_challenge(public, commitment, msg) == challenge:
                accepted = backend.verify(public, b"Unissued-negative-control", msg,
                                          Signature(public.context, zero, challenge))
                return {"evaluated_pairs": evaluated, "accepted": accepted,
                        "user_secret_or_issuance_used": False}
    return {"evaluated_pairs": evaluated, "accepted": False,
            "search_exhausted": True, "user_secret_or_issuance_used": False}


def run_profile(name, config, *, roots=3, rng_factory=None):
    if not isinstance(config, Config) or type(roots) is not int or not 1 <= roots <= 8:
        raise ValueError("Config and bounded root count required")
    rows = []
    for index in range(roots):
        backend = Backend(rng=None if rng_factory is None else rng_factory(index))
        row = {"root_index": index, "setup_succeeded": False, "identities": []}
        with _temporary_root(row) as root:
            if root is None:
                rows.append(row)
                continue
            issuer = FixedIssuer(root, backend)
            started = perf_counter()
            try:
                public = issuer.initialize(config, max_users=2)
                row.update(setup_succeeded=True, setup_seconds=perf_counter()-started,
                           public_key_bytes=len(public.to_bytes()))
            except Exception as exc:
                row["setup_failure_class"] = type(exc).__name__
                rows.append(row)
                continue
            for identity in (b"Alice", b"Bob"):
                item = {"identity_bytes": len(identity), "issuance_succeeded": False,
                        "signatures": [], "restore_succeeded": False}
                started = perf_counter()
                try:
                    key = issuer.key_extract(identity)
                    item.update(issuance_succeeded=True, issuance_seconds=perf_counter()-started,
                                signing_key_bytes=len(key.to_bytes()))
                    restarted = FixedIssuer(root, Backend(rng=NoEntropy()))
                    cached = restarted.key_extract(identity)
                    restored_public = restarted.public_key()
                    restored = SigningKey.from_bytes(cached.to_bytes())
                    item["cached_same_key"] = cached.to_bytes() == key.to_bytes()
                    item["restored_public_matches"] = restored_public.to_bytes() == public.to_bytes()
                    for length in (0, 32, config.message_max_bytes):
                        msg = b"M"*length
                        started = perf_counter()
                        sig = backend.sign(restored, msg)
                        elapsed = perf_counter()-started
                        accepted = backend.verify(restored_public, identity, msg, sig)
                        item["signatures"].append({"message_bytes": length, "verified": accepted,
                                                   "signature_bytes": len(sig.to_bytes()),
                                                   "sign_seconds": elapsed})
                    sig = backend.sign(restored, b"after-restart")
                    item["restore_succeeded"] = backend.verify(restored_public, identity,
                                                               b"after-restart", sig)
                    for label, raw in (("truncated", sig.to_bytes()[:-1]),
                                       ("appended", sig.to_bytes()+b"x")):
                        try:
                            backend.load_signature(public, raw)
                        except SerializationError:
                            item[label+"_wire_rejected"] = True
                        else:
                            item[label+"_wire_rejected"] = False
                except Exception as exc:
                    item["failure_class"] = type(exc).__name__
                row["identities"].append(item)
            try:
                row["trusted_plaintext_state_bytes"] = _public_state_size(root)
            except Exception as exc:
                row["state_measurement_failure_class"] = type(exc).__name__
            if index == 0:
                try:
                    row["public_negative_control"] = public_forgery(backend, public)
                except Exception as exc:
                    row["public_negative_control"] = {"failure_class": type(exc).__name__}
        rows.append(row)
    return {"profile": name, "parameters": config.record(), "roots_requested": roots,
            "rng": "SecureRandom" if rng_factory is None else "deterministic test fixture",
            "roots": rows, "root_reselection": False, "security_claim": "none",
            "parameters_are_formal": False, "backend_admitted": False}


def build_report(*, roots=3):
    from sage.version import version
    import resource
    result = {
        "schema": "IBME/SRGG-QUALIFICATION-LIFECYCLE/1",
        "environment": {"python": sys.version.split()[0], "sage": version,
                        "platform": platform.platform(), "processor": platform.processor()},
        "profiles": [run_profile(name, config, roots=roots) for name, config in profiles().items()],
        "limits": ["Both profiles retain an 8-bit publicly forgeable challenge; neither is a formal candidate.",
                   "Small-root measurements do not estimate rare abort probability or a distribution distance.",
                   "This audits the standalone persistent issuer, not a selected HIBE composition.",
                   "Timings include validation and trusted local persistence; no constant-time claim.",
                   "Peak memory is cumulative process ru_maxrss, not a per-profile allocation measurement."],
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
    }
    result["process_peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roots", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_report(roots=args.roots)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n",
                           encoding="utf-8", newline="\n")
    print(json.dumps({"profiles": len(result["profiles"]), "roots_per_profile": args.roots,
                      "process_peak_rss_kib": result["process_peak_rss_kib"]}))


if __name__ == "__main__":
    main()
