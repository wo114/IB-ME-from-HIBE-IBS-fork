"""Public lifecycle checks; never emit private objects or actual signatures."""
from dataclasses import replace
import json

from ibme.core.errors import SerializationError
from .paper_objects import PublicKey, MasterSecret, SigningKey, Signature


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def codec_checks(public, master, key, signature):
    checks, sizes = {}, {}
    for name, value, cls in (("public", public, PublicKey), ("master", master, MasterSecret),
                             ("key", key, SigningKey), ("signature", signature, Signature)):
        data = value.to_bytes()
        sizes[name] = len(data)
        checks[name+"_roundtrip"] = cls.from_bytes(data).to_bytes() == data
        record = json.loads(data)
        variants = {"truncated": data[:-1], "appended": data+b"0",
                    "duplicate": b'{"kind":"duplicate",'+data[1:],
                    "extra": _canonical({**record, "extra": 0}),
                    "wrong_kind": _canonical({**record, "kind": "wrong"})}
        for label, malformed in variants.items():
            try:
                cls.from_bytes(malformed)
            except (SerializationError, ValueError, TypeError):
                checks[name+"_"+label+"_rejected"] = True
            else:
                checks[name+"_"+label+"_rejected"] = False
    return checks, sizes


def attack_checks(backend, public, identity, message, signature):
    """One-step mutations and a real public Q-shift strong-forgery probe.

    A valid same-message replacement is recorded as an attack SUCCESS.  It is
    never turned into a failed parser test by imposing a non-paper norm cap.
    """
    rows = [list(poly) for poly in signature.response]
    rows[0][0] += 1
    mutation = replace(signature, response=rows)
    challenge = list(signature.challenge)
    challenge[0] ^= 1
    zero = tuple((0,)*public.params.degree for _ in signature.response)
    checks = {
        "honest": backend.verify(public, identity, message, signature),
        "wrong_identity_rejected": not backend.verify(public, identity+b"!", message, signature),
        "wrong_message_rejected": not backend.verify(public, identity, message+b"!", signature),
        "response_unit_tamper_rejected": not backend.verify(public, identity, message, mutation),
        "challenge_tamper_rejected": not backend.verify(public, identity, message,
                                                       replace(signature, challenge=challenge)),
        "zero_response_forgery_rejected": not backend.verify(public, identity, message,
                                                            replace(signature, response=zero)),
        "wrong_context_rejected": not backend.verify(public, identity, message,
                                                      replace(signature, context=bytes(32))),
        "invalid_types_rejected": all(not backend.verify(public, i, m, s) for i, m, s in
                                      ((None, message, signature), (identity, None, signature),
                                       (identity, message, object()))),
    }
    # 2*A*(Q e_i)=0 mod 2Q. Search coordinates in the identity block and
    # choose the sign towards zero. The original gamma is the only norm gate.
    q = public.params.modulus
    norm = sum(x*x for poly in signature.response for x in poly)
    cap = public.params.signature_norm_cap
    successes, trials = 0, 0
    for row in range(public.params.rank):
        for column, coefficient in enumerate(signature.response[row]):
            shift = -q if coefficient >= 0 else q
            if norm+2*coefficient*shift+q*q > cap:
                continue
            candidate = [list(poly) for poly in signature.response]
            candidate[row][column] += shift
            forged = replace(signature, response=candidate)
            trials += 1
            if backend.verify(public, identity, message, forged):
                successes += 1
                break
        if successes:
            break
    return checks, {"attack": "public Q shift in first identity block; same challenge/message",
                    "eligible_trials": trials, "accepted_replacements": successes,
                    "native_strong_counterexample_found": bool(successes),
                    "sample_or_forgery_exported": False,
                    "unsuccessful_probe_is_not_a_security_proof": True}
