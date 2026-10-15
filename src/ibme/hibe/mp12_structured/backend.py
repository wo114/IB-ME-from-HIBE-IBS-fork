"""Real structured MP12 GenTrap/DelTrap + complete CHKP H/G seed HIBE.

This is a separately named implementation variant, not original CHKP
RandBasis, not a new paper algorithm and not security admitted.
"""

from functools import lru_cache
from hmac import compare_digest

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_identity, validate_bytes
from .params import StructuredHIBEParams
from .objects import (StructuredPublicKey, StructuredMasterSecret,
    StructuredLevel1Key, StructuredLevel2Key, StructuredCiphertext)


def _source(rng):
    source = SecureRandom() if rng is None else rng
    if not callable(getattr(source, "read", None)):
        raise InvalidParameterError("structured HIBE RNG must provide read(n)")
    return source


@lru_cache(maxsize=8)
def _noise(p):
    from ibme.lattice.chkp.noise_budget import RoundedNoiseParams
    from ibme.lattice.chkp.rounded_noise import build_rounded_noise
    return build_rounded_noise(RoundedNoiseParams(p.q, p.alpha,
        tail_bits=128, mass_bits=256, precision_bits=320, max_radius=8192))


class StructuredMP12HIBE:
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def __init__(self, *, persist_pending=None):
        if persist_pending is not None and not callable(persist_pending):
            raise TypeError("structured HIBE pending persister must be callable")
        self._persist_pending = persist_pending

    def setup(self, params, *, rng=None):
        if not isinstance(params, StructuredHIBEParams):
            raise InvalidParameterError("explicit complete structured HIBE parameters required")
        from ibme.lattice.matrix_sampling.mp12_structured import generate_structured_root
        from ibme.lattice.chkp.identity import ROHIBEContext
        _noise(params)  # complete actual noise construction, before private RNG
        t = generate_structured_root(params.n, params.q, params.root_r_squared, rng=_source(rng))
        oracle = ROHIBEContext(params.n, params.m, params.q, t.public.rows,
            params.to_bytes(), identity_bytes=params.identity_bytes)
        public = StructuredPublicKey(params, oracle)
        return public, StructuredMasterSecret(public, t)

    def extract(self, master, parent_id, *, rng=None):
        if not isinstance(master, StructuredMasterSecret): raise TypeError("structured HIBE master required")
        receiver = validate_identity(parent_id, max_bytes=master.params.identity_bytes)
        def generate():
            from ibme.lattice.matrix_sampling.mp12_extension import delegate_extension
            if self._persist_pending is not None: self._persist_pending(master)
            t = delegate_extension(master.trapdoor, master.public_key.oracle.h((receiver,)), rng=_source(rng))
            return StructuredLevel1Key(master.public_key, receiver, t)
        return master.issue(receiver, generate)

    def derive(self, parent, child_id, *, rng=None):
        if not isinstance(parent, StructuredLevel1Key): raise TypeError("structured HIBE first-level key required")
        sender = validate_identity(child_id, max_bytes=parent.params.identity_bytes)
        def generate(plan):
            from ibme.lattice.matrix_sampling.mp12_extension import StructuredLeftSampler
            from ibme.lattice.chkp.entropy import CheckedEntropy
            if self._persist_pending is not None: self._persist_pending(parent)
            sampler = StructuredLeftSampler(parent.trapdoor,
                parent.public_key.oracle.h((parent.identity, sender)))
            if (sampler.public_rows != plan.public_rows
                    or sampler.output_squared != parent.params.leaf_width_squared):
                raise InvalidParameterError("structured H/G complete leaf sampler mismatch")
            budget = 256*sampler.random_tape_bytes
            if budget > 2**48:
                raise InvalidParameterError("structured HIBE whole 256-preimage tape limit")
            source = CheckedEntropy(_source(rng), budget)
            return tuple(sampler.sample(target, rng=source) for target in plan.targets)
        key = parent.leaves.resolve(sender, generate)
        return StructuredLevel2Key(parent.public_key, key)

    def encrypt(self, public, parent_id, child_id, payload, *, rng=None):
        if not isinstance(public, StructuredPublicKey): raise TypeError("structured HIBE public key required")
        receiver = validate_identity(parent_id, max_bytes=public.params.identity_bytes)
        sender = validate_identity(child_id, max_bytes=public.params.identity_bytes)
        payload = validate_bytes(payload, name="structured HIBE seed")
        if len(payload) != 32: raise InvalidParameterError("structured HIBE seed32 requires exactly 32 bytes")
        from ibme.lattice.chkp.seed_kem import encapsulate_seed
        return StructuredCiphertext(encapsulate_seed(public.oracle, receiver, sender,
            payload, _noise(public.params), rng=_source(rng)))

    def decrypt(self, child, ciphertext, *, rng=None):
        if not isinstance(child, StructuredLevel2Key) or not isinstance(ciphertext, StructuredCiphertext):
            raise TypeError("structured HIBE fixed leaf and ciphertext required")
        from ibme.lattice.chkp.seed_kem import decapsulate_seed
        return decapsulate_seed(child.key, ciphertext.capsule)

    def load_ciphertext(self, raw): return StructuredCiphertext.from_bytes(raw)

    def validate_key_binding(self, public_key, secret_key):
        return (isinstance(public_key, StructuredPublicKey)
            and isinstance(secret_key, (StructuredMasterSecret, StructuredLevel1Key, StructuredLevel2Key))
            and compare_digest(public_key.to_bytes(), secret_key.public_key.to_bytes()))
