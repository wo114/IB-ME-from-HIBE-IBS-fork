"""Depth-two CHKP research backend, with explicit MP12 root generation.

All private randomness is byte-injected; fixed RNGs are test fixtures only.
Extract executes RandBasis. At maximum depth Derive fixes the 256 indexed
preimages once and discards the extended trapdoor. No MP12 DelTrap, public
fixture root, seeded-native sampler, or synthetic Gaussian fallback is used.
"""

from functools import lru_cache
from hmac import compare_digest

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity

from .params import CHKPParams
from .objects import (CHKPPublicKey, CHKPMasterSecret, CHKPLevel1SecretKey,
                      CHKPLevel2SecretKey, CHKPCiphertext, _scope)


def _options(p):
    from ibme.lattice.chkp.finite_gaussian import FirstFiniteOptions
    return FirstFiniteOptions(**{name: getattr(p, name) for name in (
        "tail_bits", "mass_bits", "precision_bits", "gaussian_abort_bits",
        "max_uniform_trials", "max_gaussian_trials", "max_radius",
        "rational_bits", "max_tape_bytes")})


@lru_cache(maxsize=16)
def _noise(p):
    from ibme.lattice.chkp.noise_budget import RoundedNoiseParams
    from ibme.lattice.chkp.rounded_noise import build_rounded_noise
    return build_rounded_noise(RoundedNoiseParams(p.q, p.alpha,
        tail_bits=p.noise_tail_bits, mass_bits=p.noise_mass_bits,
        precision_bits=p.noise_precision_bits, max_radius=p.noise_max_radius))


def _source(rng):
    source = SecureRandom() if rng is None else rng
    if not callable(getattr(source, "read", None)):
        from ibme.core.errors import RandomnessError
        raise RandomnessError("CHKP randomness must provide read(n)")
    return source


class CHKPHIBE:
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False

    def setup(self, params, *, rng=None):
        if not isinstance(params, CHKPParams):
            raise InvalidParameterError("explicit CHKP research parameters required")
        from ibme.lattice.chkp.root_generation import MP12RootGenerator, MP12RootParams
        from ibme.lattice.chkp.identity import ROHIBEContext
        from ibme.lattice.chkp.delegation_state import MasterTreeState
        p = params
        source = _source(rng)
        generator = MP12RootGenerator(MP12RootParams(
            p.n, p.q, p.m_bar, p.r_width_squared, regularity_bits=p.regularity_bits,
            uniform_trials=p.max_uniform_trials, max_entropy_bytes=p.root_entropy_budget),
            options=_options(p))
        public_bound = 10*(1+p.m_bar*p.n*(p.q-1).bit_length()*generator.scalar.radius**2)
        if p.root_gs_squared_bound < public_bound:
            raise InvalidParameterError("CHKP published root bound is below its generator bound")
        # Build the mandatory actual-noise table before consuming private RNG.
        _noise(p)
        generated = generator.generate(rng=source)
        oracle = ROHIBEContext(p.n, p.m, p.q, generated.basis.public.rows,
                               p.to_bytes(), identity_bytes=p.identity_bytes)
        public = CHKPPublicKey(p, oracle)
        master = CHKPMasterSecret(public, MasterTreeState(_scope(public), generated.basis))
        return public, master

    def extract(self, master, parent_id, *, rng=None):
        if not isinstance(master, CHKPMasterSecret):
            raise TypeError("CHKP master secret required")
        p = master.params
        identity = validate_identity(parent_id, max_bytes=p.identity_bytes)
        # The state lookup intentionally precedes RNG validation: a ready
        # address can be restored and reused without a functioning sampler.
        try:
            return CHKPLevel1SecretKey(master.public_key, master.state.lookup(identity))
        except KeyError:
            pass
        source = _source(rng)

        def generate(plan):
            from ibme.lattice.chkp.basis import ModMatrixReference
            from ibme.lattice.chkp.extended_gpv import ExtendedGPV
            from ibme.lattice.chkp.finite_randbasis import FirstFiniteRandBasis
            extension = ModMatrixReference(plan.scope.oracle.h((plan.receiver,)), p.q)
            sampler = ExtendedGPV(plan.root_basis, extension, p.parent_width_squared,
                                  epsilon_bits=p.epsilon_bits, options=_options(p),
                                  max_dimension=p.max_dimension)
            randomized = FirstFiniteRandBasis(sampler, max_vectors=p.parent_max_vectors,
                          max_tape_bytes=p.parent_entropy_budget, max_dimension=p.max_dimension).sample(rng=source)
            basis = randomized.basis
            if p.lll_policy == "checked":
                from ibme.lattice.chkp.basis_reduce import checked_lll
                basis = checked_lll(basis, p.parent_width_squared*(2*p.m),
                                    max_dimension=p.max_dimension)
            return basis

        return CHKPLevel1SecretKey(master.public_key, master.state.issue(identity, generate))

    def derive(self, parent, child_id, *, rng=None):
        if not isinstance(parent, CHKPLevel1SecretKey):
            raise TypeError("CHKP first-level key required")
        p = parent.params
        identity = validate_identity(child_id, max_bytes=p.identity_bytes)
        try:
            return CHKPLevel2SecretKey(parent.public_key, parent.state.lookup(identity))
        except KeyError:
            pass
        source = _source(rng)

        def generate(plan):
            from ibme.lattice.chkp.basis import ModMatrixReference
            from ibme.lattice.chkp.extended_gpv import ExtendedGPV
            seed = plan.seed_plan
            extension = ModMatrixReference(seed.scope.oracle.h((seed.scope.receiver, seed.sender)), p.q)
            sampler = ExtendedGPV(plan.parent_basis, extension, p.leaf_width_squared,
                                  epsilon_bits=p.epsilon_bits, options=_options(p),
                                  max_dimension=p.max_dimension)
            if sampler.basis.public.rows != seed.public_rows:
                raise InvalidParameterError("CHKP leaf sampler differs from real identity matrix")
            if 256*sampler.random_tape_bytes > p.leaf_entropy_budget:
                raise InvalidParameterError("CHKP full leaf entropy bound exceeds profile budget")
            return tuple(sampler.sample(target, rng=source) for target in seed.targets)

        return CHKPLevel2SecretKey(parent.public_key, parent.state.derive(identity, generate))

    def encrypt(self, public, parent_id, child_id, payload, *, rng=None):
        if not isinstance(public, CHKPPublicKey):
            raise TypeError("CHKP public key required")
        p = public.params
        parent_id = validate_identity(parent_id, max_bytes=p.identity_bytes)
        child_id = validate_identity(child_id, max_bytes=p.identity_bytes)
        payload = validate_bytes(payload, name="CHKP plaintext")
        if p.message_mode == "seed32":
            if len(payload) != 32:
                raise InvalidParameterError("CHKP seed32 requires exactly 32 plaintext bytes")
            encoded = payload
        else:
            if len(payload) > 28:
                raise InvalidParameterError("CHKP framed32 plaintext exceeds 28 bytes")
            encoded = len(payload).to_bytes(4, "big") + payload + bytes(28-len(payload))
        from ibme.lattice.chkp.seed_kem import encapsulate_seed
        return CHKPCiphertext(encapsulate_seed(public.oracle, parent_id, child_id,
                                              encoded, _noise(p), rng=_source(rng)))

    def decrypt(self, child, ciphertext, *, rng=None):
        if not isinstance(child, CHKPLevel2SecretKey) or not isinstance(ciphertext, CHKPCiphertext):
            raise TypeError("CHKP leaf key and ciphertext required")
        from ibme.lattice.chkp.seed_kem import decapsulate_seed
        value = decapsulate_seed(child.key, ciphertext.capsule)
        if value is None or child.params.message_mode == "seed32":
            return value
        length = int.from_bytes(value[:4], "big")
        if length > 28 or value[4+length:] != bytes(28-length):
            return None
        return value[4:4+length]

    def load_ciphertext(self, data):
        return CHKPCiphertext.from_bytes(data)

    def validate_key_binding(self, public_key, secret_key):
        if not isinstance(public_key, CHKPPublicKey) or not isinstance(secret_key,
                (CHKPMasterSecret, CHKPLevel1SecretKey, CHKPLevel2SecretKey)):
            return False
        # Constructors/decoders validate complete kernel/equation and identity
        # relations internally. The context and complete profile additionally
        # rule out an equally shaped key under another A0 or message mode.
        return bool(compare_digest(public_key.to_bytes(), secret_key.public_key.to_bytes()))
