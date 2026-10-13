"""Complete public CHKP research profiles; no implicit security admission.

The root generator is explicitly MP12 GenTrap converted to a complete basis.
Delegation is CHKP RandBasis, followed by maximum-depth GPV preimages. These
are independently named choices; MP12 DelTrap is not a permitted substitute.
"""

from dataclasses import asdict, dataclass, fields
from fractions import Fraction
import json
from math import gcd

from ibme.core.errors import InvalidParameterError, SerializationError

PARAM_MAGIC = b"IBME:CHKP:PARAMS:v1\0"
MAX_PARAM_BYTES = 4096


def _int(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise InvalidParameterError(f"{name} is outside its exact integer domain")


def _prime64(n):
    if n < 2:
        return False
    for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % prime == 0:
            return n == prime
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if base % n == 0:
            continue
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate parameter field")
        result[key] = value
    return result


@dataclass(frozen=True)
class CHKPParams:
    n: int
    q: int
    m_bar: int
    r_width_squared: int
    root_gs_squared_bound: int
    parent_width_squared: int
    leaf_width_squared: int
    alpha_numerator: int
    alpha_denominator: int
    message_mode: str = "seed32"
    identity_bytes: int = 86
    epsilon_bits: int = 128
    regularity_bits: int = 64
    parent_max_vectors: int = 382
    max_dimension: int = 512
    max_receivers: int = 8
    tail_bits: int = 128
    mass_bits: int = 256
    precision_bits: int = 320
    gaussian_abort_bits: int = 128
    max_uniform_trials: int = 192
    max_gaussian_trials: int = 2048
    max_radius: int = 2**48
    rational_bits: int = 8192
    max_tape_bytes: int = 2**40
    root_entropy_budget: int = 2**34
    parent_entropy_budget: int = 2**39
    leaf_entropy_budget: int = 2**39
    noise_tail_bits: int = 80
    noise_mass_bits: int = 128
    noise_precision_bits: int = 256
    noise_max_radius: int = 8192
    lll_policy: str = "none"

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False
    version = "chkp-ro-mp12-root-finite-v1"
    root_algorithm = "MP12-GenTrap/full-basis"
    delegation_algorithm = "CHKP-ExtBasis/RandBasis/ToBasis"
    leaf_algorithm = "CHKP-maximum-depth/SampleD256"
    seed_bits = 256

    def __post_init__(self):
        for name, low, high in (
            ("n", 1, 64), ("q", 2, 2**61-1), ("m_bar", 1, 2048),
            ("r_width_squared", 1, 2**80), ("root_gs_squared_bound", 1, 2**160),
            ("parent_width_squared", 1, 2**160), ("leaf_width_squared", 1, 2**160),
            ("alpha_numerator", 1, 2**80), ("alpha_denominator", 2, 2**160),
            ("identity_bytes", 1, 256), ("epsilon_bits", 2, 128),
            ("regularity_bits", 8, 192), ("parent_max_vectors", 1, 4096),
            ("max_dimension", 1, 512), ("max_receivers", 1, 8),
            ("tail_bits", 8, 1024), ("mass_bits", 32, 2048),
            ("precision_bits", 96, 4096), ("gaussian_abort_bits", 8, 1024),
            ("max_uniform_trials", 1, 4096), ("max_gaussian_trials", 1, 1000000),
            ("max_radius", 1, 2**48), ("rational_bits", 128, 8192),
            ("max_tape_bytes", 1, 2**40), ("noise_tail_bits", 8, 256),
            ("root_entropy_budget", 1, 2**40), ("parent_entropy_budget", 1, 2**40),
            ("leaf_entropy_budget", 1, 2**40),
            ("noise_mass_bits", 8, 512), ("noise_precision_bits", 128, 1024),
            ("noise_max_radius", 1, 16384),
        ):
            _int(getattr(self, name), name, low, high)
        if not _prime64(self.q):
            raise InvalidParameterError("CHKP modulus must be prime")
        if self.message_mode not in ("seed32", "framed32"):
            raise InvalidParameterError("explicit seed32 or framed32 message mode required")
        if self.lll_policy not in ("none", "checked"):
            raise InvalidParameterError("unknown CHKP basis reduction policy")
        if self.leaf_dimension > self.max_dimension or self.parent_max_vectors < 2*self.m:
            raise InvalidParameterError("CHKP dimensions or RandBasis budget exceed the profile")
        if gcd(self.alpha_numerator, self.alpha_denominator) != 1:
            raise InvalidParameterError("noise alpha must be in reduced rational form")
        if not 0 < self.alpha < 1 or not Fraction(1, 256) <= self.q*self.alpha <= 16384:
            raise InvalidParameterError("rounded noise alpha is outside the executable domain")
        if self.noise_precision_bits < self.noise_mass_bits + 32:
            raise InvalidParameterError("rounded noise precision cannot certify its mass grid")
        if max(self.root_entropy_budget, self.parent_entropy_budget, self.leaf_entropy_budget) > self.max_tape_bytes:
            raise InvalidParameterError("stage entropy budget exceeds the full profile budget")
        k1 = (4*self.m*(1+2**self.epsilon_bits)-1).bit_length()
        k2 = (6*self.m*(1+2**self.epsilon_bits)-1).bit_length()
        if self.parent_width_squared < 4*self.root_gs_squared_bound*k1:
            raise InvalidParameterError("parent width fails the public C1-exec bound")
        if self.leaf_width_squared < 4*self.parent_width_squared*(2*self.m)*k2:
            raise InvalidParameterError("leaf width fails the public C1-exec bound")

    @property
    def m(self):
        return self.m_bar + self.n*(self.q-1).bit_length()

    @property
    def leaf_dimension(self):
        return 3*self.m

    @property
    def max_message_bytes(self):
        return 32 if self.message_mode == "seed32" else 28

    @property
    def alpha(self):
        return Fraction(self.alpha_numerator, self.alpha_denominator)

    def to_bytes(self):
        return PARAM_MAGIC + json.dumps(asdict(self), sort_keys=True,
                                       separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @classmethod
    def from_bytes(cls, data):
        if not isinstance(data, bytes) or len(data) > MAX_PARAM_BYTES or not data.startswith(PARAM_MAGIC):
            raise SerializationError("invalid CHKP parameter wire")
        try:
            values = json.loads(data[len(PARAM_MAGIC):].decode("ascii"), object_pairs_hook=_unique)
            if type(values) is not dict or set(values) != {f.name for f in fields(cls)}:
                raise ValueError("incomplete CHKP parameter snapshot")
            result = cls(**values)
            if result.to_bytes() != data:
                raise ValueError("noncanonical CHKP parameter snapshot")
            return result
        except (ValueError, TypeError, UnicodeError, RecursionError, InvalidParameterError) as exc:
            raise SerializationError("invalid CHKP parameter snapshot") from exc


def ciphertext_size(params, payload_bytes, identity_bytes=None):
    """Exact seed capsule wire size, independent of private key geometry."""
    if not isinstance(params, CHKPParams):
        raise InvalidParameterError("CHKP parameters required")
    _int(payload_bytes, "payload bytes", 0, params.max_message_bytes)
    if params.message_mode == "seed32" and payload_bytes != 32:
        raise InvalidParameterError("seed32 profile accepts exactly 32 bytes")
    if identity_bytes is not None:
        _int(identity_bytes, "identity bytes", 1, params.identity_bytes)
    return len(b"IBME:CHKP:SEED-KEM:v1") + 64 + 8 + 4 + (params.leaf_dimension+256)*(((params.q-1).bit_length()+7)//8)


def research_params(*, message_mode="seed32", lll_policy="checked"):
    """Frozen n=2 executable research candidate; no lattice security grade.

    Values independently checked in experiments/research/chkp_parameter_profile.
    The public arithmetic gate does not promise every private generation fits
    its bounded sampler. Such failures remain explicit and are never retried.
    """
    return CHKPParams(n=2, q=1099511627791, m_bar=45, r_width_squared=1024,
        root_gs_squared_bound=1078992910, parent_width_squared=591288114680,
        leaf_width_squared=82903323983053440, alpha_numerator=4,
        alpha_denominator=1099511627791, message_mode=message_mode,
        lll_policy=lll_policy)
