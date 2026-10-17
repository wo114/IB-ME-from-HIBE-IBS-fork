"""A single complete H/G parameter group, with exact portable admission gates.

These are functionality/resource gates, not security admission. The fixed
finite sampler options belong to this version, as do all derived widths.
"""

from dataclasses import asdict, dataclass
from fractions import Fraction
import json

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.hibe.chkp.params import _prime64, _unique
from ibme.lattice.chkp.joint_parameters import evaluate_noise, smoothing_factor
from . import BACKEND_VERSION

MAGIC = b"IBME:MP12-STRUCTURED-HG:PARAMS:v1\0"
MAGIC192 = b"IBME:MP12-STRUCTURED-HG:PARAMS:v2\0"
FINITE192_VERSION = "mp12-structured-hg-finite192-v2"


def output_width(w, bound, *, epsilon_bits=128):
    r = 4*smoothing_factor(w, epsilon_bits)
    return max(7*r*(1+bound), 10*r*(w+bound))


@dataclass(frozen=True)
class StructuredHIBEParams:
    n: int = 2
    q: int = 549755813911
    root_r_squared: int = 16
    q_alpha: int = 4
    identity_bytes: int = 86
    max_receivers: int = 2
    max_children: int = 2

    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False
    version = BACKEND_VERSION
    parameter_magic = MAGIC
    sampler_epsilon_bits = 128
    decode_error_bits = 128
    finite_option_values = ()
    noise_option_values = (("tail_bits", 128), ("mass_bits", 256),
                          ("precision_bits", 320), ("max_radius", 8192))
    finite_sampler_description = "IBME/MP12-STRUCTURED/1/default-options/epsilon128/trials512"
    noise_description = "rounded-continuous/qalpha/tail128/mass256/precision320/radius8192"
    probability_reporting_bits = None

    def __post_init__(self):
        for name, low, high in (("n", 2, 128), ("q", 3, 2**61-1),
                ("root_r_squared", 1, 2**80), ("q_alpha", 1, 1024),
                ("identity_bytes", 1, 86), ("max_receivers", 1, 8), ("max_children", 1, 8)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise InvalidParameterError(f"structured HIBE {name} exact integer domain")
        if self.root_r_squared < 4*self.n or not _prime64(self.q) or self.q % 2 == 0:
            raise InvalidParameterError("structured HIBE requires its prime/root-width conditions")
        # Same bounds as the unchanged A3 structured tools. In particular a
        # high-dimensional root fitting A3 does not imply HIBE delegation fits.
        if (self.leaf_dimension-self.w > 512 or self.leaf_dimension > 8192
                or (self.leaf_dimension-self.w)*self.w > 2**22):
            raise InvalidParameterError("structured HIBE complete H/G prefix resource limit")
        if self.leaf_width_squared > 2**192 or self.parent_bound > 2**256:
            raise InvalidParameterError("structured HIBE complete width chain resource limit")
        # FixedSeedState reserves 37 bytes per signed 256-bit coordinate;
        # retain room for public contexts, R, framing and failed addresses.
        leaf_bytes = 256*self.leaf_dimension*37
        if (self.max_children*leaf_bytes > 15*2**20
                or self.max_receivers*self.max_children*leaf_bytes > 24*2**20):
            raise InvalidParameterError("structured HIBE whole fixed-tree snapshot resource limit")
        if not self.noise_budget()["conditional_noise_sufficient"]:
            raise InvalidParameterError("structured HIBE fails the complete conditional noisy-decode gate")

    @property
    def w(self): return self.n*(self.q-1).bit_length()

    @property
    def m(self): return 2*self.n+self.w

    @property
    def root_bound(self): return 2*self.n*self.w*self.root_r_squared

    @property
    def parent_sample_dimension(self): return 2*self.m-self.w

    @property
    def parent_width_squared(self):
        return output_width(self.w, self.root_bound, epsilon_bits=self.sampler_epsilon_bits)

    @property
    def parent_bound(self): return self.parent_sample_dimension*self.w*self.parent_width_squared

    @property
    def leaf_width_squared(self):
        return output_width(self.w, self.parent_bound, epsilon_bits=self.sampler_epsilon_bits)

    @property
    def leaf_dimension(self): return 3*self.m

    @property
    def alpha(self): return Fraction(self.q_alpha, self.q)

    @property
    def max_message_bytes(self): return 32

    def sampling_options(self):
        from ibme.lattice.matrix_sampling.scalar import MatrixFiniteOptions
        return MatrixFiniteOptions(**dict(self.finite_option_values))

    def noise_options(self):
        return dict(self.noise_option_values)

    def noise_budget(self):
        return evaluate_noise(q=self.q, dimension=self.leaf_dimension,
            width_squared=self.leaf_width_squared, alpha=self.alpha,
            error_bits=self.decode_error_bits, seed_bits=256, encapsulations=2**20)

    def record(self):
        return dict(version=self.version, parameters=asdict(self),
            w=self.w, m=self.m, root_R_bound=str(self.root_bound),
            parent_sample_dimension=self.parent_sample_dimension,
            parent_width_squared=str(self.parent_width_squared),
            parent_R_bound=str(self.parent_bound), leaf_dimension=self.leaf_dimension,
            leaf_width_squared=str(self.leaf_width_squared),
            finite_sampler=self.finite_sampler_description,
            noise=self.noise_description,
            leaf_entropy_budget=str(2**48),
            security_claim="none", backend_admitted=False, parameters_are_formal=False)

    def to_bytes(self):
        return self.parameter_magic+json.dumps(self.record(), sort_keys=True, separators=(",", ":")).encode("ascii")

    @classmethod
    def from_bytes(cls, raw):
        if (type(raw) is not bytes or not len(cls.parameter_magic) < len(raw) <= 4096
                or not raw.startswith(cls.parameter_magic)):
            raise SerializationError("structured HIBE parameter wire/version")
        try:
            def reject(value): raise ValueError("noninteger structured HIBE parameter")
            def integer(value):
                if len(value) > 100: raise ValueError("structured HIBE parameter integer budget")
                return int(value)
            record = json.loads(raw[len(cls.parameter_magic):].decode("ascii"), object_pairs_hook=_unique,
                parse_int=integer, parse_float=reject, parse_constant=reject)
            result = cls(**record["parameters"])
            if result.to_bytes() != raw:
                raise ValueError("noncanonical or inconsistent structured HIBE parameters")
            return result
        except (KeyError, TypeError, ValueError, RecursionError, InvalidParameterError) as exc:
            raise SerializationError("invalid structured HIBE parameter snapshot") from exc


@dataclass(frozen=True)
class StructuredHIBEParams192(StructuredHIBEParams):
    """Explicit v2 finite recipe, still an insecure n2 research profile.

    The prime near 2^40 keeps the EXISTING 128-trial RO/KEM residue rejection
    terms small; the recipe does not silently raise those shared limits.
    No inherited dataclass field is added, so all v1 suite snapshots stay valid.
    """

    q: int = 1099511627689

    version = FINITE192_VERSION
    parameter_magic = MAGIC192
    sampler_epsilon_bits = 192
    decode_error_bits = 160
    finite_option_values = (("tail_bits", 192), ("gaussian_abort_bits", 192),
        ("mass_bits", 320), ("precision_bits", 384), ("max_uniform_trials", 256))
    noise_option_values = (("tail_bits", 192), ("mass_bits", 320),
                          ("precision_bits", 384), ("max_radius", 8192))
    finite_sampler_description = "IBME/MP12-STRUCTURED/1/finite192-options/epsilon192/trials512"
    noise_description = "rounded-continuous/qalpha/tail192/mass320/precision384/radius8192"
    probability_reporting_bits = 384

    def record(self):
        result = super().record()
        result["finite_recipe"] = dict(epsilon_bits=192, scalar_tail_bits=192,
            scalar_abort_bits=192, scalar_mass_bits=320, precision_bits=384,
            scalar_uniform_trials=256, root_uniform_trials=256,
            perturbation_trials=512, noise_tail_bits=192, noise_mass_bits=320,
            noise_precision_bits=384, decode_error_bits=160,
            ciphertext_uniform_trials=128, oracle_uniform_trials=128,
            probability_reporting_bits=384)
        return result


def load_structured_parameters(raw):
    """Version dispatch for object containers; individual parameter readers are strict."""
    if type(raw) is bytes:
        for params_type in (StructuredHIBEParams, StructuredHIBEParams192):
            if raw.startswith(params_type.parameter_magic):
                return params_type.from_bytes(raw)
    raise SerializationError("unknown structured HIBE parameter version")
