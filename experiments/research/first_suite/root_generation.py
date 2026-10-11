"""Private-input MP12 root generation with system bytes and finite Gaussian R.

qFALL public API performs the unmodified full-basis conversion. Independently
check A=[Abar|G-Abar R], full kernel, and a public Frobenius-based GS bound.
Actual finite R min-entropy gives a conditional leftover-hash regularity bound;
uniform/R sampling aborts are separate. No LWE security level is implied.
"""

from dataclasses import asdict, dataclass, field
import json
from math import isqrt
from pathlib import Path
import subprocess

from sage.all import QQ, ZZ, matrix

from ibme.core.randomness import SecureRandom, DeterministicRandom
from ibme.core.errors import InvalidParameterError
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference
from experiments.research.gaussian_reference import draw_uniform_integer

from .entropy import CheckedEntropy
from .finite_gaussian import FirstFiniteGaussian, FirstFiniteOptions
from .identity import checked_int

SCHEMA = "IBME/MP12-SECRET-ROOT/1"
MAX_INPUT_BYTES, MAX_OUTPUT_BYTES = 32 * 2**20, 64 * 2**20
MAX_DIMENSION = 1024


@dataclass(frozen=True)
class MP12RootParams:
    n: int
    q: int
    m_bar: int
    r_width_squared: int
    regularity_bits: int | None = 64
    uniform_trials: int = 192
    max_entropy_bytes: int = 2**40
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)

    def __post_init__(self):
        checked_int(self.n, "root n", 1, 64)
        checked_int(self.q, "root q", 2, 2**61 - 1)
        checked_int(self.m_bar, "root m_bar", 1, 2048)
        checked_int(self.r_width_squared, "R squared width", 1, 2**80)
        checked_int(self.uniform_trials, "uniform trials", 32, 4096)
        checked_int(self.max_entropy_bytes, "root entropy bytes", 1, 2**40)
        if self.regularity_bits is not None:
            checked_int(self.regularity_bits, "regularity bits", 8, 192)
        if self.dimension > MAX_DIMENSION or self.m_bar * self.n * self.k > 2**20:
            raise InvalidParameterError("root full-basis/matrix resource domain exceeded")
        if not ZZ(self.q).is_prime(proof=True):
            raise InvalidParameterError("root modulus must be a proven prime")

    @property
    def k(self): return (self.q - 1).bit_length()

    @property
    def dimension(self): return self.m_bar + self.n * self.k


def regularity_upper(params, mass_lower):
    """Conservative LHL column union, conditional on all finite draws succeed.

    If 2*radius<q, finite integer support is injective modulo q. For independent
    coordinates, max P[R] <= mass_lower^-m_bar. Universal Abar hashing gives
    nk*sqrt(q^n/mass_lower^m_bar); omit the 1/2 to remain conservative.
    """
    mass = QQ(mass_lower)
    if mass <= 1:
        return QQ(1)
    value = QQ(params.q)**params.n / mass**params.m_bar
    # Keep enough upward-rounding margin also for the declared 128/192-bit
    # targets. A fixed 128-bit sqrt grid could never certify these targets.
    precision = max(128, (params.regularity_bits or 64) + 64)
    scale = 2**(2*precision)
    scaled = int((value * scale).ceil())
    root = isqrt(scaled)
    if root * root < scaled: root += 1
    return min(QQ(1), QQ(params.n * params.k * root) / 2**precision)


@dataclass(frozen=True, repr=False)
class PrivateRootResult:
    params: MP12RootParams
    basis: KernelBasis = field(repr=False)
    public_gs_squared_bound: int
    public_generation_certificate: dict = field(repr=False)
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)


class MP12RootGenerator:
    def __init__(self, params, binary, *, options=None):
        if not isinstance(params, MP12RootParams):
            raise TypeError("explicit MP12 root parameters required")
        self.params, self.binary = params, Path(binary)
        self.scalar = FirstFiniteGaussian(params.r_width_squared, params.r_width_squared,
                                         options=FirstFiniteOptions() if options is None else options)
        if 2 * self.scalar.radius >= params.q:
            raise InvalidParameterError("finite R support is not injective modulo q")
        self.regularity = regularity_upper(params, self.scalar.acceptance_mass_lower)
        if params.regularity_bits is not None and self.regularity > QQ(1)/2**params.regularity_bits:
            raise InvalidParameterError("finite R entropy does not meet root regularity target")
        uniform_size = (params.k + 7)//8
        self.worst_entropy = (params.n * params.m_bar * params.uniform_trials * uniform_size
                              + params.m_bar * params.n * params.k * self.scalar.random_tape_bytes)
        if self.worst_entropy > params.max_entropy_bytes:
            raise InvalidParameterError("whole root entropy upper bound exceeds profile budget")

    def generate(self, *, rng=None):
        p = self.params
        if not self.binary.is_file():
            raise InvalidParameterError("private root engine not built; no public-fixture fallback")
        source = CheckedEntropy(SecureRandom() if rng is None else rng, self.worst_entropy)
        mode = "system" if rng is None else "deterministic-test" if isinstance(rng, DeterministicRandom) else "external-byte-source"
        a_bar = [[draw_uniform_integer(source, p.q, max_trials=p.uniform_trials) for _ in range(p.m_bar)] for _ in range(p.n)]
        r = [[self.scalar.sample(p.r_width_squared, 0, rng=source) for _ in range(p.n * p.k)] for _ in range(p.m_bar)]
        request = dict(schema=SCHEMA, entropy_source=mode, n=p.n, q=p.q, m_bar=p.m_bar, a_bar=a_bar, r=r)
        raw = json.dumps(request, separators=(",", ":")).encode()
        if len(raw) > MAX_INPUT_BYTES:
            raise InvalidParameterError("private root request exceeds byte budget")
        result = subprocess.run([str(self.binary)], input=raw, capture_output=True, timeout=60)
        if result.returncode or len(result.stdout) > MAX_OUTPUT_BYTES:
            raise InvalidParameterError("private root conversion failed; secret diagnostics withheld")
        try:
            output = json.loads(result.stdout, object_pairs_hook=unique_fields)
            root = validate_output(request, output)
        except (ValueError, TypeError, KeyError):
            # int()/JSON diagnostics may contain private serialized integers.
            raise InvalidParameterError("private root output failed canonical/algebra validation") from None
        bound = 10 * (1 + p.m_bar * p.n * p.k * self.scalar.radius**2)
        # A column-norm sufficient certificate avoids GS when possible; exact
        # GS is retained otherwise. Do not use measured geometry to choose s.
        norms = [sum(row[j]**2 for row in root.basis_rows) for j in range(p.dimension)]
        if max(norms) > bound:
            star, _ = matrix(QQ, root.basis_rows).transpose().gram_schmidt()
            if max(row.dot_product(row) for row in star.rows()) > bound:
                raise InvalidParameterError("private root exceeds public MP12 GS bound")
        abort = min(QQ(1), QQ(p.n * p.m_bar)/2**p.uniform_trials
                    + p.m_bar * p.n * p.k * self.scalar.abort_upper)
        cert = dict(schema=SCHEMA, qfall_revision="b8eb4842fb80c36f7f3494930ea316472cb75793",
                    parameters=asdict(p), k=p.k, dimension=p.dimension,
                    entropy_source=mode, native_entropy_generated=False, r_distribution="finite Gaussian D_Z,s,0, bounded rejection",
                    finite_options=asdict(self.scalar.options),
                    r_width_squared=p.r_width_squared, r_support_radius=self.scalar.radius,
                    r_conditional_mass_lower=str(self.scalar.acceptance_mass_lower),
                    root_regular_distance_upper_conditional=str(self.regularity),
                    regularity_upward_rounding_bits=max(128, (p.regularity_bits or 64) + 64),
                    root_abort_upper=str(abort), worst_entropy_bytes=self.worst_entropy,
                    r_batch_vs_ideal_Gaussian_tv_upper_including_abort=str(min(
                        QQ(1), p.m_bar * p.n * p.k * self.scalar.tv_upper)),
                    actual_entropy_bytes=source.bytes_used, public_gs_squared_bound=bound,
                    complete_kernel_and_defining_relation_checked=True,
                    security_claim="none", backend_admitted=False, parameters_are_formal=False,
                    regularity_does_not_certify_LWE_difficulty=True)
        return PrivateRootResult(p, root, bound, cert)


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate private output field")
        result[key] = value
    return result


def validate_output(request, output):
    keys = {"schema", "entropy_source", "n", "q", "k", "m_bar", "a", "basis", "native_entropy_generated", "security_claim", "backend_admitted"}
    if type(output) is not dict or set(output) != keys:
        raise ValueError("private root schema mismatch")
    p_n, q, m_bar = request["n"], request["q"], request["m_bar"]
    k, dimension = (q - 1).bit_length(), m_bar + p_n * (q - 1).bit_length()
    if (output["schema"] != SCHEMA or output["entropy_source"] != request["entropy_source"]
            or output["native_entropy_generated"] is not False or output["security_claim"] != "none"
            or output["backend_admitted"] is not False):
        raise ValueError("private root role/admission mismatch")
    for name, value in (("n", p_n), ("q", q), ("k", k), ("m_bar", m_bar)):
        if type(output[name]) is not int or output[name] != value:
            raise ValueError("private root dimensions mismatch")
    def rows(group, height, residues=False):
        if type(group) is not list or len(group) != height:
            raise ValueError("bad private root row count")
        result = []
        for row in group:
            if type(row) is not list or len(row) != dimension:
                raise ValueError("bad private root column count")
            values = []
            for raw in row:
                if type(raw) is not str or not 1 <= len(raw) <= 100:
                    raise ValueError("bad private integer encoding")
                value = int(raw)
                if str(value) != raw or abs(value).bit_length() > 256 or (residues and not 0 <= value < q):
                    raise ValueError("noncanonical private integer")
                values.append(value)
            result.append(tuple(values))
        return tuple(result)
    a, b = rows(output["a"], p_n, True), rows(output["basis"], dimension)
    expected = tuple(tuple(request["a_bar"][i]) + tuple(
        ((2**(j % k) if j//k == i else 0) - sum(request["a_bar"][i][t] * request["r"][t][j] for t in range(m_bar))) % q
        for j in range(p_n * k)) for i in range(p_n))
    if a != expected: raise ValueError("private MP12 defining relation mismatch")
    return KernelBasis(ModMatrixReference(a, q), b)
