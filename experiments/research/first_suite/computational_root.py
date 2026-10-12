"""MP12 section 5.2 computational GenTrap, [I | Ahat], m_bar=2*n.

Distinct research profile from the statistical/LHL generator. Gaussian R1/R2
give Ahat*R2+R1; ignoring I, pseudorandomness requires normal-form decision LWE.
Finite sampling/abort and a public, preselected Frobenius cutoff are explicit.
The private qFALL engine only converts the supplied secret to a full basis.
No statistical regularity target is switched off or inherited. No security level.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path

from sage.all import QQ, ZZ

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer
from .delegation_state import validate_basis
from .entropy import CheckedEntropy
from .finite_gaussian import FirstFiniteGaussian, FirstFiniteOptions, interval_upper
from .identity import checked_int
from .private_basis_bridge import convert_private_input
from .root_generation import SCHEMA as ENGINE_SCHEMA

PROFILE = "IBME/MP12-COMPUTATIONAL-ROOT/1"


@dataclass(frozen=True)
class ComputationalRootParams:
    n: int
    q: int
    r_width_squared: int
    uniform_trials: int = 192
    max_entropy_bytes: int = 2**40
    security_claim: str = field(default="none", init=False)
    backend_admitted: bool = field(default=False, init=False)

    def __post_init__(self):
        checked_int(self.n, "computational root n", 2, 64)
        checked_int(self.q, "computational root q", 3, 2**61-1)
        checked_int(self.r_width_squared, "Gaussian R squared width", 4*self.n, 2**80)
        checked_int(self.uniform_trials, "uniform trials", 32, 4096)
        checked_int(self.max_entropy_bytes, "root entropy budget", 1, 2**40)
        if not ZZ(self.q).is_prime(proof=True):
            raise InvalidParameterError("computational root requires proven prime q")
        if self.dimension > 1024 or self.r_entries > 2**20:
            raise InvalidParameterError("private conversion resource domain exceeded")

    @property
    def k(self): return (self.q-1).bit_length()

    @property
    def m_bar(self): return 2*self.n

    @property
    def gadget_columns(self): return self.n*self.k

    @property
    def dimension(self): return self.m_bar+self.gadget_columns

    @property
    def r_entries(self): return self.m_bar*self.gadget_columns

    @property
    def quality_squared(self): return self.r_width_squared*self.r_entries

    @property
    def public_gs_squared_bound(self): return 10*(1+self.quality_squared)


@dataclass(frozen=True, repr=False)
class ComputationalRootResult:
    params: ComputationalRootParams
    basis: object = field(repr=False)
    public_generation_certificate: dict = field(repr=False)

    @property
    def public_gs_squared_bound(self): return self.params.public_gs_squared_bound


class ComputationalRootGenerator:
    def __init__(self, params, binary, *, options=None):
        if not isinstance(params, ComputationalRootParams):
            raise TypeError("explicit computational-root parameters required")
        self.params, self.binary = params, Path(binary)
        self.scalar = FirstFiniteGaussian(params.r_width_squared, params.r_width_squared,
            options=FirstFiniteOptions() if options is None else options)
        if 2*self.scalar.radius >= params.q:
            raise InvalidParameterError("finite Gaussian support not injective modulo q")
        # Markov with rho_{sqrt(2)*s}/rho_s and exp(-pi*d/2). The
        # public Poisson bound proves the per-coordinate factor <= 1/2;
        # thus ideal centered R has norm-cutoff probability <= 2^-d.
        f, theta = self.scalar.field, self.scalar.theta
        factor = f(2).sqrt()*(-f.pi()/2).exp()*(1+f(theta))/(1-f(theta))
        if interval_upper(factor) > QQ(1)/2:
            raise InvalidParameterError("public ideal Gaussian norm-tail bound not certified")
        self.ideal_norm_bad = QQ(1)/2**params.r_entries
        size = (params.k+7)//8
        self.worst_entropy = (params.n**2*params.uniform_trials*size
            + params.r_entries*self.scalar.random_tape_bytes)
        if self.worst_entropy > params.max_entropy_bytes:
            raise InvalidParameterError("whole computational-root entropy budget exceeded")

    def generate(self, *, rng=None):
        if not self.binary.is_file():
            raise InvalidParameterError("private conversion engine missing; no fixture fallback")
        p = self.params
        source = CheckedEntropy(SecureRandom() if rng is None else rng, self.worst_entropy)
        mode = ("system" if rng is None else "deterministic-test"
            if isinstance(rng, DeterministicRandom) else "external-byte-source")
        ahat = [[draw_uniform_integer(source, p.q, max_trials=p.uniform_trials)
            for _ in range(p.n)] for _ in range(p.n)]
        a_bar = [[int(i == j) for j in range(p.n)]+ahat[i] for i in range(p.n)]
        r = [[self.scalar.sample(p.r_width_squared, 0, rng=source)
            for _ in range(p.gadget_columns)] for _ in range(p.m_bar)]
        if sum(x*x for row in r for x in row) > p.quality_squared:
            raise SamplingAbort("computational-root norm cutoff failed; no retry")
        request = dict(schema=ENGINE_SCHEMA, entropy_source=mode, n=p.n, q=p.q,
            m_bar=p.m_bar, a_bar=a_bar, r=r)
        basis = convert_private_input(request, self.binary)
        basis = validate_basis(basis, basis.public.rows, p.q, p.public_gs_squared_bound)
        finite_tv = min(QQ(1), p.r_entries*self.scalar.tv_upper)
        cert = dict(profile=PROFILE, source="MP12 section5.2, PDF25 computational instantiation",
            parameters=asdict(p), n=p.n, q=p.q, k=p.k, m_bar=p.m_bar, dimension=p.dimension,
            public_base_layout="[I_n | uniform Ahat_nxn]", entropy_source=mode,
            native_entropy_generated=False, root_distribution="computational, ignoring public identity block",
            root_security_assumption="normal-form decision LWE; R2 secret and R1 error",
            root_lwe_exact_distribution="independent ideal D_Z,s coordinates; finite implementation separately coupled",
            root_lwe_samples_per_secret=p.n, root_lwe_independent_secret_columns=p.gadget_columns,
            root_lwe_width_squared=p.r_width_squared, root_statistical_regularity_bound=None,
            public_quality_squared=p.quality_squared, public_gs_squared_bound=p.public_gs_squared_bound,
            ideal_root_norm_bad_upper=str(self.ideal_norm_bad),
            r_batch_tv_upper_including_abort=str(finite_tv),
            root_output_coupling_upper_including_norm_abort=str(min(QQ(1), finite_tv+self.ideal_norm_bad)),
            uniform_matrix_abort_upper=str(min(QQ(1), QQ(p.n**2)/2**p.uniform_trials)),
            worst_entropy_bytes=self.worst_entropy, actual_entropy_bytes=source.bytes_used,
            finite_options=asdict(self.scalar.options), scalar_radius=self.scalar.radius,
            complete_kernel_and_defining_relation_checked=True,
            qfall_revision="b8eb4842fb80c36f7f3494930ea316472cb75793",
            basis_conversion_supplies_no_entropy=True, parameters_are_formal=False,
            security_claim="none", backend_admitted=False,
            exclusions=["normal-form LWE attack estimate", "multi-column reduction loss",
                "HIBE key-distribution/model mapping", "side channels", "native conversion resource failure"])
        return ComputationalRootResult(p, basis, cert)
