"""Full, bounded Yu byte-domain research configuration; not security parameters."""
from dataclasses import dataclass
from functools import lru_cache
from typing import ClassVar

VERSION = "Yu2026-IBS/1"


@dataclass(frozen=True)
class YuParams:
    n: int = 1
    q: int = 3
    random_rows: int = 3
    m1: int = 3
    m2: int = 12
    hadamard_scale: int = 8
    max_uniform_trials: int = 192
    prf_dimension: int = 1
    prf_columns: int = 1
    prf_modulus_bits: int = 5
    prf_ticket_bits: int = 32
    prf_gaussian_width: int = 2
    identity_max_bytes: int = 1
    message_max_bytes: int = 1
    salt_bits: int = 4
    gamma_squared: int = 32768
    delta_squared: int = 67108864
    max_vectors: int = 32
    epsilon_bits: int = 16
    postprocess: bool = True
    max_users: int = 16
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False
    parameters_are_formal: ClassVar[bool] = False

    def __post_init__(self):
        bounds = dict(n=(1,4), q=(3,65537), random_rows=(1,64), m1=(1,64),
            m2=(1,64), hadamard_scale=(1,1024), max_uniform_trials=(1,4096),
            prf_dimension=(1,8), prf_columns=(1,8), prf_modulus_bits=(1,16),
            prf_ticket_bits=(1,64), prf_gaussian_width=(1,8),
            identity_max_bytes=(1,4), message_max_bytes=(1,4), salt_bits=(1,32),
            gamma_squared=(1,10**12), delta_squared=(1,10**12),
            max_vectors=(1,4096), epsilon_bits=(2,128), max_users=(1,64))
        for name,(lo,hi) in bounds.items():
            value=getattr(self,name)
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError(f"Yu invalid integer parameter: {name}")
        if type(self.postprocess) is not bool:
            raise ValueError("Yu postprocess must be bool")
        if self.q % 2 == 0 or any(self.q % d == 0 for d in range(3, int(self.q**0.5)+1, 2)):
            raise ValueError("Yu modulus must be an odd prime")
        ell=(self.q-1).bit_length()
        if not self.m1 >= self.random_rows > self.n*ell:
            raise ValueError("AP09 requires m1 >= random_rows > n log2(q)")
        if self.m2 < 2*self.n*ell+2*self.random_rows:
            raise ValueError("AP09 second block is too short")
        width=1 << ((self.m2-2*self.n*ell).bit_length()-1)
        if 4*self.random_rows*self.m2 > self.hadamard_scale**2*width:
            raise ValueError("AP09 finite quality gate fails")
        if self.signature_dimension > 64 or self.max_vectors < self.m+self.w:
            raise ValueError("Yu basis dimension or RandBasis capacity exceeds budget")
        if self.signing_input_bits > 128:
            raise ValueError("Yu encoded input exceeds BPR bit budget")
        if self.prf_columns*self.prf_dimension > 64 or self.key_bits(self.signing_input_bits) > 8192:
            raise ValueError("Yu BPR key/output exceeds circuit budget")

    @property
    def m(self): return self.m1+self.m2
    @property
    def w(self): return self.n*(self.q-1).bit_length()
    @property
    def signature_dimension(self): return self.m+2*self.w
    @property
    def identity_bits(self): return 32+8*self.identity_max_bytes
    @property
    def message_bits(self): return 32+8*self.message_max_bytes
    @property
    def signing_input_bits(self): return self.identity_bits+self.message_bits+self.salt_bits
    @property
    def output_bits(self): return self.prf_columns*self.prf_dimension
    def key_bits(self, inputs):
        return self.prf_dimension*self.prf_columns*self.prf_modulus_bits+inputs*self.prf_dimension**2*self.prf_ticket_bits
    def raw(self): return raw_params(self)


@lru_cache(maxsize=16)
def raw_params(params):
    from experiments.research.candidates.yu import bpr, standalone
    from experiments.research.chkp_genbasis import AP09Parameters
    p=params
    def spec(inputs):
        return bpr.make_spec(bpr.Params(inputs,p.prf_dimension,p.prf_columns,
            p.prf_modulus_bits,p.prf_ticket_bits,p.prf_gaussian_width))
    return standalone.Params(AP09Parameters(p.n,p.q,p.random_rows,p.m1,p.m2,
        p.hadamard_scale,p.max_uniform_trials),spec(p.identity_bits),
        spec(p.signing_input_bits),p.message_bits,p.salt_bits,p.gamma_squared,
        p.delta_squared,p.max_vectors,p.epsilon_bits,p.postprocess)


def preflight(params):
    if type(params) is not YuParams:
        raise TypeError("expected YuParams")
    # Build canonical public Gaussian tables only; never keys, files or entropy.
    return params.raw()
