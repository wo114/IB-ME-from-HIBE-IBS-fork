"""MP12 section5.5 Algorithm4 DelTrap with the finite/CSPRNG GPV oracle.

Research primitive, not the original CHKP RandBasis or an admitted HIBE.
For [A|A1] with exactly nk final columns, sample A*R'=G-A1. Extra extension
columns belong to A. No old trapdoor is padded and returned to the receiver.
The private key stores a rectangular G-trapdoor. A full basis conversion is
optional arithmetic reuse, not MP12 Algorithm3 perturbation sampling.
"""

from dataclasses import dataclass, field
from fractions import Fraction
from hashlib import sha256
import json

from sage.all import QQ, ZZ, matrix

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.randomness import SecureRandom
from experiments.research.chkp_basis import ModMatrixReference, ext_basis
from experiments.research.gaussian_reference import SamplingAbort
from .entropy import CheckedEntropy
from .finite_gpv import FirstFiniteGPV
from .root_generation import SCHEMA as ROOT_SCHEMA, unique_fields
from .private_basis_bridge import convert_private_input

SCHEMA = "IBME/MP12-DELEGATED-GTRAPDOOR/1"
MAX_WIRE, MAX_ENTRIES = 16*2**20, 2**20


def public_binding(public):
    raw=json.dumps(dict(q=public.q,rows=public.rows),separators=(",", ":")).encode()
    return sha256(SCHEMA.encode()+b"\x00"+raw).hexdigest()


@dataclass(frozen=True, repr=False)
class CompactGTrapdoor:
    public: ModMatrixReference
    r_rows: tuple = field(repr=False)
    source_width_squared: Fraction
    security_claim: str = field(default="none",init=False)
    backend_admitted: bool = field(default=False,init=False)

    def __post_init__(self):
        if not isinstance(self.public,ModMatrixReference) or not ZZ(self.public.q).is_prime(proof=True):
            raise InvalidParameterError("explicit prime-modulus public matrix required")
        if isinstance(self.source_width_squared,bool) or not isinstance(self.source_width_squared,(int,Fraction)):
            raise InvalidParameterError("exact declared delegation width required")
        width=Fraction(self.source_width_squared)
        if not 0<width<=2**80 or max(width.numerator.bit_length(),width.denominator.bit_length())>256:
            raise InvalidParameterError("delegation width exceeds private format domain")
        object.__setattr__(self,"source_width_squared",width)
        n,p,w=self.public.nrows,self.prefix_dimension,self.gadget_columns
        if not 1<=n<=64 or p<n or self.public.ncols>1024 or p*w>MAX_ENTRIES or 37*p*w+8192>MAX_WIRE:
            raise InvalidParameterError("compact trapdoor dimension/whole-wire domain exceeded")
        if not isinstance(self.r_rows,(tuple,list)) or len(self.r_rows)!=p:
            raise InvalidParameterError("bad compact trapdoor height")
        rows=[]
        for row in self.r_rows:
            if not isinstance(row,(tuple,list)) or len(row)!=w or any(type(x) is not int or abs(x).bit_length()>256 for x in row):
                raise InvalidParameterError("bad compact trapdoor row/entry")
            rows.append(tuple(row))
        rows=tuple(rows)
        object.__setattr__(self,"r_rows",rows)
        if any(sum(row[j]**2 for row in rows)>width*p for j in range(w)):
            raise InvalidParameterError("compact trapdoor exceeds declared Gaussian-column norm cutoff")
        a=matrix(ZZ,[row[:p] for row in self.public.rows])
        tail=matrix(ZZ,[row[p:] for row in self.public.rows])
        k=(self.public.q-1).bit_length()
        gadget=matrix(ZZ,n,w,lambda i,j:2**(j%k) if j//k==i else 0)
        if any(int(x)%self.public.q for x in (a*matrix(ZZ,rows)+tail-gadget).list()):
            raise InvalidParameterError("compact trapdoor defining relation failed")

    @property
    def gadget_columns(self): return self.public.nrows*(self.public.q-1).bit_length()

    @property
    def prefix_dimension(self): return self.public.ncols-self.gadget_columns

    @property
    def public_gs_squared_bound(self):
        # MP12 Lemma5.3 plus binary gadget and public column cutoff. A tighter
        # spectral bound is NOT substituted without its own source/event gate.
        return 10*(1+self.gadget_columns*self.prefix_dimension*self.source_width_squared)

    def to_basis(self,binary):
        if any(abs(x)>2**48 for row in self.r_rows for x in row):
            raise InvalidParameterError("compact key outside native conversion entry domain")
        request=dict(schema=ROOT_SCHEMA,entropy_source="external-byte-source",n=self.public.nrows,
            q=self.public.q,m_bar=self.prefix_dimension,
            a_bar=[list(row[:self.prefix_dimension]) for row in self.public.rows],r=[list(row) for row in self.r_rows])
        result=convert_private_input(request,binary)
        if result.public!=self.public:
            raise InvalidParameterError("converted basis differs from delegated public matrix")
        from .delegation_state import validate_basis
        return validate_basis(result,self.public.rows,self.public.q,self.public_gs_squared_bound)

    def to_bytes(self):
        value=dict(schema=SCHEMA,public_binding=public_binding(self.public),
            source_width_squared=str(self.source_width_squared),
            r=[[str(x) for x in row] for row in self.r_rows])
        raw=json.dumps(value,sort_keys=True,separators=(",", ":")).encode()
        if len(raw)>MAX_WIRE:raise SerializationError("compact private wire exceeds budget")
        return raw

    @classmethod
    def from_bytes(cls,data,*,expected_public,expected_width_squared):
        if type(data) is not bytes or not 1<=len(data)<=MAX_WIRE:
            raise SerializationError("compact private wire length/type invalid")
        if (not isinstance(expected_public,ModMatrixReference) or isinstance(expected_width_squared,bool)
                or not isinstance(expected_width_squared,(int,Fraction))):
            raise SerializationError("explicit exact compact private scope required")
        try:
            raw=json.loads(data,object_pairs_hook=unique_fields)
            if set(raw)!={"schema","public_binding","source_width_squared","r"} or raw["schema"]!=SCHEMA:
                raise ValueError("schema")
            if raw["public_binding"]!=public_binding(expected_public) or raw["source_width_squared"]!=str(Fraction(expected_width_squared)):
                raise ValueError("scope")
            n=expected_public.nrows;w=n*(expected_public.q-1).bit_length();p=expected_public.ncols-w
            if p<1 or p*w>MAX_ENTRIES or not isinstance(raw["r"],list) or len(raw["r"])!=p:
                raise ValueError("shape")
            rows=[]
            for row in raw["r"]:
                if not isinstance(row,list) or len(row)!=w:raise ValueError("shape")
                values=[]
                for text in row:
                    if type(text) is not str or not 1<=len(text)<=79:raise ValueError("integer")
                    v=int(text)
                    if str(v)!=text or abs(v).bit_length()>256:raise ValueError("integer")
                    values.append(v)
                rows.append(tuple(values))
            result=cls(expected_public,tuple(rows),Fraction(expected_width_squared))
            if result.to_bytes()!=data:raise ValueError("canonical wire")
            return result
        except (ValueError,TypeError,KeyError,InvalidParameterError):
            raise SerializationError("invalid compact private wire; diagnostics withheld") from None


def public_gpv_tv_upper(sampler):
    """Conservative public range bound, not a published secret GS profile."""
    p,opts,b=sampler.dimension,sampler.scalars[0].options,sampler.epsilon_bits
    denominator=2**b-2*p-1
    geometry=QQ(p)/denominator if denominator>0 else QQ(1)
    count=2*opts.max_radius+2
    e=(opts.mass_bits-1).bit_length()
    quant=count*(QQ(2)**(e+8-opts.precision_bits)+QQ(1)/2**opts.mass_bits)
    abort=QQ(1)/2**opts.gaussian_abort_bits+QQ(opts.max_gaussian_trials)/2**opts.max_uniform_trials
    upper=min(QQ(1),geometry+p*(QQ(1)/2**opts.tail_bits+quant+abort))
    if sampler.tv_upper>upper:raise InvalidParameterError("public finite-GPV range bound inconsistent")
    return upper


class FiniteDelTrap:
    """Sample independent appropriate cosets; norm failure aborts whole call."""
    def __init__(self,sampler,tail,*,max_entropy_bytes=2**40):
        if not isinstance(sampler,FirstFiniteGPV) or not isinstance(tail,ModMatrixReference):
            raise InvalidParameterError("finite GPV oracle and explicit terminal block required")
        q,n,p=sampler.basis.public.q,sampler.basis.public.nrows,sampler.dimension
        w=n*(q-1).bit_length()
        if tail.q!=q or (tail.nrows,tail.ncols)!=(n,w):
            raise InvalidParameterError("DelTrap requires exactly nk final columns")
        self.sampler,self.public=sampler,sampler.basis.public.append(tail)
        self.width=Fraction(str(sampler.width_squared));self.w=w
        if type(max_entropy_bytes) is not int or not 1<=max_entropy_bytes<=2**40:
            raise InvalidParameterError("invalid whole DelTrap entropy budget")
        self.worst_entropy=w*sampler.random_tape_bytes
        if self.worst_entropy>max_entropy_bytes:
            raise InvalidParameterError("whole DelTrap entropy budget exceeded before sampling")
        # Admit private shape/format before invoking the oracle, even when
        # constructor geometry already passed independently.
        if n>64 or self.public.ncols>1024 or p*w>MAX_ENTRIES or 37*p*w+8192>MAX_WIRE:
            raise InvalidParameterError("whole compact key resources exceed format domain")
        k=(q-1).bit_length()
        self.targets=tuple(tuple(((2**(j%k) if j//k==i else 0)-tail.rows[i][j])%q for i in range(n)) for j in range(w))
        eps=QQ(1)/2**sampler.epsilon_bits
        self.ideal_norm_bad_upper=min(QQ(1),w*(1+eps)/(1-eps)*QQ(2)**(-p))
        self.public_tv=min(QQ(1),w*public_gpv_tv_upper(sampler))
        self.last_entropy_bytes=None

    def sample(self,*,rng=None):
        source=CheckedEntropy(SecureRandom() if rng is None else rng,self.worst_entropy)
        columns=[]
        try:
            for target in self.targets:
                column=self.sampler.sample(target,rng=source)
                if sum(x*x for x in column)>self.width*self.sampler.dimension:
                    raise SamplingAbort("DelTrap column norm cutoff exceeded; whole call aborted")
                columns.append(column)
        finally:
            self.last_entropy_bytes=source.bytes_used
        rows=tuple(tuple(col[i] for col in columns) for i in range(self.sampler.dimension))
        return CompactGTrapdoor(self.public,rows,self.width)

    def certificate(self):
        return dict(profile=SCHEMA,source="MP12 section5.5 Algorithm4/Lemma5.7; finite GPV and explicit column norm cutoff",
            prefix_dimension=self.sampler.dimension,gadget_columns=self.w,
            full_delegated_dimension=self.public.ncols,source_width_squared=str(self.width),
            ideal_norm_bad_union_upper=str(self.ideal_norm_bad_upper),
            actual_vs_bounded_ideal_output_tv_upper_public=str(self.public_tv),
            whole_failure_upper_public=str(min(QQ(1),self.ideal_norm_bad_upper+self.public_tv)),
            rank_detection_required=False,tobasis_required=False,old_trapdoor_padded_and_returned=False,
            finite_error_includes_sampler_abort=True,source_randomness_assumption="independent uniform bytes",
            native_qfall_or_Sage_entropy_used=False,security_claim="none",backend_admitted=False,
            constant_time=False,hibe_model_mapping_pending=True)


def split_extension(root_basis,block):
    """Extra columns enter the sampling prefix; final nk columns are A1."""
    q,n=root_basis.public.q,root_basis.public.nrows
    w=n*(q-1).bit_length()
    if block.q!=q or block.nrows!=n or block.ncols<w:
        raise InvalidParameterError("extension shorter than the mandatory gadget-width block")
    extra=block.ncols-w
    prefix=root_basis if extra==0 else ext_basis(root_basis,ModMatrixReference(tuple(row[:extra] for row in block.rows),q))
    return prefix,ModMatrixReference(tuple(row[extra:] for row in block.rows),q)
