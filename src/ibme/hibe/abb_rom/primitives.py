"""ABB10 CRYPTO 2010 SampleR and BasisDel, column-basis convention.

SampleR retries whole IID Gaussian matrices on modular singularity. BasisDel
completes R*T inside the target kernel, then executes real finite RandBasis.
Input/result are algebraic/finite research objects, not a complete HIBE or the
paper's full ROM security theorem. Old finite/ToBasis guards are unchanged.
"""

from dataclasses import dataclass,field
from fractions import Fraction
from itertools import islice

from sage.all import GF,QQ,ZZ,matrix

from ibme.core.errors import InvalidParameterError
from ibme.core.randomness import SecureRandom
from ibme.lattice.research import (FirstFiniteOptions,FirstFiniteGaussian,FirstFiniteGPV,
    KernelBasis,ModMatrixReference,SamplingAbort)
from experiments.research.chkp_basis import complete_kernel_basis,gram_schmidt_squared_lengths
from experiments.research.chkp_tobasis import to_basis,MAX_DIMENSION,MAX_ENTRY_BITS
from experiments.research.first_suite.finite_randbasis import FirstFiniteRandBasis
from experiments.research.first_suite.entropy import CheckedEntropy
from experiments.research.first_suite.finite_gaussian import capped_exp_minus_pi,interval_upper
from experiments.research.ibme_root_sampler_audit import checked_sage_lll
from ibme.lattice.matrix_sampling import (MatrixFiniteOptions,MatrixFiniteGaussian,
    MatrixFiniteGPV,MatrixFiniteRandBasis,MatrixBasisLimits,matrix_to_basis,matrix_checked_lll)
from ibme.lattice.matrix_sampling.basis import LEGACY_BASIS_LIMITS


def exact_int(value,name,low,high):
    if isinstance(value,bool) or not isinstance(value,(int,type(ZZ(0)))) or not low<=value<=high:
        raise InvalidParameterError(f"{name} requires bounded exact integer")
    return int(value)


def checked_width(value,maximum):
    if isinstance(value,bool) or not isinstance(value,(int,Fraction,type(ZZ(0)),type(QQ(0)))):
        raise InvalidParameterError("exact Gaussian squared width required")
    result=QQ(value)
    if not 1<=result<=maximum:raise InvalidParameterError("width outside explicitly selected finite profile")
    return result


def exact_width(value):
    return checked_width(value,2**80)


def signed_square(value,dimension,*,max_entry_bits=MAX_ENTRY_BITS):
    if hasattr(value,"rows") and callable(value.rows):
        if value.dimensions()!=(dimension,dimension):raise InvalidParameterError("R shape")
        value=value.rows()
    try:
        rows=tuple(islice(iter(value),dimension+1))
        rows=tuple(tuple(islice(iter(row),dimension+1)) for row in rows)
    except TypeError:raise InvalidParameterError("finite square integer R required") from None
    if len(rows)!=dimension or any(len(row)!=dimension for row in rows):
        raise InvalidParameterError("R shape mismatch")
    checked=[]
    for row in rows:
        out=[]
        for x in row:
            if isinstance(x,bool) or not isinstance(x,(int,type(ZZ(0)))):
                raise InvalidParameterError("R must retain signed exact integers, not field entries")
            if abs(int(x)).bit_length()>max_entry_bits:
                raise InvalidParameterError("R coefficient resource budget")
            out.append(int(x))
        checked.append(out)
    result=matrix(ZZ,checked);result.set_immutable();return result


@dataclass(frozen=True,repr=False)
class SampleRResult:
    q:int
    rows:tuple=field(repr=False)
    matrices_sampled:int
    width_squared:object


class FiniteSampleR:
    """First invertible whole matrix; finite resource/abort adaptation.

    Certificate compares to the bounded ideal SampleR including ABORT. Its
    ideal modular nonsingularity lower bound uses a per-entry residue mass
    upper bound and successive subspace codimensions, not paper hidden O().
    """
    MAX_DIMENSION=MAX_DIMENSION
    MAX_Q=2**61-1
    MAX_SQUARED_WIDTH=2**80
    OPTIONS_TYPE=FirstFiniteOptions
    SCALAR_TYPE=FirstFiniteGaussian
    MAX_TAPE_BYTES=2**40
    PROFILE_ID="ABB-ROM-FINITE-SAMPLER/1"

    def __init__(self,q,dimension,width_squared,*,max_matrices=32,options=None,max_tape_bytes=2**40):
        self.q=exact_int(q,"q",3,self.MAX_Q)
        if not ZZ(self.q).is_prime(proof=True):raise InvalidParameterError("odd prime q required")
        self.dimension=exact_int(dimension,"dimension",1,self.MAX_DIMENSION)
        self.width_squared=checked_width(width_squared,self.MAX_SQUARED_WIDTH)
        self.max_matrices=exact_int(max_matrices,"matrix attempts",1,1024)
        self.max_tape_bytes=exact_int(max_tape_bytes,"whole SampleR tape",1,self.MAX_TAPE_BYTES)
        self.scalar=self.SCALAR_TYPE(self.width_squared,self.width_squared,
            options=self.OPTIONS_TYPE() if options is None else options)
        self.random_tape_bytes=self.max_matrices*self.dimension**2*self.scalar.random_tape_bytes
        if self.random_tape_bytes>self.max_tape_bytes:
            raise InvalidParameterError("whole SampleR tape exceeded before entropy")
        # For each canonical residue |t|<=q/2, rho_s(t+qZ) is at most
        # 1 + 2*exp(-pi*q^2/(4*s^2))/(1-exp(-2*pi*q^2/s^2)).
        # rho_s(Z)>=s*(1-theta), so every ideal residue has mass <=mu.
        f=self.scalar.field;v=self.width_squared
        first=capped_exp_minus_pi(QQ(self.q**2)/(4*v),f,self.scalar.cap_bits)
        ratio=capped_exp_minus_pi(QQ(2*self.q**2)/v,f,self.scalar.cap_bits)
        denominator=1-ratio
        if denominator.lower()<=0:raise InvalidParameterError("periodic Gaussian bound precision failed")
        mu=min(QQ(1),interval_upper((1+2*first/denominator)/(f(v).sqrt()*(1-f(self.scalar.theta)))))
        lower=f(1)
        for k in range(1,self.dimension+1):lower*=1-f(mu)**k
        lo=max(QQ(0),lower.lower().exact_rational())
        self.ideal_nonsingular_lower=QQ((lo*2**256).floor())/2**256
        self.ideal_rank_abort_upper=min(QQ(1),interval_upper((1-f(self.ideal_nonsingular_lower))**self.max_matrices))
        self.output_tv_upper=min(QQ(1),self.max_matrices*self.dimension**2*self.scalar.tv_upper)
        self.failure_upper=min(QQ(1),self.ideal_rank_abort_upper+self.output_tv_upper)
        success_lower=1-self.ideal_rank_abort_upper-self.output_tv_upper
        self.conditional_success_tv_upper=(None if success_lower<=0 else
            min(QQ(1),2*self.output_tv_upper/success_lower))
        self.last_entropy_bytes=None

    def sample(self,*,rng=None):
        source=CheckedEntropy(SecureRandom() if rng is None else rng,self.random_tape_bytes)
        try:
            for attempt in range(1,self.max_matrices+1):
                rows=tuple(tuple(self.scalar.sample(self.width_squared,0,rng=source)
                    for _ in range(self.dimension)) for _ in range(self.dimension))
                if matrix(GF(self.q),rows).is_invertible():
                    return SampleRResult(self.q,rows,attempt,self.width_squared)
            raise SamplingAbort("whole SampleR matrix attempts exhausted; no fallback")
        finally:self.last_entropy_bytes=source.bytes_used

    def certificate(self):
        return dict(profile=self.PROFILE_ID,source="ABB10 PDF9 Definition7/SampleR",
            q=self.q,dimension=self.dimension,width_squared=str(self.width_squared),
            whole_matrix_attempts=self.max_matrices,per_column_filtering=False,
            ideal_nonsingular_probability_lower=str(self.ideal_nonsingular_lower),
            ideal_bounded_rank_abort_upper=str(self.ideal_rank_abort_upper),
            output_tv_upper_including_scalar_abort=str(self.output_tv_upper),
            conditional_success_vs_ideal_invertible_matrix_tv_upper=(None if
                self.conditional_success_tv_upper is None else str(self.conditional_success_tv_upper)),
            total_failure_upper=str(self.failure_upper),random_tape_bytes=self.random_tape_bytes,
            conditional_target="IID ideal Gaussian integer matrix conditioned on mod-q invertibility",
            conditional_success_error_not_a_ROM_proof=True,security_claim="none",backend_admitted=False)


@dataclass(frozen=True,repr=False)
class BasisDelPrepared:
    source_public:ModMatrixReference
    target_public:ModMatrixReference
    transformation_rows:tuple
    transformed_rows:tuple=field(repr=False)
    completed_basis:KernelBasis=field(repr=False)
    transformed_sublattice_index:int
    ordered_gs_not_increased:bool|None
    max_gs_not_increased:bool
    completion_reduced:bool=False


def _prepare_basis_del(parent_basis,transformation,limits,*,reduce_completion=False):
    if type(reduce_completion) is not bool:raise InvalidParameterError("explicit completion reduction flag required")
    if not isinstance(parent_basis,KernelBasis):raise InvalidParameterError("complete parent basis required")
    m=parent_basis.public.ncols
    exact_int(m,"dimension",1,limits.max_dimension)
    q=parent_basis.public.q
    if q<=2:raise InvalidParameterError("ABB-ROM requires odd prime q")
    r=signed_square(transformation,m,max_entry_bits=limits.max_entry_bits)
    rmod=matrix(GF(q),r)
    if not rmod.is_invertible():raise InvalidParameterError("R is singular modulo q")
    a=matrix(GF(q),parent_basis.public.rows)
    target=ModMatrixReference(tuple(tuple(int(x) for x in row) for row in (a*rmod.inverse()).rows()),q)
    transformed=r*matrix(ZZ,parent_basis.basis_rows)
    if any(abs(int(x)).bit_length()>limits.max_entry_bits for x in transformed.list()):
        raise InvalidParameterError("transformed basis arithmetic resource budget")
    anchor=complete_kernel_basis(target)
    completed=matrix_to_basis(transformed,anchor,limits=limits)
    if limits!=LEGACY_BASIS_LIMITS:
        if reduce_completion:
            # The first GS squared length of R*T is its first-column norm.
            # Checking max GS(output) <= this proves the original maximum-GS
            # obligation, without computing a skew private GSO first.
            lower_on_old_max=sum(int(x)**2 for x in transformed.column(0))
            completed=matrix_checked_lll(completed,lower_on_old_max,limits=limits)
            ordered=None  # LLL may reorder/increase an individual GS coordinate.
        else:
            ordered=True  # Exact triangular ToBasis factorization proves it.
        return BasisDelPrepared(parent_basis.public,target,
            tuple(tuple(int(x) for x in row) for row in r.rows()),
            tuple(tuple(int(x) for x in row) for row in transformed.rows()),completed,
            abs(int(r.det())),ordered,True,reduce_completion)
    old=gram_schmidt_squared_lengths(transformed)
    if reduce_completion:
        # Explicit concrete realization of the completion-quality obligation:
        # retain the same full lattice and the paper's maximum GS obligation.
        # Reduction can permute/improve GS globally while increasing one
        # coordinate; its ordered profile is reported separately, not claimed.
        # A failed maximum-quality check rejects before any entropy;
        # it does not weaken width/ToBasis guards or resample R/parent keys.
        completed=checked_sage_lll(completed,max(old))
    new=gram_schmidt_squared_lengths(completed.basis_rows)
    ordered=all(b<=a for a,b in zip(old,new))
    maximum=max(new)<=max(old)
    if not maximum or (not reduce_completion and not ordered):
        raise ArithmeticError("BasisDel completion failed its GS quality obligation")
    return BasisDelPrepared(parent_basis.public,target,
        tuple(tuple(int(x) for x in row) for row in r.rows()),
        tuple(tuple(int(x) for x in row) for row in transformed.rows()),completed,
        abs(int(r.det())),ordered,maximum,reduce_completion)


def prepare_basis_del(parent_basis,transformation,*,reduce_completion=False):
    return _prepare_basis_del(parent_basis,transformation,LEGACY_BASIS_LIMITS,
        reduce_completion=reduce_completion)


def prepare_matrix_basis_del(parent_basis,transformation,*,reduce_completion=False,basis_limits=None):
    limits=MatrixBasisLimits() if basis_limits is None else basis_limits
    if not isinstance(limits,MatrixBasisLimits):raise InvalidParameterError("explicit MatrixBasisLimits required")
    return _prepare_basis_del(parent_basis,transformation,limits,reduce_completion=reduce_completion)


class FiniteBasisDel:
    """Original transform/completion/randomization sequence with finite oracle."""
    BASIS_LIMITS=LEGACY_BASIS_LIMITS
    MAX_SQUARED_WIDTH=2**80
    SAMPLER_TYPE=FirstFiniteGPV
    RANDOMIZER_TYPE=FirstFiniteRandBasis
    PROFILE_ID="ABB-ROM-FINITE-BASISDEL/1"

    def __init__(self,parent_basis,transformation,width_squared,*,epsilon_bits=128,
                 max_vectors=None,options=None,max_tape_bytes=2**40,reduce_completion=False):
        self.prepared=_prepare_basis_del(parent_basis,transformation,self.BASIS_LIMITS,reduce_completion=reduce_completion)
        self.sampler=self.SAMPLER_TYPE(self.prepared.completed_basis,checked_width(width_squared,self.MAX_SQUARED_WIDTH),
            epsilon_bits=epsilon_bits,options=options)
        count=self.sampler.dimension+64 if max_vectors is None else max_vectors
        kwargs={} if self.BASIS_LIMITS==LEGACY_BASIS_LIMITS else {"basis_limits":self.BASIS_LIMITS}
        self.randomizer=self.RANDOMIZER_TYPE(self.sampler,max_vectors=count,max_tape_bytes=max_tape_bytes,**kwargs)
        self.random_tape_bytes=self.randomizer.random_tape_bytes

    def sample(self,*,rng=None):
        # A failed rank/norm/scalar invocation is not re-run. The randomizer
        # canonicalizes the complete target lattice, not merely R*T's HNF.
        result=self.randomizer.sample(rng=rng)
        if result.basis.public!=self.prepared.target_public:
            raise ArithmeticError("delegated basis has wrong public matrix")
        return result

    def public_test_certificate(self):
        """Basis-dependent diagnostic; only publish for explicitly public inputs."""
        return dict(profile=self.PROFILE_ID,source="ABB10 PDF10 section3.1",
            dimension=self.sampler.dimension,q=self.prepared.target_public.q,
            transformed_sublattice_index=self.prepared.transformed_sublattice_index,
            complete_kernel_verified=True,
            completion_ordered_gs_not_increased=self.prepared.ordered_gs_not_increased,
            completion_max_gs_not_increased=self.prepared.max_gs_not_increased,
            completion_reduced=self.prepared.completion_reduced,
            RandBasis=self.randomizer.certificate(),not_full_HIBE=True,
            theorem3_finite_constants_or_ROM_mapping_verified=False,security_claim="none",backend_admitted=False)


class MatrixSampleR(FiniteSampleR):
    """Same whole-matrix Gaussian/invertibility algorithm, explicit wide input."""
    MAX_DIMENSION=1536
    MAX_Q=2**256-1
    MAX_SQUARED_WIDTH=2**192
    OPTIONS_TYPE=MatrixFiniteOptions
    SCALAR_TYPE=MatrixFiniteGaussian
    MAX_TAPE_BYTES=2**44
    PROFILE_ID="ABB-ROM-MATRIX-SAMPLER/1"

    def __init__(self,q,dimension,width_squared,*,max_matrices=32,options=None,max_tape_bytes=2**44):
        super().__init__(q,dimension,width_squared,max_matrices=max_matrices,
            options=options,max_tape_bytes=max_tape_bytes)


class MatrixBasisDel(FiniteBasisDel):
    """Same transform/completion/randomization, explicitly selected wide tools."""
    BASIS_LIMITS=MatrixBasisLimits()
    MAX_SQUARED_WIDTH=2**192
    SAMPLER_TYPE=MatrixFiniteGPV
    RANDOMIZER_TYPE=MatrixFiniteRandBasis
    PROFILE_ID="ABB-ROM-MATRIX-BASISDEL/1"

    def __init__(self,parent_basis,transformation,width_squared,*,epsilon_bits=128,
                 max_vectors=None,options=None,max_tape_bytes=2**44,reduce_completion=False):
        super().__init__(parent_basis,transformation,width_squared,epsilon_bits=epsilon_bits,
            max_vectors=max_vectors,options=options,max_tape_bytes=max_tape_bytes,reduce_completion=reduce_completion)


def prefix_matrices(root_public,h1,h2):
    if not isinstance(root_public,ModMatrixReference):raise InvalidParameterError("root modular matrix required")
    m,q=root_public.ncols,root_public.q
    exact_int(m,"dimension",1,MAX_DIMENSION)
    r1,r2=signed_square(h1,m),signed_square(h2,m)
    f=GF(q);a=matrix(f,root_public.rows)
    b1,b2=matrix(f,r1),matrix(f,r2)
    if not b1.is_invertible() or not b2.is_invertible():raise InvalidParameterError("identity transform not invertible")
    first=a*b1.inverse();second=first*b2.inverse()
    direct=a*(b2*b1).inverse()
    if second!=direct:raise ArithmeticError("ABB prefix product order mismatch")
    convert=lambda x:ModMatrixReference(tuple(tuple(int(y) for y in row) for row in x.rows()),q)
    return convert(first),convert(second)
