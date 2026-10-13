"""ABB-ROM finite research backend, using actual AP09 and BasisDel providers.

Independent bits use fresh encryption vectors/noises and fresh SamplePre.
Fixed issued/failed identity addresses persist; no teaching/mock fallback.
Public matrix-hash engineering, fixed normalization and finite errors are
explicit implementation adaptations, not a formal ROM or security admission.
"""

from fractions import Fraction

from ibme.core.errors import IBMEError, InvalidParameterError, EncodingError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from ibme.lattice.matrix_sampling import MatrixFiniteOptions, MatrixFiniteGPV, matrix_checked_lll
from experiments.research.first_suite.entropy import CheckedEntropy
from experiments.research.gaussian_reference import draw_uniform_integer, SamplingAbort

from .params import ABBROMParams
from .objects import ABBPublicKey, ABBMasterSecret, ABBLevel1Key, ABBLevel2Key, ABBCiphertext, header
from .trapgen import ABBTrapGenParams, abb_trapgen
from .parameter_screen import abb_parameter_screen
from .identity import prefix_matrix
from .key_validation import validate_basis, expected_matrix
from .primitives import MatrixSampleR, MatrixBasisDel
from .bit_encryption import ABBBitPublic, ABBBitEncryptor, ABBBitCiphertext, abb_decode_phase


class ABBSamplingAbort(IBMEError):
    """Fixed issuance or finite sampling/resource call failed; no implicit retry."""


def finite_options(p):
    return MatrixFiniteOptions(tail_bits=p.finite_tail_bits,mass_bits=p.finite_mass_bits,
        precision_bits=p.finite_precision_bits,gaussian_abort_bits=p.finite_abort_bits,
        max_uniform_trials=p.uniform_trials,max_tape_bytes=p.max_tape_bytes)


def root_parameters(p):
    return ABBTrapGenParams(p.n,p.q,p.random_rows,p.root_m1,p.root_m2,
        hadamard_scale=p.hadamard_scale,uniform_trials=p.uniform_trials,max_entropy_bytes=min(p.max_tape_bytes,2**40))


def check_setup_profile(p):
    if not isinstance(p,ABBROMParams):
        raise InvalidParameterError("ABB requires independent ABBROMParams, no old Params conversion")
    if p.normalization == "matrix-flatter-lll-075-0501-exact074-v2":
        from sage.features.flatter import Flatter
        Flatter().require()  # fixed local dependency, before any private RNG
    public_size=len(header(b"PK",p))+4+(p.n*p.dimension+p.n)*((p.q.bit_length()+7)//8)
    minimum_master_size=len(header(b"MSK",p))+4+public_size+64+6*p.dimension**2+4
    if minimum_master_size>p.max_blob_bytes:
        raise InvalidParameterError("ABB master wire lower bound exceeds selected profile before entropy")
    root = root_parameters(p)
    report = abb_parameter_screen(root,epsilon_bits=p.epsilon_bits,error_bits=p.error_bits,
        encapsulations=p.encapsulation_budget,options=finite_options(p))
    for name in ("matrix_gaussian_squared_width","sigma1_squared","sigma2_squared","decryption_tau_squared"):
        actual = p.tau2_squared if name=="decryption_tau_squared" else getattr(p,name)
        if actual != int(report[name]):
            raise InvalidParameterError("ABB exact same-group public widths differ from the declared finite recipe")
    if (Fraction(p.noise_width_numerator,p.noise_width_denominator)!=4 or
            report["conditional_noise_sufficient"] is not True):
        raise InvalidParameterError("ABB conditional noise profile is not admitted for byte HIBE")
    if report["blockers"]:
        raise InvalidParameterError("ABB known public finite-tool admission condition failed")
    # Build public distribution/budget before consuming Setup or issuance entropy.
    oracle_sampler = MatrixSampleR(p.q,p.dimension,p.matrix_gaussian_squared_width,
        options=finite_options(p),max_matrices=p.sample_r_max_matrices,max_tape_bytes=p.max_tape_bytes)
    return root,oracle_sampler,report


class ABBROMHIBE:
    BACKEND_ID = "abb-rom-finite"
    WIRE_ID = "ABRF1"

    def __init__(self,*,persist_pending=None):
        if persist_pending is not None and not callable(persist_pending):
            raise TypeError("optional single-writer pending-state persister must be callable")
        self._oracle_samplers = {}
        self._persist_pending = persist_pending

    def _oracle(self,p):
        encoded = p.to_bytes()
        if encoded not in self._oracle_samplers:
            _,sampler,_ = check_setup_profile(p)
            self._oracle_samplers[encoded] = sampler
        return self._oracle_samplers[encoded]

    @staticmethod
    def _reduction_options(p):
        return ({"preconditioner": "flatter"} if p.normalization ==
            "matrix-flatter-lll-075-0501-exact074-v2" else {})

    def setup(self,params,*,rng=None):
        root,sampler,_ = check_setup_profile(params)
        self._oracle_samplers[params.to_bytes()] = sampler
        source = CheckedEntropy(SecureRandom() if rng is None else rng,params.max_tape_bytes)
        try:
            generated = abb_trapgen(root,rng=source)
            u0 = tuple(draw_uniform_integer(source,params.q,max_trials=params.uniform_trials) for _ in range(params.n))
            pk = ABBPublicKey(params,generated.basis.public.rows,u0)
            msk = ABBMasterSecret(pk,generated.basis.basis_rows)
            msk.to_bytes()  # private wire resource gate before returning state
            return pk,msk
        except SamplingAbort as exc:
            raise ABBSamplingAbort("ABB Setup sampling aborted; no fallback") from exc

    def extract(self,msk,parent_id,*,rng=None):
        if not isinstance(msk,ABBMasterSecret):raise TypeError("ABBMasterSecret required")
        pk,p = msk.public_key,msk.public_key.params
        identity = validate_identity(parent_id,max_bytes=p.identity_max_bytes)
        sampler = self._oracle(p)
        with msk.lock:
            if identity in msk.parents:
                stored = msk.parents[identity]
                if stored is None:raise ABBSamplingAbort("ABB parent address already failed; no reissue")
                if (not isinstance(stored,ABBLevel1Key) or stored.identity!=identity or
                        not self.validate_key_binding(pk,stored)):
                    raise InvalidParameterError("cached ABB parent address binding failed")
                return stored
            if len(msk.parents)>=p.max_parents:raise InvalidParameterError("ABB parent address capacity")
            basis = validate_basis(pk,(),msk.basis)
            msk.parents[identity] = None
            if self._persist_pending is not None:
                self._persist_pending(msk)  # durable FAILED/PENDING before any issuance entropy
            try:
                transformation = prefix_matrix(pk.context,(identity,),p,sampler=sampler)
                delegated = MatrixBasisDel(basis,transformation,p.sigma1_squared,epsilon_bits=p.epsilon_bits,
                    options=finite_options(p),max_tape_bytes=p.max_tape_bytes,reduce_completion=True,
                    **self._reduction_options(p)).sample(rng=rng)
                normalized = matrix_checked_lll(delegated.basis,p.sigma1_squared*p.dimension,
                    **self._reduction_options(p))
                result = ABBLevel1Key(pk,identity,normalized.basis_rows)
                result.to_bytes()
                msk.parents[identity] = result
                msk.to_bytes()
                return result
            except (SamplingAbort,ValueError,ArithmeticError,IBMEError) as exc:
                msk.parents[identity] = None
                raise ABBSamplingAbort("ABB parent issuance failed; address retained") from exc

    def derive(self,sk_parent,child_id,*,rng=None):
        if not isinstance(sk_parent,ABBLevel1Key):raise TypeError("ABBLevel1Key required")
        pk,p = sk_parent.public_key,sk_parent.public_key.params
        identity = validate_identity(child_id,max_bytes=p.identity_max_bytes)
        sampler = self._oracle(p)
        with sk_parent.lock:
            if identity in sk_parent.children:
                stored = sk_parent.children[identity]
                if stored is None:raise ABBSamplingAbort("ABB child address already failed; no reissue")
                if (not isinstance(stored,ABBLevel2Key) or stored.parent_identity!=sk_parent.identity or
                        stored.child_identity!=identity or not self.validate_key_binding(pk,stored)):
                    raise InvalidParameterError("cached ABB child address binding failed")
                return stored
            if len(sk_parent.children)>=p.max_children_per_parent:raise InvalidParameterError("ABB child address capacity")
            basis = validate_basis(pk,(sk_parent.identity,),sk_parent.basis)
            sk_parent.children[identity] = None
            if self._persist_pending is not None:
                self._persist_pending(sk_parent)
            try:
                transformation = prefix_matrix(pk.context,(sk_parent.identity,identity),p,sampler=sampler)
                delegated = MatrixBasisDel(basis,transformation,p.sigma2_squared,epsilon_bits=p.epsilon_bits,
                    options=finite_options(p),max_tape_bytes=p.max_tape_bytes,reduce_completion=True,
                    **self._reduction_options(p)).sample(rng=rng)
                normalized = matrix_checked_lll(delegated.basis,p.sigma2_squared*p.dimension,
                    **self._reduction_options(p))
                result = ABBLevel2Key(pk,sk_parent.identity,identity,normalized.basis_rows)
                result.to_bytes()
                sk_parent.children[identity] = result
                sk_parent.to_bytes()
                return result
            except (SamplingAbort,ValueError,ArithmeticError,IBMEError) as exc:
                sk_parent.children[identity] = None
                raise ABBSamplingAbort("ABB child issuance failed; address retained") from exc

    def encrypt(self,pk,parent_id,child_id,payload,*,rng=None):
        if not isinstance(pk,ABBPublicKey):raise TypeError("ABBPublicKey required")
        p = pk.params
        parent = validate_identity(parent_id,max_bytes=p.identity_max_bytes)
        child = validate_identity(child_id,max_bytes=p.identity_max_bytes)
        message = validate_bytes(payload,name="ABB payload")
        if len(message)>p.payload_max_bytes:raise EncodingError("ABB raw payload capacity")
        self._oracle(p)
        public = ABBBitPublic(expected_matrix(pk,(parent,child)),pk.u0)
        scaled = Fraction(p.noise_width_numerator,p.noise_width_denominator)
        encryptor = ABBBitEncryptor(public,scaled/p.q,uniform_trials=p.uniform_trials,
            tail_bits=p.finite_tail_bits,mass_bits=p.finite_mass_bits,precision_bits=p.finite_precision_bits)
        if 8*len(message)*encryptor.random_tape_bytes>p.max_tape_bytes:
            raise InvalidParameterError("ABB complete encryption tape exceeds selected profile")
        source = CheckedEntropy(SecureRandom() if rng is None else rng,p.max_tape_bytes)
        blocks = []
        try:
            for byte in message:
                for shift in reversed(range(8)):
                    bit = encryptor.encrypt((byte>>shift)&1,rng=source)
                    blocks.append((bit.c0,)+bit.c1)
        except SamplingAbort as exc:
            raise ABBSamplingAbort("ABB bit encryption entropy budget aborted") from exc
        result = ABBCiphertext(p,pk.context,len(message),tuple(blocks))
        if len(result.to_bytes())>p.max_blob_bytes:raise InvalidParameterError("ABB ciphertext wire budget")
        return result

    def decrypt(self,sk_child,ct,*,rng=None):
        if not isinstance(sk_child,ABBLevel2Key):raise TypeError("ABBLevel2Key required")
        if not isinstance(ct,ABBCiphertext):return None
        pk,p = sk_child.public_key,sk_child.public_key.params
        if ct.params!=p or ct.context!=pk.context:return None
        if not self.validate_key_binding(pk,sk_child):return None
        self._oracle(p)
        if ct.payload_bytes==0:return b""
        basis = validate_basis(pk,(sk_child.parent_identity,sk_child.child_identity),sk_child.basis)
        sampler = MatrixFiniteGPV(basis,p.tau2_squared,epsilon_bits=p.epsilon_bits,options=finite_options(p))
        if len(ct.blocks)*sampler.random_tape_bytes>p.max_tape_bytes:
            raise InvalidParameterError("ABB complete decryption tape exceeds selected profile")
        source = CheckedEntropy(SecureRandom() if rng is None else rng,p.max_tape_bytes)
        output = bytearray()
        value = 0
        try:
            for index,block in enumerate(ct.blocks):
                # Exactly one fresh SamplePre per original one-bit Decrypt.
                x = sampler.sample(pk.u0,rng=source)
                if len(x)!=p.dimension or any(sum(a*b for a,b in zip(row,x))%p.q!=target
                        for row,target in zip(basis.public.rows,pk.u0)):
                    raise ArithmeticError("ABB fresh SamplePre equation failed")
                if sum(a*a for a in x)>p.tau2_squared*p.dimension:
                    raise SamplingAbort("ABB SamplePre norm event failed; no retry")
                phase = (block[0]-sum(a*b for a,b in zip(x,block[1:])))%p.q
                value = (value<<1)|abb_decode_phase(phase,p.q)
                if index%8==7:
                    output.append(value);value=0
        except SamplingAbort as exc:
            raise ABBSamplingAbort("ABB bit decryption sampling aborted") from exc
        return bytes(output)

    def load_ciphertext(self,data):
        return ABBCiphertext.from_bytes(data)

    def validate_key_binding(self,public_key,secret_key):
        if not isinstance(public_key,ABBPublicKey) or getattr(secret_key,"public_key",None)!=public_key:
            return False
        try:
            if isinstance(secret_key,ABBMasterSecret):path=()
            elif isinstance(secret_key,ABBLevel1Key):path=(secret_key.identity,)
            elif isinstance(secret_key,ABBLevel2Key):path=(secret_key.parent_identity,secret_key.child_identity)
            else:return False
            validate_basis(public_key,path,secret_key.basis)
            return True
        except (TypeError,ValueError,ArithmeticError,IBMEError,SamplingAbort):
            return False
