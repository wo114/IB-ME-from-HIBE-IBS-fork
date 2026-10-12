"""Six-method research HIBE: MP12 computational root/DelTrap + CHKP H/G.

Real finite byte-driven sampling, true receiver delegation, fixed 256 preimages.
Sage reference with public installable entry; not a production backend. Original
CHKP RandBasis and the statistical root profiles are unchanged. This variant's
ROM/model mapping and formal parameters remain unadmitted. Payload <=32 bytes;
the public Hybrid adapter can use its exact 32-byte seed capacity.
"""

from dataclasses import asdict, dataclass, field, fields
from fractions import Fraction
from hmac import compare_digest
import json
from pathlib import Path
from threading import RLock

from sage.all import ZZ

from ibme.core.encoding import encode_bytes
from ibme.core.errors import EncodingError, InvalidParameterError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_identity
from experiments.research.chkp_basis import KernelBasis, ModMatrixReference, ext_basis
from experiments.research.ibme_joint_parameters import evaluate_noise, smoothing_factor
from experiments.research.ibme_noise_budget import RoundedNoiseParams
from experiments.research.ibme_rounded_noise import build_rounded_noise
from experiments.research.ibme_root_sampler_audit import checked_sage_lll

from .compact_delegation import FiniteDelTrap, split_extension
from .computational_root import ComputationalRootParams, ComputationalRootGenerator
from .delegation_state import validate_basis
from .finite_gpv import FirstFiniteGPV
from .entropy import CheckedEntropy
from .identity import Reader, ROHIBEContext, checked_bytes, checked_int
from .leaf_state import FixedSeedKey, FixedSeedState, SeedPlan, SeedScope
from .root_generation import unique_fields
from .seed_kem import SeedCapsule, encapsulate_seed, decapsulate_seed

PROFILE = "MP12-COMPUTATIONAL-CHKP-FINITE/1"
SEED_PROFILE = PROFILE.encode()+b"; fixed256; FirstFiniteGPV; epsilon128"
PK_MAGIC = b"IBME:MP12-CHKP:PK:1"
MSK_MAGIC = b"IBME:MP12-CHKP:MSK:1"
PARENT_MAGIC = b"IBME:MP12-CHKP:L1:1"
LEAF_MAGIC = b"IBME:MP12-CHKP:L2:1"
CT_MAGIC = b"IBME:MP12-CHKP:CT:1"
PRIVATE_MAX = 16*2**20
MASTER_MAX = 64*2**20


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class MP12HIBEParams:
    n: int = 2
    q: int = 549755813911
    r_width_squared: int = 16
    identity_bytes: int = 86
    max_receivers: int = 2
    max_children: int = 2
    security_claim: str = "none"
    backend_admitted: bool = False
    parameters_are_formal: bool = False

    def __post_init__(self):
        if (type(self.security_claim) is not str or self.security_claim!="none"
                or self.backend_admitted is not False or self.parameters_are_formal is not False):
            raise InvalidParameterError("research parameters cannot claim security admission")
        root = self.root_params
        checked_int(self.identity_bytes, "identity bytes", 1, 86)
        checked_int(self.max_receivers, "receiver entries", 1, 2)
        checked_int(self.max_children, "sender entries", 1, 2)
        if 3*root.dimension > 256:
            raise InvalidParameterError("reference leaf exceeds finite GPV cap before sampling")
        if self.leaf_width_squared > 2**80:
            raise InvalidParameterError("reference leaf width exceeds finite scalar cap")
        noise = self.noise_budget()
        if not noise["conditional_noise_sufficient"]:
            raise InvalidParameterError("reference same-input conditional correctness fails")

    @property
    def root_params(self): return ComputationalRootParams(self.n, self.q, self.r_width_squared)

    @property
    def m(self): return self.root_params.dimension

    @property
    def max_message_bytes(self): return 32

    @property
    def parent_width_squared(self):
        return 4*self.root_params.public_gs_squared_bound*smoothing_factor(2*self.m, 128)

    @property
    def parent_gs_squared_bound(self):
        w = self.n*(self.q-1).bit_length()
        return 10*(1+w*(2*self.m-w)*self.parent_width_squared)

    @property
    def leaf_width_squared(self):
        return 4*self.parent_gs_squared_bound*smoothing_factor(3*self.m, 128)

    @property
    def noise_params(self):
        return RoundedNoiseParams(self.q, Fraction(4, self.q), tail_bits=128,
            mass_bits=192, precision_bits=256)

    def noise_budget(self):
        return evaluate_noise(q=self.q, dimension=3*self.m,
            width_squared=self.leaf_width_squared, alpha=Fraction(4, self.q),
            error_bits=128, seed_bits=256, encapsulations=2**20)

    def configuration(self):
        return canonical(dict(profile=PROFILE, parameters=asdict(self),
            root_profile="IBME/MP12-COMPUTATIONAL-ROOT/1",
            parent_profile="MP12 Algorithm4 with FirstFiniteGPV; norm cutoff; no retry",
            leaf_profile=SEED_PROFILE.decode(), epsilon_bits=128,
            root_gs_squared_bound=self.root_params.public_gs_squared_bound,
            parent_width_squared=self.parent_width_squared,
            parent_gs_squared_bound=self.parent_gs_squared_bound,
            leaf_width_squared=self.leaf_width_squared, noise=self.noise_params.to_record(),
            max_payload_bytes=32, fixed_seed_bits=256))

    @classmethod
    def from_configuration(cls, data):
        if type(data) is not bytes or not 1<=len(data)<=4096:
            raise SerializationError("MP12 configuration type/size budget exceeded")
        try:
            record = json.loads(data, object_pairs_hook=unique_fields)
            p = record["parameters"]
            if set(p) != {f.name for f in fields(cls)}:
                raise ValueError("parameter fields")
            if (p["security_claim"] != "none" or p["backend_admitted"] is not False
                    or p["parameters_are_formal"] is not False):
                raise ValueError("security metadata")
            value = cls(**{f.name:p[f.name] for f in fields(cls) if f.init})
            if value.configuration() != data: raise ValueError("canonical configuration")
            return value
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError, InvalidParameterError):
            raise SerializationError("invalid MP12 HIBE parameter snapshot") from None


@dataclass(frozen=True)
class MP12HIBEPublicKey:
    params: MP12HIBEParams
    oracle: ROHIBEContext

    def __post_init__(self):
        if not isinstance(self.params, MP12HIBEParams) or not isinstance(self.oracle, ROHIBEContext):
            raise InvalidParameterError("validated parameters/oracle required")
        p, o = self.params, self.oracle
        if ((o.n,o.m,o.q,o.identity_bytes) != (p.n,p.m,p.q,p.identity_bytes)
                or o.public_configuration != p.configuration()
                or any(o.root_rows[i][j] != int(i==j) for i in range(p.n) for j in range(p.n))):
            raise InvalidParameterError("computational root/snapshot binding failed")

    def to_bytes(self): return PK_MAGIC+encode_bytes(self.oracle.to_bytes())

    @classmethod
    def from_bytes(cls, data):
        r = Reader(data)
        if r.take(len(PK_MAGIC)) != PK_MAGIC: raise SerializationError("unknown MP12 public version")
        o = ROHIBEContext.from_bytes(r.blob(PRIVATE_MAX)); r.finish()
        try: return cls(MP12HIBEParams.from_configuration(o.public_configuration),o)
        except InvalidParameterError:
            raise SerializationError("invalid MP12 public binding") from None


def pack_integer(value):
    if type(value) is not int or abs(value).bit_length()>256:
        raise SerializationError("private integer domain")
    return bytes([int(value<0)])+encode_bytes(abs(value).to_bytes(max(1,(abs(value).bit_length()+7)//8),"big"))


def read_integer(r):
    sign, raw = r.number(1), r.blob(32)
    value = int.from_bytes(raw,"big")
    if sign not in (0,1) or (len(raw)>1 and raw[0]==0) or (sign==1 and value==0):
        raise SerializationError("noncanonical private integer")
    return -value if sign else value


def pack_basis(basis):
    return basis.public.ncols.to_bytes(4,"big")+b"".join(pack_integer(x) for row in basis.basis_rows for x in row)


def load_basis(raw, rows, q):
    r = Reader(raw,maximum=PRIVATE_MAX); d = len(rows[0])
    if r.number()!=d or len(r.data)-r.pos<6*d*d:
        raise SerializationError("private basis shape/truncation")
    values = tuple(tuple(read_integer(r) for _ in range(d)) for _ in range(d));r.finish()
    try: return KernelBasis(ModMatrixReference(rows,q),values)
    except (ValueError,InvalidParameterError):
        raise SerializationError("invalid full private kernel basis") from None


def seed_scope(pk,receiver):
    return SeedScope(pk.oracle,receiver,Fraction(pk.params.leaf_width_squared),SEED_PROFILE,
        max_children=pk.params.max_children)


class MP12HIBEReceiver:
    def __init__(self,pk,identity,basis,seeds=None):
        if not isinstance(pk,MP12HIBEPublicKey): raise InvalidParameterError("MP12 public key required")
        self.pk = pk
        self.identity = validate_identity(identity,max_bytes=pk.params.identity_bytes)
        self.basis = validate_basis(basis,pk.oracle.parent_rows(self.identity),pk.params.q,
            pk.params.parent_gs_squared_bound)
        scope = seed_scope(pk,self.identity)
        if seeds is not None and (not isinstance(seeds,FixedSeedState) or seeds.scope != scope):
            raise InvalidParameterError("fixed child state binding failed")
        self.seeds = FixedSeedState(scope) if seeds is None else seeds
        self.lock = RLock()

    def __repr__(self): return "MP12HIBEReceiver(RESEARCH, private state hidden)"

    def to_bytes(self):
        with self.lock:
            out = (PARENT_MAGIC+encode_bytes(self.pk.to_bytes())+encode_bytes(self.identity)
                +encode_bytes(pack_basis(self.basis))+encode_bytes(self.seeds.to_bytes()))
            if len(out)>PRIVATE_MAX: raise SerializationError("receiver wire budget exceeded")
            return out

    @classmethod
    def from_bytes(cls,data):
        r = Reader(data,maximum=PRIVATE_MAX)
        if r.take(len(PARENT_MAGIC))!=PARENT_MAGIC: raise SerializationError("unknown MP12 receiver version")
        pk = MP12HIBEPublicKey.from_bytes(r.blob(PRIVATE_MAX));i = r.blob(pk.params.identity_bytes)
        basis = load_basis(r.blob(PRIVATE_MAX),pk.oracle.parent_rows(i),pk.params.q)
        state = FixedSeedState.from_bytes(r.blob(PRIVATE_MAX),expected_scope=seed_scope(pk,i));r.finish()
        try: return cls(pk,i,basis,state)
        except (InvalidParameterError,EncodingError):
            raise SerializationError("invalid MP12 receiver binding") from None


class MP12HIBEMasterSecret:
    def __init__(self,pk,basis):
        if not isinstance(pk,MP12HIBEPublicKey): raise InvalidParameterError("MP12 public key required")
        self.pk = pk
        self.basis = validate_basis(basis,pk.oracle.root_rows,pk.params.q,pk.params.root_params.public_gs_squared_bound)
        self.receivers,self.lock = {},RLock()

    def __repr__(self): return "MP12HIBEMasterSecret(RESEARCH, private state hidden)"

    def to_bytes(self):
        with self.lock:
            out = bytearray(MSK_MAGIC+encode_bytes(self.pk.to_bytes())+encode_bytes(pack_basis(self.basis))
                +len(self.receivers).to_bytes(4,"big"))
            for i,key in sorted(self.receivers.items()):
                out.extend(encode_bytes(i)+bytes([int(key is not None)]))
                if key is not None: out.extend(encode_bytes(key.to_bytes()))
            if len(out)>MASTER_MAX: raise SerializationError("master wire budget exceeded")
            return bytes(out)

    @classmethod
    def from_bytes(cls,data):
        r = Reader(data,maximum=MASTER_MAX)
        if r.take(len(MSK_MAGIC))!=MSK_MAGIC: raise SerializationError("unknown MP12 master version")
        pk = MP12HIBEPublicKey.from_bytes(r.blob(PRIVATE_MAX))
        basis = load_basis(r.blob(PRIVATE_MAX),pk.oracle.root_rows,pk.params.q)
        try: result = cls(pk,basis)
        except InvalidParameterError: raise SerializationError("invalid master binding") from None
        count = r.number()
        if count>pk.params.max_receivers: raise SerializationError("master receiver capacity")
        previous = None
        for _ in range(count):
            identity = r.blob(pk.params.identity_bytes)
            if previous is not None and identity<=previous: raise SerializationError("duplicate/unsorted receiver")
            previous = identity;status = r.number(1)
            if status==0: result.receivers[identity]=None
            elif status==1:
                receiver = MP12HIBEReceiver.from_bytes(r.blob(PRIVATE_MAX))
                if receiver.pk!=pk or receiver.identity!=identity: raise SerializationError("master receiver binding")
                result.receivers[identity]=receiver
            else: raise SerializationError("unknown receiver state")
        r.finish();return result


@dataclass(frozen=True,repr=False)
class MP12HIBELeaf:
    pk: MP12HIBEPublicKey
    fixed: FixedSeedKey = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.pk,MP12HIBEPublicKey) or not isinstance(self.fixed,FixedSeedKey):
            raise InvalidParameterError("public key and checked fixed leaf required")
        if self.fixed.plan.scope != seed_scope(self.pk,self.fixed.plan.scope.receiver):
            raise InvalidParameterError("leaf public/profile binding")

    @property
    def parent_identity(self): return self.fixed.plan.scope.receiver

    @property
    def child_identity(self): return self.fixed.plan.sender

    def to_bytes(self):
        out = (LEAF_MAGIC+encode_bytes(self.pk.to_bytes())+encode_bytes(self.parent_identity)
            +encode_bytes(self.child_identity)+b"".join(pack_integer(x) for sample in self.fixed.preimages for x in sample))
        if len(out)>PRIVATE_MAX: raise SerializationError("leaf wire budget")
        return out

    @classmethod
    def from_bytes(cls,data):
        r = Reader(data,maximum=PRIVATE_MAX)
        if r.take(len(LEAF_MAGIC))!=LEAF_MAGIC: raise SerializationError("unknown MP12 leaf version")
        pk = MP12HIBEPublicKey.from_bytes(r.blob(PRIVATE_MAX))
        receiver,sender = r.blob(pk.params.identity_bytes),r.blob(pk.params.identity_bytes)
        d = pk.oracle.leaf_dimension
        if len(r.data)-r.pos<6*256*d: raise SerializationError("truncated fixed leaf")
        values = tuple(tuple(read_integer(r) for _ in range(d)) for _ in range(256));r.finish()
        try: return cls(pk,FixedSeedKey(SeedPlan(seed_scope(pk,receiver),sender),values))
        except (InvalidParameterError,EncodingError):
            raise SerializationError("invalid fixed leaf equations/binding") from None


@dataclass(frozen=True)
class MP12HIBECiphertext:
    capsule: SeedCapsule
    payload_length: int

    def __post_init__(self):
        if not isinstance(self.capsule,SeedCapsule): raise InvalidParameterError("seed capsule required")
        checked_int(self.payload_length,"raw payload length",0,32)

    def to_bytes(self):
        return CT_MAGIC+self.payload_length.to_bytes(4,"big")+encode_bytes(self.capsule.to_bytes())

    @classmethod
    def from_bytes(cls,data):
        r = Reader(data)
        if r.take(len(CT_MAGIC))!=CT_MAGIC: raise SerializationError("unknown MP12 ciphertext version")
        size = r.number();capsule = SeedCapsule.from_bytes(r.blob(PRIVATE_MAX));r.finish()
        try: return cls(capsule,size)
        except InvalidParameterError: raise SerializationError("invalid payload length") from None


class MP12CHKPResearchHIBE:
    """Public contract implementation; custom source-checkout registration only."""
    security_claim="none"
    backend_admitted=False
    parameters_are_formal=False

    def __init__(self,basis_engine=None):
        self.basis_engine = None if basis_engine is None else Path(basis_engine)
        self.last_setup_receipt = None

    def setup(self,params,*,rng=None):
        if not isinstance(params,MP12HIBEParams): raise InvalidParameterError("MP12 HIBE parameters required")
        if self.basis_engine is None or not self.basis_engine.is_file():
            raise InvalidParameterError("private basis engine required for Setup before entropy")
        result = ComputationalRootGenerator(params.root_params,self.basis_engine).generate(rng=rng)
        oracle = ROHIBEContext(params.n,params.m,params.q,result.basis.public.rows,
            params.configuration(),params.identity_bytes)
        pk = MP12HIBEPublicKey(params,oracle)
        self.last_setup_receipt = result.public_generation_certificate
        return pk,MP12HIBEMasterSecret(pk,result.basis)

    def extract(self,msk,parent_id,*,rng=None):
        if not isinstance(msk,MP12HIBEMasterSecret): raise InvalidParameterError("MP12 master secret required")
        identity = validate_identity(parent_id,max_bytes=msk.pk.params.identity_bytes)
        with msk.lock:
            if identity in msk.receivers:
                if msk.receivers[identity] is None: raise InvalidParameterError("receiver blocked after failed delegation")
                return msk.receivers[identity]
            if len(msk.receivers)>=msk.pk.params.max_receivers:
                raise InvalidParameterError("receiver capacity exhausted before entropy")
            if self.basis_engine is None or not self.basis_engine.is_file():
                raise InvalidParameterError("private basis engine required for new receiver before entropy/state")
            msk.receivers[identity]=None
            p,o = msk.pk.params,msk.pk.oracle
            base,tail = split_extension(msk.basis,ModMatrixReference(o.h((identity,)),p.q))
            base = checked_sage_lll(base,p.root_params.public_gs_squared_bound)
            sampler = FirstFiniteGPV(base,p.parent_width_squared,epsilon_bits=128)
            trapdoor = FiniteDelTrap(sampler,tail).sample(rng=rng)
            basis = trapdoor.to_basis(self.basis_engine)
            # Reducing once gives the stored private parent basis; use fixed
            # public widths, never tune widths to a generated secret's GS.
            basis = checked_sage_lll(basis,p.parent_gs_squared_bound)
            key = MP12HIBEReceiver(msk.pk,identity,basis)
            msk.receivers[identity]=key
            return key

    def derive(self,sk_parent,child_id,*,rng=None):
        if not isinstance(sk_parent,MP12HIBEReceiver): raise InvalidParameterError("MP12 receiver required")
        sender = validate_identity(child_id,max_bytes=sk_parent.pk.params.identity_bytes)
        with sk_parent.lock:
            def generate(plan):
                p = sk_parent.pk.params
                basis = ext_basis(sk_parent.basis,ModMatrixReference(sk_parent.pk.oracle.h((sk_parent.identity,sender)),p.q))
                basis = checked_sage_lll(basis,p.parent_gs_squared_bound)
                sampler = FirstFiniteGPV(basis,p.leaf_width_squared,epsilon_bits=128)
                budget = 256*sampler.random_tape_bytes
                if budget>2**40:
                    raise InvalidParameterError("whole 256-position entropy budget exceeded")
                source = CheckedEntropy(SecureRandom() if rng is None else rng,budget)
                return tuple(sampler.sample(target,rng=source) for target in plan.targets)
            fixed = sk_parent.seeds.resolve(sender,generate)
            return MP12HIBELeaf(sk_parent.pk,fixed)

    def encrypt(self,pk,parent_id,child_id,payload,*,rng=None):
        if not isinstance(pk,MP12HIBEPublicKey): raise InvalidParameterError("MP12 public key required")
        receiver = validate_identity(parent_id,max_bytes=pk.params.identity_bytes)
        sender = validate_identity(child_id,max_bytes=pk.params.identity_bytes)
        value = checked_bytes(payload,"raw HIBE payload",32,nonempty=False)
        noise = build_rounded_noise(pk.params.noise_params)
        capsule = encapsulate_seed(pk.oracle,receiver,sender,value+b"\x00"*(32-len(value)),noise,rng=rng)
        return MP12HIBECiphertext(capsule,len(value))

    def decrypt(self,sk_child,ct,*,rng=None):
        if not isinstance(sk_child,MP12HIBELeaf) or not isinstance(ct,MP12HIBECiphertext): return None
        out = decapsulate_seed(sk_child.fixed,ct.capsule)
        if out is None or any(out[ct.payload_length:]): return None
        return out[:ct.payload_length]

    def load_ciphertext(self,data): return MP12HIBECiphertext.from_bytes(data)

    def validate_key_binding(self,public_key,secret_key):
        if not isinstance(public_key,MP12HIBEPublicKey): return False
        try:
            if not isinstance(secret_key,(MP12HIBEMasterSecret,MP12HIBEReceiver,MP12HIBELeaf)):
                return False
            if not compare_digest(public_key.to_bytes(),secret_key.pk.to_bytes()): return False
            p,o = public_key.params,public_key.oracle
            if isinstance(secret_key,MP12HIBEMasterSecret):
                validate_basis(secret_key.basis,o.root_rows,p.q,p.root_params.public_gs_squared_bound)
            elif isinstance(secret_key,MP12HIBEReceiver):
                validate_basis(secret_key.basis,o.parent_rows(secret_key.identity),p.q,p.parent_gs_squared_bound)
                if secret_key.seeds.scope != seed_scope(public_key,secret_key.identity): return False
            else:
                if secret_key.fixed.plan.scope != seed_scope(public_key,secret_key.parent_identity): return False
                FixedSeedKey(secret_key.fixed.plan,secret_key.fixed.preimages)
            return True
        except (ValueError,TypeError,InvalidParameterError,EncodingError,SerializationError):
            return False
