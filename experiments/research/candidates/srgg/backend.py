"""Complete SRGG research IBS five methods and cached fixed-identity issuance.

Norm rejection follows Algorithm7. Internal sampling/entropy aborts propagate;
failed/pending identities are never silently reissued. No formal security claim.
"""
from ibme.core.errors import EncodingError, SerializationError
from ibme.core.randomness import SecureRandom
from ibme.core.types import validate_bytes, validate_identity
from ..wang_pw.backend import CheckedRandom
from .algebra import build_public, recover_commitment
from .config import Config
from .hashing import identity_target,message_challenge,public_matrix
from .objects import PublicKey,MasterSecret,SigningKey,Signature


def identity(c,value):
    value=validate_identity(value)
    if len(value)>c.identity_max_bytes: raise EncodingError("identity capacity exceeded")
    return value


def message(c,value):
    value=validate_bytes(value,name="message")
    if len(value)>c.message_max_bytes: raise EncodingError("message capacity exceeded")
    return value


def signature_shape(pk,s):
    p=pk.config.algebra
    return (isinstance(s,Signature) and s.context==pk.context and len(s.challenge)==p.degree
            and len(s.z)==p.columns+1 and sum(x*x for poly in s.z for x in poly)<=pk.config.signature_bound_squared)


class Backend:
    security_claim="none"
    backend_admitted=False
    def __init__(self,*,rng=None): self.rng=CheckedRandom(SecureRandom() if rng is None else rng)

    def setup(self,params):
        if not isinstance(params,Config): raise TypeError("SRGG Config required")
        from .geometry import Widths,master_geometry
        from .sampling import GadgetSampler,TableOptions
        from . import runtime
        # Whole public resource classes are checked before reading secret bytes.
        p=params.algebra
        zero=tuple(tuple((0,)*p.degree for _ in range(p.rank*p.digits)) for _ in range(2*p.rank))
        master_geometry(p,zero,Widths(params.master_first_squared,params.master_second_squared,params.r_squared))
        runtime.options(params)
        GadgetSampler(p,params.gadget_width_squared,TableOptions(tail_bits=params.gadget_tail_bits,mass_bits=params.scalar_mass_bits,
                                                             precision_bits=params.precision_bits,max_radius=128))
        seed=self.rng.read(32); a_hat=public_matrix(params,seed)
        for _ in range(params.setup_max_attempts):
            values=[]
            for _ in range(2*p.rank*p.rank*p.digits*p.degree):
                v=self.rng.read(1)[0]; values.append((v&1)-((v>>1)&1))
            r=tuple(tuple(tuple(values[(i*p.rank*p.digits+j)*p.degree:(i*p.rank*p.digits+j+1)*p.degree])
                          for j in range(p.rank*p.digits)) for i in range(2*p.rank))
            master_geometry(p,r,Widths(params.master_first_squared,params.master_second_squared,params.r_squared))
            public=build_public(p,a_hat,r)
            pk=PublicKey(params,seed,public.b)
            return pk,MasterSecret(pk,r)
        raise RuntimeError("public root class admission invariant failed")

    def key_extract(self,msk,id_value):
        if not isinstance(msk,MasterSecret): raise TypeError("SRGG master secret required")
        from experiments.research.gaussian_reference import SamplingAbort
        c=msk.public_key.config; id_value=identity(c,id_value)
        if id_value in msk.states:
            status,key=msk.states[id_value]
            if status=="issued": return key
            raise SamplingAbort("identity already pending/failed; no reselection")
        if len(msk.states)>=c.max_users: raise SamplingAbort("identity issuance budget exhausted")
        from . import runtime
        msk.states[id_value]=("pending",None)
        try:
            tail=runtime.extract_tail(msk,identity_target(msk.public_key,id_value),self.rng)
            try: key=SigningKey(msk.public_key,id_value,tail)
            except ValueError as e: raise SamplingAbort("extracted key outside fixed norm class") from e
            msk.states[id_value]=("issued",key)
            return key
        except Exception:
            msk.states[id_value]=("failed",None)
            raise

    def sign(self,sk,raw_message):
        if not isinstance(sk,SigningKey): raise TypeError("SRGG signing key required")
        from . import runtime
        from experiments.research.gaussian_reference import SamplingAbort
        c=sk.public_key.config; raw_message=message(c,raw_message)
        for _ in range(c.sign_max_attempts):
            z,challenge=runtime.sign_attempt(sk,raw_message,self.rng)
            sig=Signature(sk.public_key.context,z,challenge)
            p=c.algebra
            if len(sig.z)!=p.columns+1 or len(sig.challenge)!=p.degree:
                raise RuntimeError("SRGG sampler response/challenge shape invariant failed")
            if sum(v*v for poly in sig.z for v in poly)>c.signature_bound_squared:
                continue  # only paper Algorithm7 norm rejection
            if not self.verify(sk.public_key,sk.identity,raw_message,sig):
                raise RuntimeError("honest SRGG commitment/challenge invariant failed")
            return sig
        raise SamplingAbort("Algorithm7 norm-rejection attempt budget exhausted")

    def verify(self,pk,id_value,raw_message,sig):
        try:
            if not isinstance(pk,PublicKey) or not signature_shape(pk,sig): return False
            id_value=identity(pk.config,id_value); raw_message=message(pk.config,raw_message)
            commitment=recover_commitment(pk.public,identity_target(pk,id_value),sig.z,sig.challenge)
            return message_challenge(pk,commitment,raw_message)==sig.challenge
        except (EncodingError,SerializationError,ValueError,TypeError,AttributeError,OverflowError): return False

    def load_signature(self,pk,data):
        if not isinstance(pk,PublicKey): raise TypeError("SRGG public key required")
        sig=Signature.from_bytes(data)
        if not signature_shape(pk,sig): raise SerializationError("SRGG signature context/shape/norm invalid")
        return sig
