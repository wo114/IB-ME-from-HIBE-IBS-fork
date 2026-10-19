"""HAL v1 Figure 7 with native exact arithmetic and structured perturbations."""
import numpy as np
from ibme.core.randomness import SecureRandom
from ibme.core.encoding import encode_bytes
from ..uniform import uniform_mod_q,shake_uniform_mod_q,UniformSamplingAbort
from .params import RingParams
from .objects import PublicKey,MasterSecret,SigningKey,Signature,_identity
from .native import Library,SmallMatrix,WideRow
from .spectral import FourierPlan
from .gaussian import ByteSource,SamplingAbort,ternary


def norm_squared(values):return sum(int(x)**2 for x in np.asarray(values).flat)


def tail_ok(z,first,width):
    return (norm_squared(z[:first])<=2*z[:first].size*width and
            norm_squared(z[first:])<=2*z[first:].size*width)


def _message(p,value):
    if type(value) is not bytes or len(value)>p.message_max_bytes:raise ValueError("message byte domain")
    return value


def h1(pk,r,identity):
    p=pk.params;_identity(p,identity)
    if type(r) is not bytes or len(r)!=p.salt_bytes: raise ValueError("identity salt")
    data=encode_bytes(pk.context)+encode_bytes(r)+encode_bytes(identity)
    values=shake_uniform_mod_q(b"IBME:SAGELOLI-RSIS-H1:v3",data,p.q,p.k*p.d,max_trials_per_value=320)
    return np.array(values,dtype=object).reshape(p.k,p.d)


def h2(pk,r,s,identity,message):
    p=pk.params;_identity(p,identity);_message(p,message)
    if any(type(v) is not bytes or len(v)!=p.salt_bytes for v in (r,s)):raise ValueError("signature salts")
    data=b"".join(map(encode_bytes,(pk.context,r,identity,s,message)))
    return np.array(shake_uniform_mod_q(b"IBME:SAGELOLI-RSIS-H2:v3",data,p.q,p.d,
                                      max_trials_per_value=320),dtype=object)


def _center(z,q):
    if q>2**63:
        if any(abs(int(x))>q//2 for x in z.flat):raise SamplingAbort("wide canonical signed coefficient domain")
        return z
    return (z+q//2)%q-q//2


class RingBackend:
    route="rsis-structured-v3"
    security_claim="none";backend_admitted=False;parameters_are_formal=False

    def __init__(self,rng=None,*,native_path=None,progress=None):
        self.rng=SecureRandom() if rng is None else rng
        self.source=ByteSource(self.rng);self.library=Library(native_path);self.progress=progress

    def _event(self,kind,current,total):
        if self.progress:self.progress(kind,current,total)

    def _public_row(self,pk):
        if getattr(pk,"_native",None) is None:pk._native=WideRow(self.library,pk.a,pk.params.q)
        return pk._native

    def setup(self,params):
        if not isinstance(params,RingParams):raise TypeError("RingParams required")
        p=params
        abar=np.array(uniform_mod_q(self.source,p.q,(p.l-p.k)*p.d,
                                   max_trials_per_value=320),dtype=object).reshape(p.l-p.k,p.d)
        raw=np.frombuffer(self.source.read((p.l-p.k)*p.k*p.d),dtype=np.uint8)
        root=((raw&1).astype(np.int64)-((raw>>1)&1).astype(np.int64)).reshape(p.l-p.k,p.k,p.d)
        root[:,:,:p.d//4]*=4;root[:,:,3*p.d//4:]*=4
        a=np.empty((p.l,p.d),dtype=object);a[:p.l-p.k]=abar
        row=WideRow(self.library,abar,p.q)
        for j in range(p.k):
            value=-row.apply(root[:,j,:]);value[0]+=3**j
            a[p.l-p.k+j]=value%p.q
            self._event("setup-public",j+1,p.k)
        row.close();pk=PublicKey(p,a)
        return pk,MasterSecret(pk,root)

    def _sample(self,pk,plan,native,target,*,negative,extra=None):
        p=pk.params;perturb=plan.sample(self.source,tail_bits=p.tail_bits,mass_bits=p.mass_bits)
        row=self._public_row(pk) if extra is None else extra
        residual=(target-row.apply(perturb))%p.q
        digits=ternary(residual,p.k,p.r_squared,self.source,tail_bits=p.tail_bits,mass_bits=p.mass_bits)
        correction=native.apply(digits)
        out=perturb.copy();out[:plan.top]+=(-correction if negative else correction)
        out[plan.top:]+=digits
        # Exact output equation is checked at each call, including delegation.
        if any(int(x) for x in (row.apply(out)-target)%p.q):
            raise SamplingAbort("exact ring SampleDR equation failed")
        return out

    def key_extract(self,master,identity):
        if not isinstance(master,MasterSecret):raise TypeError("v3 ring master required")
        pk=master.public_key;p=pk.params;identity=_identity(p,identity)
        with master._lock:
            entry=master.states.get(identity)
            if entry:
                if (entry[0]=="issued" and isinstance(entry[1],SigningKey)
                        and entry[1].identity==identity and entry[1].public_key.context==pk.context):
                    return entry[1]
                if entry[0]=="issued":master.states[identity]=("failed",None)
                raise SamplingAbort("identity pending/failed; no automatic reissue")
            if len(master.states)>=p.max_users:raise SamplingAbort("identity capacity")
            master.states[identity]=("pending",None)
            try:
                if master._plan is None:
                    master._plan=FourierPlan(-master.root,p.identity_width_squared,p.r_squared,progress=self.progress)
                if master._native is None:master._native=SmallMatrix(self.library,master.root)
                salt=self.source.read(p.salt_bytes);h=h1(pk,salt,identity)
                trapdoor=np.empty((p.l,p.k,p.d),dtype=np.int64)
                for j in range(p.k):
                    target=h[j].copy();target[0]=(int(target[0])-3**j)%p.q
                    z=self._sample(pk,master._plan,master._native,target,negative=False)
                    if not tail_ok(z,p.l-p.k,p.identity_width_squared):raise SamplingAbort("raw identity tail gate")
                    trapdoor[:,j,:]=z;self._event("extract-column",j+1,p.k)
                key=SigningKey(pk,identity,salt,trapdoor);master.states[identity]=("issued",key)
                return key
            except BaseException:
                master.states[identity]=("failed",None);raise

    def sign(self,key,message):
        if not isinstance(key,SigningKey):raise TypeError("v3 ring signing key required")
        pk=key.public_key;p=pk.params;message=_message(p,message)
        h=h1(pk,key.identity_salt,key.identity)
        if key._plan is None:key._plan=FourierPlan(key.trapdoor,p.signature_width_squared,p.r_squared,progress=self.progress)
        if key._native is None:key._native=SmallMatrix(self.library,key.trapdoor)
        row=WideRow(self.library,np.concatenate((pk.a,h),axis=0),p.q)
        try:
            for _ in range(p.max_sign_attempts):
                salt=self.source.read(p.salt_bytes);target=h2(pk,key.identity_salt,salt,key.identity,message)
                z=_center(self._sample(pk,key._plan,key._native,target,negative=True,extra=row),p.q)
                if not np.any(z) or not tail_ok(z,p.l,p.signature_width_squared):continue
                return Signature(pk.context,key.identity_salt,salt,z,p)
        finally:row.close()
        raise SamplingAbort("signature tail rejection cap")

    def verify(self,pk,identity,message,signature):
        try:
            if not isinstance(pk,PublicKey) or not isinstance(signature,Signature):return False
            p=pk.params;_identity(p,identity);_message(p,message)
            if signature.params!=p or signature.context!=pk.context or not np.any(signature.z):return False
            if not np.array_equal(_center(signature.z,p.q),signature.z):return False
            if not tail_ok(signature.z,p.l,p.signature_width_squared):return False
            h=h1(pk,signature.identity_salt,identity)
            row=WideRow(self.library,np.concatenate((pk.a,h),axis=0),p.q)
            try:return np.array_equal(row.apply(signature.z),h2(pk,signature.identity_salt,signature.message_salt,identity,message))
            finally:row.close()
        except (ValueError,TypeError,OverflowError,SamplingAbort,UniformSamplingAbort):return False

    def load_signature(self,pk,raw):
        sig=Signature.from_bytes(raw,pk)
        if not np.array_equal(_center(sig.z,pk.params.q),sig.z) or not np.any(sig.z) or not tail_ok(
                sig.z,pk.params.l,pk.params.signature_width_squared):raise ValueError("invalid signature bounds")
        return sig

    def validate_signing_key(self,key):
        pk=key.public_key;p=pk.params;h=h1(pk,key.identity_salt,key.identity);row=self._public_row(pk)
        for j in range(p.k):
            target=h[j].copy();target[0]=(int(target[0])-3**j)%p.q
            if not tail_ok(key.trapdoor[:,j],p.l-p.k,p.identity_width_squared) or not np.array_equal(
                    row.apply(key.trapdoor[:,j]),target):raise ValueError("identity trapdoor relation/bound mismatch")
        return key

    def load_signing_key(self,raw,public_key=None):
        return self.validate_signing_key(SigningKey.from_bytes(raw,public_key))

    def load_master(self,raw):
        master=MasterSecret.from_bytes(raw);pk=master.public_key;p=pk.params
        row=WideRow(self.library,pk.a[:p.l-p.k],p.q)
        try:
            for j in range(p.k):
                expected=-row.apply(master.root[:,j]);expected[0]+=3**j
                if not np.array_equal(expected%p.q,pk.a[p.l-p.k+j]):raise ValueError("root trapdoor relation mismatch")
        finally:row.close()
        for status,key in master.states.values():
            if status=="issued":self.validate_signing_key(key)
        return master
