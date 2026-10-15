"""Public key and signature envelopes, with exact public-parameter binding."""
from dataclasses import asdict, dataclass, fields as dataclass_fields
from hashlib import sha256
from ibme.ibs.api import IBSPublicKey, IBSSignature
from ibme.core.errors import SerializationError
from .params import YuParams
from .codec import fields, checked_matrix, exact_int, encode, decode


def public_data(public):
    r=public.raw
    return dict(params=asdict(public.params),a=r.a,hat=r.hat,tilde=r.tilde)


def parse_public(data):
    fields(data,("params","a","hat","tilde"))
    values=fields(data["params"],(f.name for f in dataclass_fields(YuParams)))
    p=YuParams(**values)
    a=checked_matrix(data["a"],p.n,p.m,modulus=p.q)
    blocks=[]
    for name,count in (("hat",p.key_bits(p.identity_bits)),("tilde",p.key_bits(p.signing_input_bits))):
        value=data[name]
        if type(value) not in (list,tuple) or len(value)!=count:
            raise SerializationError("Yu public block count mismatch")
        blocks.append(tuple(checked_matrix(x,p.n,p.w,modulus=p.q) for x in value))
    from experiments.research.candidates.yu.standalone import PublicKey as RawPublic
    return PublicKey(p,RawPublic(p.raw(),a,*blocks))


@dataclass(frozen=True, repr=False, eq=False)
class PublicKey(IBSPublicKey):
    params: YuParams
    raw: object

    def __post_init__(self):
        from experiments.research.candidates.yu.standalone import PublicKey as RawPublic
        if type(self.params) is not YuParams or type(self.raw) is not RawPublic or self.raw.params!=self.params.raw():
            raise ValueError("Yu public key parameter mismatch")

    def to_bytes(self): return encode("PK",public_data(self))
    @property
    def context(self): return sha256(self.to_bytes()).digest()
    @classmethod
    def from_bytes(cls,data):
        try: return parse_public(decode("PK",data))
        except (ValueError,TypeError,KeyError,RecursionError,OverflowError):
            raise SerializationError("invalid Yu public key") from None
    def __repr__(self): return "YuPublicKey(material=<omitted>, security_claim='none')"


@dataclass(frozen=True, repr=False, eq=False)
class Signature(IBSSignature):
    context: bytes
    raw: object

    def __post_init__(self):
        from experiments.research.candidates.yu.standalone import Signature as RawSignature
        if type(self.context) is not bytes or len(self.context)!=32 or type(self.raw) is not RawSignature:
            raise ValueError("Yu signature type/context mismatch")
        # Revalidate Python-level construction; wire parsing also checks shapes.
        RawSignature(self.raw.s,self.raw.r_hat,self.raw.r_tilde,self.raw.salt)

    def to_bytes(self):
        return encode("SIG",dict(context=self.context.hex(),s=self.raw.s,
            r_hat=self.raw.r_hat,r_tilde=self.raw.r_tilde,salt=self.raw.salt))

    @classmethod
    def from_bytes(cls,data,public):
        if type(public) is not PublicKey:
            raise SerializationError("Yu signature needs its public key")
        try:
            value=fields(decode("SIG",data),("context","s","r_hat","r_tilde","salt"))
            if value["context"]!=public.context.hex(): raise ValueError("wrong public context")
            p=public.params
            values=[]
            for name,count,lo,hi in (("s",p.signature_dimension,-(1<<127),(1<<127)-1),
                    ("r_hat",p.output_bits,0,1),("r_tilde",p.output_bits,0,1),("salt",p.salt_bits,0,1)):
                seq=value[name]
                if type(seq) is not list or len(seq)!=count: raise ValueError("wrong signature shape")
                values.append(tuple(exact_int(x,lo,hi) for x in seq))
            from experiments.research.candidates.yu.standalone import Signature as RawSignature
            return cls(public.context,RawSignature(*values))
        except (ValueError,TypeError,KeyError,RecursionError,OverflowError):
            raise SerializationError("invalid Yu signature") from None
    def __repr__(self): return "YuSignature(material=<omitted>)"
