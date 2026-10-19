"""HAL v1 Table 6/Appendix E inputs, with outward-rounded squared widths."""
from dataclasses import asdict, dataclass
from typing import ClassVar


@dataclass(frozen=True)
class RingParams:
    d: int
    k: int
    l: int
    identity_width_squared: int
    signature_width_squared: int
    r_squared: int = 49
    identity_max_bytes: int = 256
    message_max_bytes: int = 4096
    salt_bytes: int = 32
    max_users: int = 2
    max_sign_attempts: int = 64
    tail_bits: int = 256
    mass_bits: int = 320
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False
    parameters_are_formal: ClassVar[bool] = False

    def __post_init__(self):
        for name, low, high in (("d",4,2048),("k",4,153),("l",1,308),
                ("identity_width_squared",1,2**100),("signature_width_squared",1,2**100),
                ("r_squared",16,64),("identity_max_bytes",1,4096),
                ("message_max_bytes",0,2**20),("salt_bytes",1,64),
                ("max_users",1,32),("max_sign_attempts",1,256),
                ("tail_bits",128,512),("mass_bits",256,512)):
            v=getattr(self,name)
            if type(v) is not int or not low<=v<=high:
                raise ValueError("invalid ring parameter: "+name)
        if self.d & (self.d-1) or not max(2*self.k,21)<self.l<=2*self.k+self.k//2:
            raise ValueError("Table 4 ring shape condition fails")

    @property
    def q(self): return 3**self.k

    @property
    def signature_dimension(self): return self.d*(self.l+self.k)

    def record(self): return asdict(self)

    @classmethod
    def from_record(cls, record):
        if not isinstance(record,dict) or set(record)!=set(cls.__dataclass_fields__)-{
                "security_claim","backend_admitted","parameters_are_formal"}:
            raise ValueError("complete exact ring parameter snapshot required")
        return cls(**record)


def published(name="I"):
    """Use Appendix E's C constants, not rounded log(s) table entries.

    RIF upper endpoints are rounded upward to integer s^2. r^2 is an integer
    upper envelope for r_(dk,2^-200)^2, used by the concrete scalar sampler.
    Table 6 labels s as a standard deviation, while the paper's density uses
    exp(-pi*x^2/s^2); execution follows the density convention explicitly.
    """
    from sage.all import RealIntervalField
    if name not in ("I","II"): raise ValueError("choose I or II")
    d,k,l=2048,*( (65,132) if name=="I" else (153,308) )
    f=RealIntervalField(320); pi=f.pi()
    def r2(m): return (f(2*m)*(1+f(2)**200)).log()/pi
    def ff(m,n,c): return f(m).sqrt()+c*(f(n).sqrt()+(f(m)*f(3).log()).sqrt())
    binom2=ff(d*k,l-k,f(1)/2)**2/2
    sid2=max(176*r2(d*k)*(d*binom2+1),144*r2(d*l))
    sid=int(sid2.upper().ceil())
    gauss2=f(sid)/(2*pi)*ff(d*k,l,1)**2
    ss2=max(11*r2(d*k)*(d*gauss2+1),144*r2(d*(l+k)))
    return RingParams(d,k,l,sid,int(ss2.upper().ceil()),
                      r_squared=int(r2(d*k).upper().ceil()))


def small():
    return RingParams(4,9,22,2**36,2**66,r_squared=16)
