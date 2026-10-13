"""Explicit complete-IBS research profile, not an author security parameter set."""
from dataclasses import asdict, dataclass
from math import gcd
from typing import ClassVar

from .algebra import Params, integer


@dataclass(frozen=True)
class Config:
    degree: int = 8
    rank: int = 1
    p: int = 257
    base: int = 31
    digits: int = 3
    r_squared: int = 4
    master_first_squared: int = 2**23
    master_second_squared: int = 2**23
    signature_first_squared: int = 2**37
    signature_second_squared: int = 2**37
    user_norm_squared: int = 2**29
    signature_noise_factor: int = 2
    identity_max_bytes: int = 256
    message_max_bytes: int = 4096
    max_users: int = 16
    setup_max_attempts: int = 32
    sign_max_attempts: int = 16
    precision_bits: int = 192
    ticket_bits: int = 128
    scalar_tail_bits: int = 24
    scalar_mass_bits: int = 64
    gadget_tail_bits: int = 16
    security_claim: ClassVar[str] = "none"
    backend_admitted: ClassVar[bool] = False

    def __post_init__(self):
        p = self.algebra
        for name in ("r_squared", "master_first_squared", "master_second_squared",
                     "signature_first_squared", "signature_second_squared", "user_norm_squared"):
            integer(getattr(self,name),1,10**12,name)
        for name,high in (("identity_max_bytes",4096),("message_max_bytes",2**20),
                          ("max_users",64),("setup_max_attempts",128),("sign_max_attempts",128)):
            integer(getattr(self,name),1,high,name)
        integer(self.precision_bits,128,512,"precision_bits")
        integer(self.ticket_bits,64,256,"ticket_bits")
        integer(self.scalar_tail_bits,8,128,"scalar_tail_bits")
        integer(self.scalar_mass_bits,32,256,"scalar_mass_bits")
        integer(self.gadget_tail_bits,8,128,"gadget_tail_bits")
        if self.precision_bits<max(self.ticket_bits,self.scalar_mass_bits)+32:
            raise ValueError("precision must exceed ticket/mass bits by at least32")
        if self.signature_noise_factor != 2 or type(self.signature_noise_factor) is not int:
            raise ValueError("this version explicitly uses the zeta-consistent factor2 interpretation")
        if gcd(p.p,p.base)!=1 or (p.columns+1)*p.degree>128:
            raise ValueError("coprime gadget factors and bounded coefficient dimensions required")
        root_bound=2*p.rank*p.rank*p.digits*p.degree**2+p.rank*p.digits*p.degree
        if min(self.master_first_squared,self.master_second_squared)<=self.gadget_width_squared*root_bound+self.r_squared:
            raise ValueError("public widths must cover the entire CBD1 root class")
        user_bound=p.degree*self.user_norm_squared+p.degree
        if min(self.signature_first_squared,self.signature_second_squared)<=2*self.r_squared*user_bound+self.r_squared:
            raise ValueError("signature widths must cover the full admitted user norm class")
        if p.modulus**2<=4*self.signature_bound_squared:
            raise ValueError("require exact Q>2*gamma for this nontrivial norm research profile")

    @property
    def algebra(self): return Params(self.degree,self.rank,self.p,self.base,self.digits)
    @property
    def gadget_width_squared(self): return self.base**2*self.r_squared
    @property
    def signature_bound_squared(self):
        return self.degree*(2*self.rank*self.signature_first_squared+(self.rank*self.digits+1)*self.signature_second_squared)
    def record(self): return asdict(self)
    @classmethod
    def from_record(cls,values):
        if not isinstance(values,dict) or set(values)!=set(cls().record()): raise ValueError("complete parameter snapshot required")
        return cls(**values)
