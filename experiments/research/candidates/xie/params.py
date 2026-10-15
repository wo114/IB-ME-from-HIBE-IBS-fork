"""Explicit small execution domain; no paper-parameter or security admission."""
from dataclasses import asdict,dataclass
from .ring import prime

VERSION="XIE2016-EQUATION-STUDY/1"


@dataclass(frozen=True)
class StudyParams:
    n:int=16
    q:int=12289
    key_width:int=64
    extract_width:int=4096
    signing_width:int=65536
    challenge_weight:int=4
    rejection_m:int=4
    keygen_attempts:int=64
    signing_attempts:int=128
    identity_bytes:int=64
    message_bytes:int=65536
    max_identities:int=16
    entropy_limit:int=64*1024*1024
    tail_bits:int=64
    mass_bits:int=96
    precision_bits:int=192
    security_claim:str="none"
    backend_admitted:bool=False
    parameters_are_formal:bool=False

    def __post_init__(self):
        ranges={"n":(16,32),"q":(7,65537),"key_width":(2,256),"extract_width":(64,32768),
            "signing_width":(1024,524288),"challenge_weight":(1,self.n),"rejection_m":(2,16),
            "keygen_attempts":(1,256),"signing_attempts":(1,4096),"identity_bytes":(1,256),
            "message_bytes":(0,1024*1024),"max_identities":(1,64),"entropy_limit":(1,256*1024*1024),
            "tail_bits":(16,128),"mass_bits":(32,256),"precision_bits":(96,512)}
        for name,(low,high) in ranges.items():
            value=getattr(self,name)
            if type(value) is not int or not low<=value<=high:raise ValueError("study parameter: "+name)
        if self.n not in (16,32) or not prime(self.q) or (self.q-1)%(2*self.n):
            raise ValueError("study requires small power-of-two n and split prime q")
        if (type(self.security_claim) is not str or self.security_claim!="none"
                or self.backend_admitted is not False or self.parameters_are_formal is not False):
            raise ValueError("equation study has no security admission")

    def record(self):return asdict(self)
