"""Five-method adapter for the unchanged Table 4 SRGG arithmetic.

Keys retain the original canonical JSON representation/context. Only the
explicit compact signature boundary uses the existing lossless codec.
"""
from dataclasses import dataclass

from ibme.core.errors import SerializationError
from ibme.ibs.api import IBSBackend, IBSSignature
from .paper_registration import PaperSuiteParams, _format


@dataclass(frozen=True,eq=False,repr=False)
class CompactSignature(IBSSignature):
    public: object
    signature: object

    def __post_init__(self):
        from experiments.research.candidates.srgg.paper_objects import PublicKey, Signature
        if type(self.public) is not PublicKey or type(self.signature) is not Signature:
            raise SerializationError('paper SRGG public/signature objects required')
        norm=sum(x*x for poly in self.signature.response for x in poly)
        if norm>self.public.params.signature_norm_cap:
            raise SerializationError('paper SRGG signature exceeds original norm cap')
        self.to_bytes()  # Existing codec checks context and exact dimensions.

    def to_bytes(self):
        from experiments.research.candidates.srgg.paper_compact import dump_signature
        return dump_signature(self.public,self.signature)

    @classmethod
    def from_bytes(cls,data,public):
        from experiments.research.candidates.srgg.paper_compact import load_signature
        return cls(public,load_signature(public,data))

    def __repr__(self):return 'PaperSRGGCompactSignature(values=<redacted>)'


class Backend(IBSBackend):
    security_claim='none'
    backend_admitted=False
    parameters_are_formal=False
    nist_security_category=None

    def __init__(self,*,rng=None,signature_format='reference'):
        _format(signature_format)
        from experiments.research.candidates.srgg.paper_backend import Backend as PaperBackend
        self._backend=PaperBackend(rng=rng)
        self.rng=self._backend.rng
        self.signature_format=signature_format

    def setup(self,params):
        if type(params) is not PaperSuiteParams:
            raise TypeError('paper SRGG requires its explicit public parameter selection')
        return self._backend.setup(params.paper_params())

    def key_extract(self,master,identity):
        return self._backend.key_extract(master,identity)

    def sign(self,key,message):
        signature=self._backend.sign(key,message)
        if self.signature_format=='compact':
            return CompactSignature(key.public_key,signature)
        return signature

    def verify(self,public,identity,message,signature):
        if self.signature_format=='compact':
            from experiments.research.candidates.srgg.paper_objects import PublicKey
            if (type(public) is not PublicKey or type(signature) is not CompactSignature
                    or signature.public.context!=public.context):
                return False
            signature=signature.signature
        return self._backend.verify(public,identity,message,signature)

    def load_signature(self,public,data):
        if self.signature_format=='compact':
            return CompactSignature.from_bytes(data,public)
        return self._backend.load_signature(public,data)
