"""Yu Figure 5 public five-method adapter; no hash-to-message substitution."""
from ibme.core.errors import IBMEError, InvalidParameterError, SerializationError, EncodingError
from ibme.ibs.api import IBSError
from .params import YuParams, preflight
from .codec import input_bytes,input_bits
from .objects import PublicKey, Signature
from .keys import MasterSecret, SigningKey
from .runtime import main_thread


class YuSamplingAbort(IBMEError):
    """One real sampling call aborted; no hidden retry or default signature."""


class IssuancePending(IBMEError):
    """Prior failed/pending issuance cannot automatically draw a new key."""


class YuIBS:
    def __init__(self,rng=None):
        from ibme.core.randomness import SecureRandom
        self.rng=SecureRandom() if rng is None else rng
        if not callable(getattr(self.rng,"read",None)): raise TypeError("rng must provide read(n)")

    def setup(self,params):
        if type(params) is not YuParams: raise InvalidParameterError("expected YuParams")
        main_thread()
        from experiments.research.candidates.yu import standalone as raw
        from experiments.research.gaussian_reference import SamplingAbort
        configuration=preflight(params)
        try: public,master=raw.setup(configuration,rng=self.rng)
        except SamplingAbort: raise YuSamplingAbort("Yu setup sampling aborted") from None
        pk=PublicKey(params,public)
        return pk,MasterSecret(pk,master)

    def key_extract(self,master,identity):
        if type(master) is not MasterSecret: raise TypeError("expected Yu MasterSecret")
        master.validate_binding()
        identity=input_bytes(identity,master.params.identity_max_bytes,identity=True)
        from experiments.research.candidates.yu import standalone as raw
        from experiments.research.gaussian_reference import SamplingAbort
        with master._lock:
            if master._active: raise IssuancePending("Yu recursive issuance is blocked")
            status=master._ledger.get(identity)
            if status=="issued": return master._keys[identity]
            if status is not None: raise IssuancePending("Yu identity has pending/failed issuance")
            if len(master._ledger)>=master.params.max_users: raise InvalidParameterError("Yu issuer capacity exhausted")
            main_thread() # cached reads above need no Sage/PARI call
            master._active=True
            master._ledger[identity]="pending"
            def persist():
                if master.persist_callback is not None: master.persist_callback(master)
            try:
                persist() # reserve before the first draw
                key=raw.keygen(master.raw,input_bits(identity,master.params.identity_max_bytes,identity=True),rng=self.rng)
                result=SigningKey(master.public_key,identity,key)
                master._keys[identity]=result
                master._ledger[identity]="issued"
                persist() # commit before publishing a key
                return result
            except BaseException as exc:
                master._keys.pop(identity,None)
                master._ledger[identity]="failed"
                try: persist()
                except BaseException: pass
                if isinstance(exc,SamplingAbort): raise YuSamplingAbort("Yu key extraction sampling aborted") from None
                raise
            finally: master._active=False

    def sign(self,key,message):
        if type(key) is not SigningKey: raise TypeError("expected Yu SigningKey")
        main_thread()
        key.validate_binding()
        message=input_bits(message,key.params.message_max_bytes)
        if key.raw.identity!=input_bits(key.identity,key.params.identity_max_bytes,identity=True) or key.raw.public!=key.public_key.raw:
            raise IBSError("Yu signing key identity/public binding changed")
        from experiments.research.candidates.yu import standalone as raw
        from experiments.research.gaussian_reference import SamplingAbort
        try: signature=raw.sign(key.raw,message,rng=self.rng)
        except SamplingAbort: raise YuSamplingAbort("Yu signing sampling aborted") from None
        if not raw.verify(key.public_key.raw,key.raw.identity,message,signature):
            raise IBSError("Yu sampler output failed its public equation")
        return Signature(key.public_key.context,signature)

    def verify(self,public,identity,message,signature):
        if type(public) is not PublicKey: return False
        try:
            identity=input_bits(identity,public.params.identity_max_bytes,identity=True)
            message=input_bits(message,public.params.message_max_bytes)
            if type(signature) is not Signature or signature.context!=public.context: return False
            from experiments.research.candidates.yu import standalone as raw
            return raw.verify(public.raw,identity,message,signature.raw)
        except (EncodingError,SerializationError,ValueError,TypeError,OverflowError): return False

    def load_signature(self,public,data): return Signature.from_bytes(data,public)
