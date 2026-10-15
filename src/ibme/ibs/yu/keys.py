"""Validated integer-basis snapshots and persistent fixed-issuance ledger.

Private snapshots are plaintext. Algebraic validation is not provenance,
distribution certification, authenticated storage or malicious rollback defence.
"""
from threading import RLock
from ibme.ibs.api import IBSMasterSecret, IBSSigningKey
from ibme.core.hashing import hash_identity
from ibme.core.errors import SerializationError
from .codec import fields, checked_matrix, input_bytes, input_bits, encode, decode
from .objects import PublicKey, public_data, parse_public


def _hex_identity(text,params):
    if type(text) is not str or not text or len(text)>2*params.identity_max_bytes:
        raise SerializationError("invalid Yu identity")
    try: value=bytes.fromhex(text)
    except ValueError: raise SerializationError("invalid Yu identity") from None
    if value.hex()!=text: raise SerializationError("noncanonical Yu identity")
    return input_bytes(value,params.identity_max_bytes,identity=True)


def _basis(public,rows):
    from .runtime import main_thread
    main_thread()
    from experiments.research.chkp_basis import KernelBasis,ModMatrixReference
    return KernelBasis(ModMatrixReference(public[0],public[1]),rows)


def user_data(key):
    return dict(identity=key.identity.hex(),r_hat=key.raw.r_hat,
                c_hat=key.raw.c_hat,basis=key.raw.basis.basis_rows)


def check_user_data(data,p):
    fields(data,("identity","r_hat","c_hat","basis"))
    identity=_hex_identity(data["identity"],p)
    from experiments.research.candidates.yu.evaluation import bits
    pattern=bits(data["r_hat"],p.output_bits)
    block=checked_matrix(data["c_hat"],p.n,p.w,modulus=p.q)
    basis=checked_matrix(data["basis"],p.m+p.w,p.m+p.w)
    return identity,pattern,block,basis


def restore_user(public,parts):
    from experiments.research.candidates.yu.standalone import UserKey as RawUser
    identity,pattern,block,rows=parts
    augmented=tuple(a+b for a,b in zip(public.raw.a,block))
    raw=RawUser(public.raw,input_bits(identity,public.params.identity_max_bytes,identity=True),
        pattern,block,_basis((augmented,public.params.q),rows))
    return SigningKey(public,identity,raw)


class SigningKey(IBSSigningKey):
    def __init__(self,public_key,identity,raw):
        from experiments.research.candidates.yu.standalone import UserKey as RawUser
        if type(public_key) is not PublicKey or type(raw) is not RawUser:
            raise TypeError("Yu signing key requires validated public/user objects")
        self._public_key=public_key
        self._identity=input_bytes(identity,self.params.identity_max_bytes,identity=True)
        if raw.public!=public_key.raw or raw.identity!=input_bits(self._identity,self.params.identity_max_bytes,identity=True):
            raise ValueError("Yu signing identity/public key mismatch")
        self._raw=raw
    @property
    def public_key(self): return self._public_key
    @property
    def params(self): return self.public_key.params
    @property
    def raw(self): return self._raw
    def validate_binding(self):
        if (self.raw.public!=self.public_key.raw or self.public_key.raw.params!=self.params.raw()
                or self.raw.identity!=input_bits(self.identity,self.params.identity_max_bytes,identity=True)):
            raise SerializationError("Yu signing key public/identity/parameter binding changed")
    @property
    def identity(self): return self._identity
    @property
    def identity_digest(self): return hash_identity(self.identity,32)
    def to_bytes(self):
        self.validate_binding()
        return encode("SK",dict(public=public_data(self.public_key),user=user_data(self)))
    @classmethod
    def from_bytes(cls,data):
        try:
            value=fields(decode("SK",data),("public","user"))
            public=parse_public(value["public"])
            return restore_user(public,check_user_data(value["user"],public.params))
        except (ValueError,TypeError,KeyError,RecursionError,OverflowError):
            raise SerializationError("invalid Yu signing key") from None
    def __repr__(self): return "YuSigningKey(trapdoor=<redacted>)"


class MasterSecret(IBSMasterSecret):
    def __init__(self,public_key,raw):
        from experiments.research.candidates.yu.standalone import MasterKey as RawMaster
        if type(public_key) is not PublicKey or type(raw) is not RawMaster or raw.public!=public_key.raw:
            raise ValueError("Yu master/public mismatch")
        self._public_key,self._raw=public_key,raw
        self._keys,self._ledger={},{}
        self._lock=RLock()
        self._active=False
        self.persist_callback=None

    @property
    def public_key(self): return self._public_key
    @property
    def raw(self): return self._raw
    @property
    def params(self): return self.public_key.params
    def validate_binding(self):
        if self.raw.public!=self.public_key.raw or self.public_key.raw.params!=self.params.raw():
            raise SerializationError("Yu master public/parameter binding changed")

    def to_bytes(self):
        with self._lock:
            self.validate_binding()
            ledger=[]
            for identity,status in sorted(self._ledger.items()):
                entry=dict(identity=identity.hex(),status=status)
                if status=="issued": entry["user"]=user_data(self._keys[identity])
                ledger.append(entry)
            return encode("MSK",dict(public=public_data(self.public_key),
                basis=self.raw.basis.basis_rows,ledger=ledger))

    @classmethod
    def from_bytes(cls,data):
        try:
            value=fields(decode("MSK",data),("public","basis","ledger"))
            public=parse_public(value["public"])
            p=public.params
            rows=checked_matrix(value["basis"],p.m,p.m)
            ledger=value["ledger"]
            if type(ledger) is not list or len(ledger)>p.max_users: raise ValueError("ledger capacity")
            checked=[]
            previous=b""
            for item in ledger:
                if type(item) is not dict or item.get("status") not in ("pending","failed","issued"):
                    raise ValueError("invalid ledger state")
                status=item["status"]
                fields(item,("identity","status","user") if status=="issued" else ("identity","status"))
                identity=_hex_identity(item["identity"],p)
                if identity<=previous: raise ValueError("unsorted or duplicate identity")
                previous=identity
                parts=check_user_data(item["user"],p) if status=="issued" else None
                if parts is not None and parts[0]!=identity: raise ValueError("ledger/user mismatch")
                checked.append((identity,status,parts))
            # Shape/count/range gates above run BEFORE expensive determinants.
            from experiments.research.candidates.yu.standalone import MasterKey as RawMaster
            master=cls(public,RawMaster(public.raw,_basis((public.raw.a,p.q),rows)))
            for identity,status,parts in checked:
                master._ledger[identity]=status
                if parts is not None: master._keys[identity]=restore_user(public,parts)
            return master
        except (ValueError,TypeError,KeyError,RecursionError,OverflowError):
            raise SerializationError("invalid Yu master state") from None
    def __repr__(self): return "YuMasterSecret(trapdoor=<redacted>, ledger=<redacted>)"
