"""Explicit backend records. Registration is executable code, never JSON imports.

Descriptors describe engineering capabilities, not admitted security properties.
Parameter and object checks belong here, outside the shared Wang protocol.
"""
from dataclasses import dataclass, fields, replace
import math

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.lattice.params import Params
from ibme.lattice.gadget import gadget_width


@dataclass(frozen=True)
class BackendSpec:
    id: str
    role: str
    version: str
    params_type: object = None
    presets: object = None
    factory: object = None
    decoders: object = None
    check_object: object = None
    signature_size: object = None
    signature_formats: tuple = ("reference",)
    available: bool = True
    test_only: bool = False
    two_level: bool = False
    key_binding: bool = False
    persistent_identity_cache: bool = False
    reason: str = ""
    ciphertext_size: object = None

    def parse_params(self, values):
        if not self.available:
            if values != {}:
                raise InvalidParameterError("unavailable backend has no executable parameters")
            return None
        names = {f.name for f in fields(self.params_type)}
        if type(values) is not dict or set(values) != names:
            raise InvalidParameterError(f"{self.id}: expected complete parameter fields {sorted(names)}")
        try:
            return self.params_type(**values)
        except (TypeError, ValueError) as exc:
            raise InvalidParameterError(f"{self.id}: invalid parameters: {exc}") from exc


class BackendRegistry:
    """A caller-owned registry; duplicates fail instead of replacing code silently."""
    def __init__(self, specs=()):
        self._specs = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec):
        if not isinstance(spec, BackendSpec) or spec.role not in ("hibe", "ibs"):
            raise InvalidParameterError("invalid backend descriptor")
        if not spec.id or not spec.version or (spec.role, spec.id) in self._specs:
            raise InvalidParameterError("duplicate/empty backend identifier or version")
        if spec.available:
            required = (spec.factory, spec.check_object)
            keys = {"hpk", "hmsk", "sk1", "sk2"} if spec.role == "hibe" else {"ipk", "imsk", "sk"}
            if (not all(callable(x) for x in required) or not spec.presets
                    or not spec.decoders or set(spec.decoders) != keys
                    or any(not callable(getattr(x, "from_bytes", None)) for x in spec.decoders.values())
                    or (spec.role == "ibs" and not callable(spec.signature_size))
                    or (spec.role == "hibe" and not callable(spec.ciphertext_size))):
                raise InvalidParameterError("incomplete runnable backend descriptor")
        self._specs[spec.role, spec.id] = spec

    def get(self, role, identifier):
        try:
            return self._specs[role, identifier]
        except (KeyError, TypeError) as exc:
            raise InvalidParameterError(f"unknown {role} backend: {identifier!r}; no fallback") from exc

    def list(self):
        return {role: [dict(id=s.id, version=s.version, available=s.available,
                           test_only=s.test_only, reason=s.reason,
                           parameter_presets=sorted(s.presets or {}),
                           signature_formats=list(s.signature_formats),
                           two_level=s.two_level, key_binding=s.key_binding,
                           persistent_identity_cache=s.persistent_identity_cache)
                       for s in self._specs.values() if s.role == role]
                for role in ("hibe", "ibs")}


def _equal(actual, expected, label):
    if actual != expected:
        raise SerializationError(f"{label}: object differs from selected parameter snapshot")


def _abb_check(value, p):
    meta = value.meta
    _equal((meta.n, meta.m_bar, meta.q, meta.identity_bytes, meta.max_message_bytes,
            meta.s0, meta.s_enc, meta.s_pre),
           (p.n, p.m_matrix - p.n * gadget_width(p.q), p.q, p.identity_bytes,
            p.max_message_bytes, p.s0, p.s, p.s_prime), "ABB10")


def _mock_hibe_check(value, p):
    for name in ("identity_bytes", "max_message_bytes"):
        if hasattr(value, name):
            _equal(getattr(value, name), getattr(p, name), "mock HIBE")
    # The old TEST-ONLY level2 wire has no parameter snapshot. The CLI's
    # versioned suite envelope supplies the missing configuration binding.


def _sis_check(value, p):
    public = getattr(value, "public_key", value)
    _equal((public.n, public.m, public.q, public.s_prime, public.name),
           (p.n, p.m_matrix, p.q, p.s_prime, p.name), "SIS")
    if hasattr(value, "sigma"):
        _equal(value.sigma, p.s, "SIS sampling width")


def _luo_check(value, p):
    _equal(getattr(value, "public_key", value).params, p, "Luo")


def _sis_size(p, fmt):
    cols = p.m_matrix + p.n * gadget_width(p.q)
    bound = math.ceil(p.s_prime * math.sqrt(cols))
    width = max(1, (bound.bit_length() + 1 + 7) // 8)
    if width > 8:
        raise InvalidParameterError("SIS signature exceeds its 8-byte coefficient format")
    return len(b"IBS1-S-SIG") + 8 + cols * width


def _abb_ciphertext_size(p, payload, identity):
    # ABB10 v2 explicitly encrypts LP(parent)||LP(child)||LP(payload).
    cols = p.m_matrix + 2 * p.n * gadget_width(p.q)
    return len(b"IBME:HIBE-ABB10:CT:v2") + 12 + (12+2*identity+payload)*8*(cols+1)*((p.q.bit_length()+7)//8)


def _mock_ciphertext_size(p, payload, identity):
    return len(b"IBME:HIBE-MOCK:SER-CT:v1") + 8 + payload + 16


def _matrix_size(p, fmt):
    # MATRIX-REF/1: context, two signed-int64 vectors, modular W matrix.
    return (len(b"L24R1") + 4 + len(b"IBME/LUO2024/MATRIX-REF/1") + 4 + len(b"SIGNATURE")
            + 16 + 32 + 4 + 8*p.m + 4 + 8*p.k + 12 + ((p.q.bit_length()+7)//8)*p.n*p.k)


def _module_size(p, fmt):
    if fmt == "compact":
        from ibme.ibs.luo_module_codec import compact_layout
        return compact_layout(p)["signature_bytes"]
    width = max(1, (p.max_w1.bit_length() + 7) // 8)
    return (len(b"L24M1") + 4 + len(b"IBME/LUO2024/MODULE-REF/1") + 4 + len(b"SIGNATURE")
            + 24 + len(p.to_bytes()) + 64 + 8*p.l*p.degree + p.degree
            + width*p.k*p.degree + p.k*p.degree)


def default_registry():
    from ibme.hibe.abb10 import ABB10HIBE, ABB10PublicKey, ABB10MasterSecret, ABB10Level1SecretKey, ABB10Level2SecretKey, ABB10_DEBUG_PARAMS
    from ibme.hibe.mock import MockHIBE, MockHIBEPublicKey, MockHIBEMasterSecret, MockHIBELevel1SecretKey, MockHIBELevel2SecretKey
    from ibme.ibs.sis_ibs import SisIBSBackend, SisPublicKey, SisMasterSecret, SisSigningKey, IBS_EDUCATION_PARAMS
    from ibme.ibs.mock import MockIBSBackend, MockPublicKey, MockMasterSecret, MockSigningKey
    from ibme.ibs.luo import LuoIBSBackend, LuoMatrixParams, LuoPublicKey, LuoMasterSecret, LuoSigningKey
    from ibme.ibs.luo_module import LuoModuleIBSBackend, LuoModuleParams, LuoModulePublicKey, LuoModuleMasterSecret, LuoModuleSigningKey
    from ibme.ibs.luo_module_codec import LuoModuleCompactIBSBackend
    from ibme.protocol.byteauth import BYTEAUTH_DEBUG_PARAMS
    from ibme.protocol.baseline import BASELINE_MOCK_PARAMS

    # The legacy SIS implementation never enforced its Params input-limit
    # labels. This profile makes the shared assembly enforce explicit limits;
    # its lattice algorithm and numerical sampling parameters are unchanged.
    sis = replace(IBS_EDUCATION_PARAMS, identity_bytes=64, max_message_bytes=4096)
    hybrid = replace(ABB10_DEBUG_PARAMS, name="hybrid-abb10-short-debug", identity_bytes=86, max_message_bytes=32)
    mock = replace(BASELINE_MOCK_PARAMS, identity_bytes=64, max_message_bytes=65536)
    matrix = LuoMatrixParams(k=32, kappa=8, q=2**31-1, gamma1=4096, gamma2=131072,
                             identity_max_bytes=64, message_max_bytes=4096)
    tiny = LuoModuleParams(degree=8, k=2, l=1, q=769, root=27, kappa=1,
                           gamma1=16, gamma2=256, gamma3=128, dropped_bits=3)
    hs = lambda a,b,c,d: dict(hpk=a,hmsk=b,sk1=c,sk2=d)
    ins = lambda a,b,c: dict(ipk=a,imsk=b,sk=c)
    specs = [
        BackendSpec("abb10", "hibe", "abb10-debug-v2", Params,
                    {"education": BYTEAUTH_DEBUG_PARAMS, "hybrid-research": hybrid},
                    lambda rng, fmt: ABB10HIBE(), hs(ABB10PublicKey,ABB10MasterSecret,ABB10Level1SecretKey,ABB10Level2SecretKey),
                    _abb_check, two_level=True, key_binding=True,
                    reason="teaching ABB10; not security admitted",ciphertext_size=_abb_ciphertext_size),
        BackendSpec("mock", "hibe", "mock-hibe-v1", Params,
                    {"education": mock, "hybrid-research": replace(mock,identity_bytes=86,max_message_bytes=32)},
                    lambda rng, fmt: MockHIBE(), hs(MockHIBEPublicKey,MockHIBEMasterSecret,MockHIBELevel1SecretKey,MockHIBELevel2SecretKey),
                    _mock_hibe_check, test_only=True, two_level=True,key_binding=True,reason="TEST-ONLY; no cryptographic security",
                    ciphertext_size=_mock_ciphertext_size),
        BackendSpec("sis", "ibs", "sis-teaching-v1", Params, {"education": sis},
                    lambda rng, fmt: SisIBSBackend(rng=rng), ins(SisPublicKey,SisMasterSecret,SisSigningKey),
                    _sis_check,_sis_size,reason="teaching SIS; known forgery control retained"),
        BackendSpec("mock", "ibs", "mock-ibs-v1", Params, {"education": replace(mock,max_message_bytes=4096)},
                    lambda rng, fmt: MockIBSBackend(rng=rng), ins(MockPublicKey,MockMasterSecret,MockSigningKey),
                    lambda obj,p: None,lambda p,fmt:len(b"IBS1-M-SIG")+32,test_only=True,reason="TEST-ONLY; public master material"),
        BackendSpec("luo-matrix", "ibs", "luo-matrix-ref1", LuoMatrixParams,
                    {"research":matrix,"test-small":replace(LuoMatrixParams(),identity_max_bytes=64,message_max_bytes=4096)},
                    lambda rng,fmt:LuoIBSBackend(rng=rng),ins(LuoPublicKey,LuoMasterSecret,LuoSigningKey),
                    _luo_check,_matrix_size,persistent_identity_cache=True,reason="functional research parameters; none/false"),
        BackendSpec("luo-module", "ibs", "luo-module-ref1", LuoModuleParams,
                    {"research":LuoModuleParams(),"test-small":tiny},
                    lambda rng,fmt:(LuoModuleCompactIBSBackend if fmt=="compact" else LuoModuleIBSBackend)(rng=rng),
                    ins(LuoModulePublicKey,LuoModuleMasterSecret,LuoModuleSigningKey),_luo_check,_module_size,
                    signature_formats=("reference","compact"),persistent_identity_cache=True,reason="research module backend; none/false"),
    ]
    for identifier in ("chkp", "latte", "lai-ideal-hibe", "gkr2025", "zhang2020", "abb-standard-selective", "chkp-standard"):
        specs.append(BackendSpec(identifier,"hibe","unavailable-v1",available=False,reason="public backend not delivered; no mock fallback"))
    for identifier in ("srgg2025","yu2026","sageloli-sis","sageloli-rsis","foo-li","wang-pw","cert-ml-dsa","cert-falcon","xie-ntru-ibs"):
        specs.append(BackendSpec(identifier,"ibs","unavailable-v1",available=False,reason="public backend not delivered; no mock fallback"))
    return BackendRegistry(specs)
