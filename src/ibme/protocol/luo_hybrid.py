"""Explicit none/false research profile: hybrid ABB10 debug + Luo module IBS."""

from dataclasses import dataclass, replace

from ibme.core.encoding import encode_message
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.core.types import validate_bytes, validate_identity
from ibme.lattice.gadget import gadget_width
from ibme.hibe.abb10 import (ABB10HIBE, ABB10_DEBUG_PARAMS, ABB10PublicKey, ABB10MasterSecret,
                            ABB10Level1SecretKey, ABB10Level2SecretKey)
from ibme.ibs.luo_module import (LuoModuleIBSBackend, LuoModuleParams, LuoModulePublicKey,
                               LuoModuleMasterSecret, LuoModuleSigningKey)
from ibme.ibs.luo_module_codec import LuoModuleCompactIBSBackend
from ibme.ibs.luo_module_profiles import is_c64b_profile
from .baseline import PublicKey, SenderKey
from .byteauth import ByteAuthenticatedIBME, encode_bound_message, COMMITMENT_BYTES
from .hybrid_hibe import HybridHIBE, HybridHIBEParams, HybridLimits, HybridPublicKey, encoded_identity_bytes

PROFILE_NAME = "luo-module-research"
RESEARCH_LIMITS = HybridLimits()
RESEARCH_INNER_PARAMS = replace(ABB10_DEBUG_PARAMS, name="hybrid-abb10-short-debug",
                              max_message_bytes=32, identity_bytes=encoded_identity_bytes(RESEARCH_LIMITS.identity_max_bytes))
RESEARCH_HIBE_PARAMS = HybridHIBEParams(RESEARCH_INNER_PARAMS, RESEARCH_LIMITS)
RESEARCH_IBS_PARAMS = LuoModuleParams()
_INNER_SNAPSHOT = (
    RESEARCH_INNER_PARAMS.n,
    RESEARCH_INNER_PARAMS.m_matrix - RESEARCH_INNER_PARAMS.n * gadget_width(RESEARCH_INNER_PARAMS.q),
    RESEARCH_INNER_PARAMS.q, RESEARCH_INNER_PARAMS.identity_bytes,
    RESEARCH_INNER_PARAMS.max_message_bytes, RESEARCH_INNER_PARAMS.s0,
    RESEARCH_INNER_PARAMS.s, RESEARCH_INNER_PARAMS.s_prime,
)
MAX_APPLICATION_BYTES = RESEARCH_IBS_PARAMS.message_max_bytes - len(encode_message(
    b"x" * RESEARCH_LIMITS.identity_max_bytes, encode_bound_message(b"x" * COMMITMENT_BYTES, b"")))


def make_hybrid_abb10():
    return HybridHIBE(ABB10HIBE(), backend_id=RESEARCH_LIMITS.backend_id,
                      public_key_type=ABB10PublicKey, master_type=ABB10MasterSecret,
                      level1_type=ABB10Level1SecretKey, level2_type=ABB10Level2SecretKey)


class LuoHybridResearchIBME(ByteAuthenticatedIBME):
    security_claim = "none"
    backend_admitted = False

    def __init__(self, hibe_backend, ibs_backend, *, ots_rng=None, ibs_params=RESEARCH_IBS_PARAMS):
        super().__init__(hibe_backend, ibs_backend, ots_rng=ots_rng)
        self.research_ibs_params = ibs_params

    def setup(self, params, *, ibs_params=None, rng=None):
        selected = self.research_ibs_params if ibs_params is None else ibs_params
        if type(selected) is not LuoModuleParams or selected != self.research_ibs_params:
            raise InvalidParameterError("setup differs from the selected research Luo profile")
        return super().setup(params, ibs_params=selected, rng=rng)

    def encrypt(self, public, ek, receiver_id, message, *, rng=None):
        if not isinstance(public, PublicKey) or not isinstance(ek, SenderKey):
            raise TypeError("encrypt expects IBME public and sender keys")
        receiver = validate_identity(receiver_id, max_bytes=RESEARCH_LIMITS.identity_max_bytes)
        msg = validate_bytes(message, name="application message")
        if len(msg) > MAX_APPLICATION_BYTES:
            raise InvalidParameterError(f"research application message limit is {MAX_APPLICATION_BYTES} bytes")
        return super().encrypt(public, ek, receiver, msg, rng=rng)


@dataclass(frozen=True)
class _ProfileDecoder:
    decoder: object
    module: bool
    expected_ibs_params: LuoModuleParams = RESEARCH_IBS_PARAMS

    def from_bytes(self, data):
        value = self.decoder.from_bytes(data)
        if self.module:
            public = value if isinstance(value, LuoModulePublicKey) else value.public_key
            if public.params != self.expected_ibs_params:
                raise SerializationError("state uses a different Luo module parameter profile")
        else:
            public = value if isinstance(value, HybridPublicKey) else value.public_key
            if public.limits != RESEARCH_LIMITS:
                raise SerializationError("state uses different hybrid profile limits")
            # Only inspect the public parameter snapshots, never trapdoors.
            components = (public.inner,) if isinstance(value, HybridPublicKey) else (public.inner, value.inner)
            for component in components:
                meta = component.meta
                snapshot = (meta.n, meta.m_bar, meta.q, meta.identity_bytes,
                            meta.max_message_bytes, meta.s0, meta.s_enc, meta.s_pre)
                if snapshot != _INNER_SNAPSHOT:
                    raise SerializationError("state uses different inner HIBE parameter profile")
        return value


def make_research_runtime(*, ibs_rng=None, ots_rng=None, signature_format="reference", ibs_params=None):
    """Bind restoration to an explicitly selected research parameter snapshot.

    Selection does not migrate existing keys or grant security admission.
    setup uses this selection; an explicit mismatch fails before entropy use.
    Persist the selection in caller state. Legacy callers keep the old profile.
    """
    if signature_format not in ("reference", "compact"):
        raise InvalidParameterError("unknown research signature format")
    selected = RESEARCH_IBS_PARAMS if ibs_params is None else ibs_params
    if (type(selected) is not LuoModuleParams
            or (selected != RESEARCH_IBS_PARAMS and not is_c64b_profile(selected))):
        raise InvalidParameterError("unsupported research Luo parameter profile")
    hibe = make_hybrid_abb10()
    backend = LuoModuleCompactIBSBackend if signature_format == "compact" else LuoModuleIBSBackend
    protocol = LuoHybridResearchIBME(hibe, backend(rng=ibs_rng), ots_rng=ots_rng, ibs_params=selected)
    readers = {name: _ProfileDecoder(reader, False) for name, reader in hibe.component_decoders().items()}
    readers.update(ipk=_ProfileDecoder(LuoModulePublicKey, True, selected),
                   imsk=_ProfileDecoder(LuoModuleMasterSecret, True, selected),
                   sk=_ProfileDecoder(LuoModuleSigningKey, True, selected))
    return protocol, readers
