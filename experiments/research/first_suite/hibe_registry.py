"""Executable registration proposal for the source-checkout Sage HIBE.

Caller owns this registry; stock CLI/default registry and other owners' files
are unchanged. A registered real reference still has no security admission.
"""

from ibme.assembly import BackendRegistry, default_registry, make_suite
from ibme.assembly.registry import BackendSpec
from ibme.core.errors import InvalidParameterError, SerializationError
from .hibe_reference import (PROFILE,CT_MAGIC,MP12HIBEParams,MP12HIBEPublicKey,
    MP12HIBEMasterSecret,MP12HIBEReceiver,MP12HIBELeaf,MP12CHKPResearchHIBE)
from .seed_kem import MAGIC as SEED_MAGIC

BACKEND_ID = "mp12-chkp-reference"
BACKEND_VERSION = "mp12-chkp-finite-v1"


def raw_ciphertext_size(p,payload,identity):
    if type(payload) is not int or not 0<=payload<=32 or type(identity) is not int or not 1<=identity<=p.identity_bytes:
        raise InvalidParameterError("raw MP12 HIBE capacity exceeded")
    return len(CT_MAGIC)+4+4+len(SEED_MAGIC)+64+8+4+(3*p.m+256)*(((p.q-1).bit_length()+7)//8)


def check_object(value,p):
    if not isinstance(value,(MP12HIBEPublicKey,MP12HIBEMasterSecret,MP12HIBEReceiver,MP12HIBELeaf)):
        raise SerializationError("selected MP12 HIBE object type mismatch")
    pk = value if isinstance(value,MP12HIBEPublicKey) else value.pk
    if pk.params!=p: raise SerializationError("selected MP12 HIBE parameter snapshot mismatch")


def backend_spec(binary=None):
    def factory(rng,signature_format):
        if rng is not None or signature_format!="reference":
            raise InvalidParameterError("HIBE uses per-call entropy and reference wire")
        return MP12CHKPResearchHIBE(binary)
    return BackendSpec(id=BACKEND_ID,role="hibe",version=BACKEND_VERSION,params_type=MP12HIBEParams,
        presets={"n2-reference":MP12HIBEParams()},factory=factory,
        decoders=dict(hpk=MP12HIBEPublicKey,hmsk=MP12HIBEMasterSecret,sk1=MP12HIBEReceiver,sk2=MP12HIBELeaf),
        check_object=check_object,ciphertext_size=raw_ciphertext_size,two_level=True,key_binding=True,
        persistent_identity_cache=True,object_parameter_binding="full-parameter-snapshot",
        reason="Source-checkout Sage/qFALL reference; n2 is insecure; no formal or original-CHKP theorem admission")


def research_registry(binary):
    return BackendRegistry([backend_spec(binary),default_registry().get("ibs","luo-module")])


def research_suite(binary):
    registry = research_registry(binary)
    config = make_suite(hibe=BACKEND_ID,hibe_params="n2-reference",ibs="luo-module",
        transport="hybrid",signature_format="compact",registry=registry,
        hybrid_limits=dict(backend_id=BACKEND_VERSION,identity_max_bytes=64,
            max_payload_bytes=65536,max_capsule_bytes=4*2**20))
    return config,registry
