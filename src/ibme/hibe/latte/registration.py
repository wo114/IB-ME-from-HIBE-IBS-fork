"""Descriptor for the LATTE-3 research implementation."""
import importlib.util
from ibme.core.errors import InvalidParameterError,SerializationError
from .params import LATTEParams,Q,N
from .objects import (LATTEPublicKey,LATTEMasterSecret,LATTELevel1SecretKey,LATTELevel2SecretKey,LATTECiphertext)

# The Hybrid transport requires a short lowercase identifier. This assembly
# version selects the same frozen IBME/LATTE3/COSAC-FIX/1 primitive wire.
ASSEMBLY_VERSION="latte3-cosac-fix-v1"


def check_object(value,params):
    if getattr(value,"params",None)!=params:
        raise SerializationError("LATTE object differs from selected full parameters")


def ciphertext_size(params,payload_bytes,identity_bytes):
    if (type(payload_bytes) is not int or type(identity_bytes) is not int or payload_bytes<0 or
            not 1<=identity_bytes<=params.identity_bytes or payload_bytes>params.max_payload_bytes or
            params.message_mode=="seed32" and payload_bytes!=32):
        raise InvalidParameterError("LATTE capacity exceeded")
    return len(LATTECiphertext(params,bytes(32),bytes(32),((Q-1,)*N,)*3).to_bytes())


def environment():
    # Discovery checks public dependencies/ABI without loading Sage arithmetic,
    # constructing rings, generating keys or consuming entropy.
    if importlib.util.find_spec("sage") is None or importlib.util.find_spec("sage.all") is None:
        raise InvalidParameterError("LATTE requires WSL ~/miniconda3/envs/sage; no fallback")
    from .engine import Native
    Native(LATTEParams())


def factory(rng,signature_format):
    from .backend import LATTEHIBE
    return LATTEHIBE()


def configuration(params,config):
    expected="hybrid" if params.message_mode=="seed32" else "direct"
    if config["transport"]!=expected:
        raise InvalidParameterError("LATTE plaintext framing differs from selected transport")


def backend_spec():
    from ibme.assembly.registry import BackendSpec,PROJECT_SECURITY_CLAIM
    return BackendSpec("latte3-research","hibe",ASSEMBLY_VERSION,LATTEParams,
        {"seed32":LATTEParams(),"framed32":LATTEParams(message_mode="framed32")},factory,
        {"hpk":LATTEPublicKey,"hmsk":LATTEMasterSecret,"sk1":LATTELevel1SecretKey,"sk2":LATTELevel2SecretKey},
        check_object,two_level=True,key_binding=True,persistent_identity_cache=True,
        reason="completed LATTE-3/COSAC-FIX backend; project admitted from cited paper security and HIBE-anonymity premise",
        ciphertext_size=ciphertext_size,object_parameter_binding="full-parameter-snapshot",
        default_preset=lambda transport:"seed32" if transport=="hybrid" else "framed32",
        validate_environment=environment,validate_configuration=configuration,
        security_claim=PROJECT_SECURITY_CLAIM,backend_admitted=True,
        formal_parameter_presets=("seed32","framed32"),
        admission_basis="LATTE-3 author profile, cited security result, project HIBE-anonymity premise, and completed lifecycle/combination acceptance")
