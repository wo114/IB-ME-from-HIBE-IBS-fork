"""Explicit optional registration proposal; default registry is unchanged."""
from ibme.core.errors import InvalidParameterError,SerializationError
from .params import LATTEParams,Q,N,VERSION
from .objects import (LATTEPublicKey,LATTEMasterSecret,LATTELevel1SecretKey,LATTELevel2SecretKey,LATTECiphertext)
from .backend import LATTEHIBE
from .engine import Native


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
    from .math import rings
    rings(); Native(LATTEParams())


def factory(rng,signature_format):
    return LATTEHIBE()


def configuration(params,config):
    expected="hybrid" if params.message_mode=="seed32" else "direct"
    if config["transport"]!=expected:
        raise InvalidParameterError("LATTE plaintext framing differs from selected transport")


def backend_spec():
    from ibme.assembly.registry import BackendSpec
    return BackendSpec("latte3-research","hibe",VERSION,LATTEParams,
        {"seed32":LATTEParams(),"framed32":LATTEParams(message_mode="framed32")},factory,
        {"hpk":LATTEPublicKey,"hmsk":LATTEMasterSecret,"sk1":LATTELevel1SecretKey,"sk2":LATTELevel2SecretKey},
        check_object,two_level=True,key_binding=True,persistent_identity_cache=True,
        ciphertext_size=ciphertext_size,object_parameter_binding="full-parameter-snapshot",
        default_preset=lambda config:"seed32" if config["transport"]=="hybrid" else "framed32",
        validate_environment=environment,validate_configuration=configuration)
