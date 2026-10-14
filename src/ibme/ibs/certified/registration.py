"""Optional common-interface descriptor; default catalogue stays unregistered."""
from ibme.core.errors import InvalidParameterError, SerializationError
from .params import CertifiedIBSParams, VERSION
from .objects import CertifiedPublicKey, CertifiedMasterSecret, CertifiedSigningKey, CertifiedSignature
from .backend import CertifiedIBS
from .mldsa import MLDSA, NativeFailure, PROFILES


def check_object(value, params):
    if getattr(value, "params", None) != params:
        raise SerializationError("certified IBS object differs from full parameter snapshot")


def signature_size(params, signature_format):
    if signature_format != "reference":
        raise InvalidParameterError("certified IBS supports only its canonical reference format")
    profile = PROFILES[params.base_algorithm]
    return len(CertifiedSignature(params.base_algorithm, bytes(32), bytes(profile.public_key_bytes),
                                 bytes(profile.signature_bytes), bytes(profile.signature_bytes)).to_bytes())


def environment():
    try:
        MLDSA()
    except NativeFailure as exc:
        raise InvalidParameterError(str(exc)) from exc


def factory(rng, signature_format):
    if signature_format != "reference":
        raise InvalidParameterError("certified IBS signature format")
    return CertifiedIBS(rng)


def master_public_key(master):
    if type(master) is not CertifiedMasterSecret:
        raise TypeError("expected CertifiedMasterSecret")
    return master.public_key


def backend_spec():
    from ibme.assembly.registry import BackendSpec
    return BackendSpec("cert-ml-dsa", "ibs", VERSION, CertifiedIBSParams,
        {f"ml-dsa-{n}": CertifiedIBSParams(base_algorithm=f"ml-dsa-{n}") for n in (44,65,87)},
        factory, {"ipk":CertifiedPublicKey,"imsk":CertifiedMasterSecret,"sk":CertifiedSigningKey},
        check_object, signature_size=signature_size, key_binding=True, persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot", master_public_key=master_public_key,
        default_preset=lambda config:"ml-dsa-44", validate_environment=environment)
