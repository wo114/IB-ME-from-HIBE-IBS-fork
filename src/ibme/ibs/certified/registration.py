"""Optional common-interface descriptor; default catalogue stays unregistered."""
from ibme.core.errors import InvalidParameterError, SerializationError
from .params import CertifiedIBSParams, VERSION
from .objects import CertifiedPublicKey, CertifiedMasterSecret, CertifiedSigningKey, CertifiedSignature
from .backend import CertifiedIBS
from .mldsa import MLDSA, NativeFailure
from .falcon import Falcon, PROFILES as FALCON_PROFILES
from .mldsa import PROFILES as MLDSA_PROFILES
from .ordinary import PROFILES


def check_object(value, params):
    if getattr(value, "params", None) != params:
        raise SerializationError("certified IBS object differs from full parameter snapshot")


def signature_size(params, signature_format):
    if signature_format != "reference":
        raise InvalidParameterError("certified IBS supports only its canonical reference format")
    profile = PROFILES[params.base_algorithm]
    public=(bytes([profile.logn])+bytes(profile.public_key_bytes-1) if params.base_algorithm in FALCON_PROFILES
            else bytes(profile.public_key_bytes))
    return len(CertifiedSignature(params.base_algorithm, bytes(32), public,
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


def mldsa_configuration(params,config):
    if params.base_algorithm not in MLDSA_PROFILES:
        raise InvalidParameterError("cert-ml-dsa requires an ML-DSA profile")


def falcon_configuration(params,config):
    if params.base_algorithm not in FALCON_PROFILES:
        raise InvalidParameterError("cert-falcon requires a padded Falcon v1.2 profile")


def backend_spec():
    from ibme.assembly.registry import BackendSpec
    return BackendSpec("cert-ml-dsa", "ibs", VERSION, CertifiedIBSParams,
        {f"ml-dsa-{n}": CertifiedIBSParams(base_algorithm=f"ml-dsa-{n}") for n in (44,65,87)},
        factory, {"ipk":CertifiedPublicKey,"imsk":CertifiedMasterSecret,"sk":CertifiedSigningKey},
        check_object, signature_size=signature_size, key_binding=True, persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot", master_public_key=master_public_key,
        default_preset=lambda config:"ml-dsa-44", validate_environment=environment,
        validate_configuration=mldsa_configuration)


def falcon_environment():
    try:
        Falcon()
    except NativeFailure as exc:
        raise InvalidParameterError(str(exc)) from exc


def falcon_backend_spec():
    from ibme.assembly.registry import BackendSpec
    return BackendSpec("cert-falcon", "ibs", VERSION, CertifiedIBSParams,
        {f"falcon-padded-{n}": CertifiedIBSParams(base_algorithm=f"falcon-padded-{n}") for n in (512,1024)},
        factory, {"ipk":CertifiedPublicKey,"imsk":CertifiedMasterSecret,"sk":CertifiedSigningKey},
        check_object, signature_size=signature_size, key_binding=True, persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot", master_public_key=master_public_key,
        default_preset=lambda config:"falcon-padded-1024", validate_environment=falcon_environment,
        validate_configuration=falcon_configuration)
