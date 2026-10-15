"""Coordinator-owned registry handoff; importing does not alter any registry."""
from ibme.core.errors import InvalidParameterError,SerializationError
from .params import YuParams,VERSION,preflight
from .objects import PublicKey,Signature
from .keys import MasterSecret,SigningKey
from .backend import YuIBS


def check_object(value,params):
    if type(value) not in (PublicKey,MasterSecret,SigningKey) or value.params!=params:
        raise SerializationError("Yu object differs from full parameter snapshot")
    if type(value) in (MasterSecret,SigningKey): value.validate_binding()
    elif value.raw.params!=params.raw():
        raise SerializationError("Yu public object differs from actual algorithm parameters")


def signature_size(params,signature_format):
    if signature_format!="reference": raise InvalidParameterError("Yu supports reference only")
    # JSON integer width varies. Reserve the maximum permitted int128 spelling,
    # not the observed size of a sampled signature, for conservative capacity.
    from .codec import encode
    return len(encode("SIG",dict(context="0"*64,s=[-(1<<127)]*params.signature_dimension,
        r_hat=[1]*params.output_bits,r_tilde=[1]*params.output_bits,salt=[1]*params.salt_bits)))


def factory(rng,signature_format):
    if signature_format!="reference": raise InvalidParameterError("Yu supports reference only")
    return YuIBS(rng)


def master_public_key(master):
    if type(master) is not MasterSecret: raise TypeError("expected Yu master")
    return master.public_key


def validate_configuration(params,config):
    try: preflight(params)
    except (ValueError,TypeError) as exc: raise InvalidParameterError("Yu research parameter preflight failed") from exc
    if isinstance(config,dict) and "protocol" in config:
        # Every currently supported byte profile is smaller than even the
        # baseline signature domain tag. Do not let generic compatibility
        # advertise a runnable Wang combination, hash/truncate its message,
        # or reach a late missing legacy capacity attribute.
        raise InvalidParameterError(
            "Yu standalone byte capacity is insufficient for Wang encoded messages; "
            "primitive adapter only, no combination admitted")


def validate_environment():
    import importlib.util
    if importlib.util.find_spec("sage") is None:
        raise InvalidParameterError("Yu requires WSL ~/miniconda3/envs/sage; no fallback")


def backend_spec():
    from ibme.assembly.registry import BackendSpec
    return BackendSpec("yu2026","ibs",VERSION,YuParams,{"debug-bytes-q3":YuParams()},factory,
        {"ipk":PublicKey,"imsk":MasterSecret,"sk":SigningKey},check_object,
        signature_size=signature_size,key_binding=True,persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot",master_public_key=master_public_key,
        validate_configuration=validate_configuration,validate_environment=validate_environment)
