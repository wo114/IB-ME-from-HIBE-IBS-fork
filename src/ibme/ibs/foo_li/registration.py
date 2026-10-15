"""Explicit adapter for the coordinator; does not mutate the default registry."""
from ibme.core.errors import InvalidParameterError, SerializationError
from .params import FooLiParams, VERSION, preflight
from .objects import PublicKey, Signature
from .keys import MasterSecret, SigningKey
from .backend import FooLiIBS


def check_object(value, params):
    if type(value) not in (PublicKey, MasterSecret, SigningKey) or value.params != params:
        raise SerializationError("Foo-Li object differs from complete parameter snapshot")


def signature_size(params, signature_format):
    if signature_format != "reference":
        raise InvalidParameterError("Foo-Li supports only reference format")
    return len(Signature(bytes(32), (0,)*params.dimension, 0).to_bytes())


def factory(rng, signature_format):
    if signature_format != "reference":
        raise InvalidParameterError("Foo-Li supports only reference format")
    return FooLiIBS(rng)


def master_public_key(master):
    if type(master) is not MasterSecret:
        raise TypeError("expected Foo-Li MasterSecret")
    return master.public_key


def validate_configuration(params, config):
    try:
        preflight(params)
    except (ValueError, TypeError) as exc:
        raise InvalidParameterError("Foo-Li sampling class/resource preflight failed") from exc


def backend_spec():
    from ibme.assembly.registry import BackendSpec
    return BackendSpec("foo-li", "ibs", VERSION, FooLiParams,
        {"debug-q3": FooLiParams()}, factory,
        {"ipk": PublicKey, "imsk": MasterSecret, "sk": SigningKey}, check_object,
        signature_size=signature_size, key_binding=True, persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot",
        master_public_key=master_public_key, validate_configuration=validate_configuration)
