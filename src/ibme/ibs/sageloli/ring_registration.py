"""Portable, entropy-free registration of the existing structured RSIS v3.

The frozen numeric presets are the outward-rounded Appendix E evaluations
already executed in PR59. Discovery never constructs a sampler or compiles C++.
"""
from dataclasses import dataclass
import importlib.util
import os
from pathlib import Path

from ibme.core.errors import InvalidParameterError, SerializationError
from experiments.research.candidates.sageloli.ring import codec
from experiments.research.candidates.sageloli.ring.params import RingParams, small

BACKEND_ID = "sageloli-rsis"
VERSION = "Sageloli-RSIS-structured-v3"


def paper_params(profile="PARAM-I"):
    if profile == "PARAM-I":
        return RingParams(2048, 65, 132, 2720281532542, 270116709797628319132317)
    if profile == "PARAM-II":
        return RingParams(2048, 153, 308, 6438584418095, 1513219104215593870492656)
    raise InvalidParameterError("choose PARAM-I or PARAM-II")


def _params(params):
    if type(params) is not RingParams:
        raise InvalidParameterError("complete Sageloli ring v3 parameters required")
    return params


def _format(fmt):
    if fmt != "reference":
        raise InvalidParameterError("Sageloli ring v3 supports its reference binary format only")


def _frame_size(kind, count):
    return len(codec.MAGIC) + 1 + len(kind) + 4 + 8 * count


def signature_size(params, fmt):
    p = _params(params)
    _format(fmt)
    # Four fields: context, two salts and a rank-two signed int64 tensor.
    return _frame_size(b"signature", 4) + 32 + 2*p.salt_bytes + 12 + 8*p.signature_dimension


def state_size_bounds(params):
    """Wire upper bounds, including a full maximum-identity issued ledger.

    These are serialization capacities, not peak RAM or paper key sizes.
    No coefficient arrays, keys, sampling plans or randomness are allocated.
    """
    p = _params(params)
    public = _frame_size(b"public", 2) + len(codec.params_bytes(p)) + 12 + p.l*p.d*((p.q.bit_length()+7)//8)
    signing = _frame_size(b"signing", 4) + public + p.identity_max_bytes + p.salt_bytes + 16 + 8*p.l*p.k*p.d
    entry = _frame_size(b"entry", 3) + p.identity_max_bytes + len(b"issued") + signing
    ledger = _frame_size(b"ledger", p.max_users) + p.max_users*entry
    master = _frame_size(b"master", 3) + public + 16 + (p.l-p.k)*p.k*p.d + ledger
    return dict(public=public, signing_key=signing, master_with_full_ledger=master)


def check_object(value, params):
    _params(params)
    from experiments.research.candidates.sageloli.ring.objects import PublicKey, MasterSecret
    from .ring import SigningKey
    if type(value) not in (PublicKey, MasterSecret, SigningKey):
        raise SerializationError("Sageloli ring v3 object type mismatch; no v2 migration")
    public = value if type(value) is PublicKey else value.public_key
    if public.params != params:
        raise SerializationError("Sageloli ring object differs from full parameter snapshot")


def master_public_key(master):
    from experiments.research.candidates.sageloli.ring.objects import MasterSecret
    if type(master) is not MasterSecret:
        raise TypeError("Sageloli ring v3 master required")
    return master.public_key


@dataclass(frozen=True)
class Decoder:
    kind: str

    def from_bytes(self, raw):
        from .ring import decode_object
        return decode_object(self.kind, raw)


def environment():
    if importlib.util.find_spec("sage") is None or importlib.util.find_spec("sage.all") is None:
        raise InvalidParameterError("Sageloli ring v3 requires WSL ~/miniconda3/envs/sage; no fallback")
    path = os.environ.get("IBME_SAGELOLI_RING_NATIVE")
    if not path or not Path(path).is_file():
        raise InvalidParameterError("build ring v3 explicitly and set IBME_SAGELOLI_RING_NATIVE")


def validate_configuration(params, config):
    p = _params(params)
    if RingParams.from_record(p.record()) != p:
        raise InvalidParameterError("Sageloli ring parameter snapshot mismatch")
    if max(state_size_bounds(p).values()) > codec.MAX_BYTES:
        raise InvalidParameterError("Sageloli ring full issued ledger exceeds v3 state wire budget")


def factory(rng, fmt):
    _format(fmt)
    environment()
    from .ring import Backend
    return Backend(rng=rng)


def backend_spec():
    from ibme.assembly.registry import BackendSpec, PROJECT_SECURITY_CLAIM
    return BackendSpec(
        BACKEND_ID, "ibs", VERSION, RingParams,
        {"PARAM-I": paper_params(), "PARAM-II": paper_params("PARAM-II"), "debug-small": small()},
        factory, {name: Decoder(name) for name in ("ipk", "imsk", "sk")}, check_object,
        signature_size=signature_size, key_binding=True, persistent_identity_cache=True,
        object_parameter_binding="full-parameter-snapshot", master_public_key=master_public_key,
        default_preset=lambda transport: "PARAM-I", validate_configuration=validate_configuration,
        validate_environment=environment,
        reason="completed structured RSIS v3; Table 6 profiles project admitted; debug-small remains unsafe and excluded",
        security_claim=PROJECT_SECURITY_CLAIM,backend_admitted=True,
        formal_parameter_presets=("PARAM-I","PARAM-II"),
        admission_basis="cited Sageloli construction, frozen Table 6 profiles, and completed standalone/common-combination acceptance")
