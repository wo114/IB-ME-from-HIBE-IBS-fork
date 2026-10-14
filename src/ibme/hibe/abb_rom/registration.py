"""A-owned registration proposal; does not change the shared default registry."""

from ibme.core.errors import SerializationError,InvalidParameterError
from ibme.lattice.research import sage_available
from .params import ABBROMParams
from .profiles import q104_research_params,q26_level_quality_research_params
from .objects import ABBPublicKey, ABBMasterSecret, ABBLevel1Key, ABBLevel2Key

BACKEND_ID = "abb-rom-finite"
VERSION = "abb-rom-ap09-matrix-finite-v1"


def check_object(value,params):
    public = getattr(value,"public_key",value)
    if not isinstance(public,ABBPublicKey) or public.params!=params:
        raise SerializationError("ABB object differs from selected exact profile")


def ciphertext_size(params,payload_bytes,identity_bytes):
    from .objects import header
    if type(payload_bytes) is not int or not 0<=payload_bytes<=params.payload_max_bytes:
        raise ValueError("ABB raw payload capacity")
    return len(header(b"CT",params))+64+4+8*payload_bytes*(params.dimension+1)*((params.q.bit_length()+7)//8)


def factory(rng,signature_format):
    from .backend import ABBROMHIBE
    if signature_format!="reference":raise ValueError("unknown ABB format")
    return ABBROMHIBE()


def validate_configuration(params,config):
    if config['transport']!='hybrid':
        raise InvalidParameterError('ABB seed32 research profile requires hybrid transport')
    from .backend import check_setup_profile
    try:
        check_setup_profile(params)  # public conditions/dependencies, no entropy
    except (ImportError,ValueError,OSError) as exc:
        raise InvalidParameterError('ABB public profile or local runtime dependency failed') from exc


def backend_spec():
    from ibme.assembly.registry import BackendSpec
    if not sage_available():
        return BackendSpec(BACKEND_ID,"hibe",VERSION,available=False,
            reason="ABB finite research requires WSL ~/miniconda3/envs/sage; no fallback")
    return BackendSpec(BACKEND_ID,"hibe",VERSION,ABBROMParams,
        {"n1-q160-research":ABBROMParams(),"n1-q104-single-address-research":q104_research_params(),
         "n1-q26-level-quality-research":q26_level_quality_research_params()},factory,
        dict(hpk=ABBPublicKey,hmsk=ABBMasterSecret,sk1=ABBLevel1Key,sk2=ABBLevel2Key),
        check_object,two_level=True,key_binding=True,persistent_identity_cache=True,
        reason="q26 real full lifecycle and Luo combination passed; n1 research negative control, none/false; other profiles WIP",
        ciphertext_size=ciphertext_size,object_parameter_binding="full-parameter-snapshot",
        default_preset=lambda transport:'n1-q26-level-quality-research',
        validate_configuration=validate_configuration)
