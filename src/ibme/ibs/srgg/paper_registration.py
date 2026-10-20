"""Lazy public selection for the fixed Table 4 SRGG implementation.

Discovery and capacity planning need neither Sage arithmetic nor key entropy.
This selector is separate from the unsafe degree8 SRGG research profile.
"""
from dataclasses import dataclass
from fractions import Fraction
import importlib.util
import json

from ibme.core.errors import InvalidParameterError, SerializationError
from experiments.research.candidates.srgg.paper_profiles import profile

BACKEND_ID = 'srgg2025-paper'
VERSION = 'SRGG-PAPER-TABLE4-factor1-v1'
FORMATS = ('reference', 'compact')
INTERPRETATIONS = ('table-standard-deviation', 'literal-density-width')


@dataclass(frozen=True)
class PaperSuiteParams:
    """Select a complete frozen paper profile; limits are fixed API contracts.

PaperParams itself imports Sage interval arithmetic. Keep its two selection
fields portable here and construct the original object only for execution.
The numeric profiles, source/conventions and retry policy are versioned by
the existing paper implementation, not replaced with free numeric fields.
"""
    profile_name: str = 'PARAM-I'
    interpretation: str = 'table-standard-deviation'

    def __post_init__(self):
        profile(self.profile_name)
        if type(self.interpretation) is not str or self.interpretation not in INTERPRETATIONS:
            raise ValueError('explicit published Gaussian interpretation required')

    @property
    def identity_max_bytes(self): return 4096

    @property
    def message_max_bytes(self): return 65536

    def paper_params(self):
        from experiments.research.candidates.srgg.paper_parameters import PaperParams
        return PaperParams(self.profile_name, self.interpretation)


def _params(params):
    if type(params) is not PaperSuiteParams:
        raise InvalidParameterError('complete paper SRGG selection required')
    return profile(params.profile_name)


def _format(fmt):
    if fmt not in FORMATS:
        raise InvalidParameterError('paper SRGG supports explicit reference/compact only')


def signature_size(params, fmt):
    """Conservative wire bound from the original norm cap, without sampling.

Each integer coordinate is bounded by floor(gamma). The all-extrema vector
need not be a valid signature; it bounds every valid JSON/bit-pack length.
"""
    p = _params(params)
    _format(fmt)
    bound = int(Fraction(p.gamma))
    count = ((2+p.digits)*p.rank+1)*p.degree
    if fmt == 'compact':
        width = (2*bound).bit_length()
        return len(b'IBME/SRGG-COMPACT\x00')+4+32+32+2+(count*width+7)//8+(p.degree+7)//8
    record = dict(schema='IBME/SRGG-PAPER-OBJECT/1', kind='signature', context='00'*32,
                  response=[[-bound]*p.degree]*((2+p.digits)*p.rank+1), challenge=[1]*p.degree)
    return len(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii'))


@dataclass(frozen=True)
class _PaperDecoder:
    object_name: str

    def from_bytes(self, data):
        from experiments.research.candidates.srgg import paper_objects
        return getattr(paper_objects,self.object_name).from_bytes(data)


def check_object(value, params):
    _params(params)
    from experiments.research.candidates.srgg import paper_objects as objects
    if type(value) not in (objects.PublicKey, objects.MasterSecret, objects.SigningKey):
        raise SerializationError('paper SRGG object type mismatch')
    public = value if type(value) is objects.PublicKey else value.public_key
    if public.params != params.paper_params():
        raise SerializationError('paper SRGG object differs from selected profile/interpretation')


def master_public_key(master):
    from experiments.research.candidates.srgg.paper_objects import MasterSecret
    if type(master) is not MasterSecret:
        raise TypeError('paper SRGG MasterSecret required')
    return master.public_key


def factory(rng, fmt):
    _format(fmt)
    from .paper import Backend
    return Backend(rng=rng,signature_format=fmt)


def environment():
    if importlib.util.find_spec('sage') is None or importlib.util.find_spec('sage.all') is None:
        raise InvalidParameterError('paper SRGG requires WSL ~/miniconda3/envs/sage; no fallback')


def validate_configuration(params, config):
    _params(params)
    if PaperSuiteParams(params.profile_name,params.interpretation) != params:
        raise InvalidParameterError('paper SRGG parameter snapshot mismatch')


def backend_spec():
    from ibme.assembly.registry import BackendSpec, COMPLETED_SECURITY_CLAIM
    return BackendSpec(
        BACKEND_ID,'ibs',VERSION,PaperSuiteParams,
        {name:PaperSuiteParams(name) for name in ('PARAM-I','PARAM-II','PARAM-III')},
        factory,{'ipk':_PaperDecoder('PublicKey'),'imsk':_PaperDecoder('MasterSecret'),
                 'sk':_PaperDecoder('SigningKey')},check_object,
        signature_size=signature_size,signature_formats=FORMATS,
        key_binding=True,persistent_identity_cache=True,
        object_parameter_binding='full-parameter-snapshot',master_public_key=master_public_key,
        validate_configuration=validate_configuration,validate_environment=environment,
        reason='completed SRGG Table 4 factor1 profiles; project admitted',
        security_claim=COMPLETED_SECURITY_CLAIM,backend_admitted=True,
        formal_parameter_presets=('PARAM-I','PARAM-II','PARAM-III'),
        admission_basis='cited SRGG security result, frozen Table 4 profiles, and completed standalone/common-combination acceptance')
