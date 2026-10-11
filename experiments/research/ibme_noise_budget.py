"""Portable rounded-noise profile and conditional shared-preamble budget.

This does not implement HIBE or authenticate a certificate. Supplied sampler
metadata is checked for parameter/arithmetic consistency only. Root/basis/key
norm failures and GPV TV/abort remain separate; no backend is admitted here.
"""

from dataclasses import dataclass,field
from fractions import Fraction
from math import isqrt
import re

from ibme.core.errors import InvalidParameterError
from .ibme_joint_parameters import evaluate_noise,integer,rational

SCHEMA="IBME/ROUNDED-CONTINUOUS-NOISE/1"
MAX_RADIUS=16384
CONFIG_FIELDS=("q","alpha","tail_bits","mass_bits","precision_bits","max_radius")


@dataclass(frozen=True)
class RoundedNoiseParams:
    q: int
    alpha: object
    tail_bits: int=80
    mass_bits: int=128
    precision_bits: int=256
    max_radius: int=8192
    security_claim: str=field(default="none",init=False)
    backend_admitted: bool=field(default=False,init=False)

    def __post_init__(self):
        try:
            integer(self.q,"q",low=2,high=2**61-1)
            rate=rational(self.alpha,"alpha")
            if not 0<rate<1 or not Fraction(1,256)<=self.q*rate<=16384:
                raise ValueError("need 0<alpha<1 and 1/256<=q*alpha<=16384")
            for name,low,high in (("tail_bits",8,256),("mass_bits",8,512),
                                  ("precision_bits",128,1024),("max_radius",1,MAX_RADIUS)):
                integer(getattr(self,name),name,low=low,high=high)
            if self.precision_bits<self.mass_bits+32:
                raise ValueError("CDF precision must be at least mass_bits+32")
            object.__setattr__(self,"alpha",rate)
            # A certified Chernoff cutoff; bound BEFORE any Sage/table work.
            square=(self.q*rate)**2*(self.tail_bits+1)
            radius=isqrt(square.numerator//square.denominator)
            if radius*radius<square:
                radius+=1
            if radius>self.max_radius:
                raise ValueError("rounded-noise support exceeds public radius budget")
        except ValueError as exc:
            raise InvalidParameterError(str(exc)) from exc

    @property
    def scaled_width(self):
        return self.q*self.alpha

    @property
    def radius(self):
        square=self.scaled_width**2*(self.tail_bits+1)
        value=isqrt(square.numerator//square.denominator)
        return value+int(value*value<square)

    def to_record(self):
        return {name:str(self.alpha) if name=="alpha" else getattr(self,name)
                for name in CONFIG_FIELDS}


def attach_finite_noise_budget(ideal,certificate):
    """Count D+L fresh scalar noises per shared-preamble encapsulation.

    Checks are not a substitute for the sampler's interval/construction proof.
    Invalid/missing error terms fail explicitly; never insert a default zero.
    """
    try:
        if not isinstance(ideal,dict) or not isinstance(certificate,dict):
            raise ValueError("budget and certificate must be dictionaries")
        if certificate["schema"]!=SCHEMA:
            raise ValueError("unknown rounded-noise certificate")
        config=certificate["config"]
        if not isinstance(config,dict) or set(config)!=set(CONFIG_FIELDS):
            raise ValueError("invalid rounded-noise configuration fields")
        params=RoundedNoiseParams(**config)
        if params.to_record()!=config:
            raise ValueError("noncanonical rounded-noise configuration")
        if ideal["q"]!=params.q or rational(ideal["alpha"],"alpha")!=params.alpha:
            raise ValueError("noise certificate differs from the selected q/alpha")
        dimension=integer(ideal["dimension"],"dimension")
        count=integer(ideal["seed_bits"],"seed_bits")
        calls=integer(ideal["encapsulations"],"encapsulations",high=2**32)
        recomputed=evaluate_noise(q=params.q,dimension=dimension,
                                  width_squared=ideal["width_squared"],alpha=params.alpha,
                                  error_bits=ideal["error_bits"],seed_bits=count,encapsulations=calls)
        if ideal!=recomputed:
            raise ValueError("ideal noise budget differs from its exact recomputation")
        tail=rational(certificate["tail_tv_upper"],"tail TV")
        quant=rational(certificate["cdf_quantization_and_interval_tv_upper"],"CDF TV")
        abort=rational(certificate["random_rejection_abort_upper"],"abort")
        total=rational(certificate["tv_upper_including_abort"],"total TV")
        units=integer(certificate["cdf_interval_error_units"],"CDF units",low=2*params.radius,
                      high=8*params.radius)
        if (tail!=Fraction(1,2**params.tail_bits) or abort!=0 or
                quant!=Fraction(units,2**params.mass_bits) or total!=min(1,tail+quant)):
            raise ValueError("noise error ledger is inconsistent")
        if certificate["support"]!=[-params.radius,params.radius]:
            raise ValueError("noise support differs from profile")
        if (type(certificate["draw_bytes"]) is not int or
                certificate["draw_bytes"]!=(params.mass_bits+7)//8):
            raise ValueError("noise draw size differs from profile")
        if not isinstance(certificate["cdf_sha256"],str) or not re.fullmatch(r"[0-9a-f]{64}",certificate["cdf_sha256"]):
            raise ValueError("invalid CDF evidence fingerprint")
        if (certificate["security_claim"]!="none" or certificate["backend_admitted"] is not False
                or type(ideal["conditional_noise_sufficient"]) is not bool):
            raise ValueError("invalid admission or noise-condition metadata")
        ideal_lifetime=ideal["conditional_lifetime_failure_upper"]
        if ideal["conditional_noise_sufficient"]:
            if ideal_lifetime is None:
                raise ValueError("missing ideal noise bound")
            ideal_lifetime=rational(ideal_lifetime,"ideal lifetime")
            if not 0<=ideal_lifetime<=1:
                raise ValueError("invalid ideal lifetime bound")
        elif ideal_lifetime is not None:
            raise ValueError("unsupported bound outside the ideal sufficient condition")
    except (KeyError,TypeError,ValueError) as exc:
        raise InvalidParameterError(str(exc)) from exc
    scalar_calls=calls*(dimension+count)
    coupling=min(Fraction(1),scalar_calls*total)
    return dict(scope="conditional honest encapsulation noise; supplied metadata arithmetic only",
                q=params.q,alpha=str(params.alpha),dimension=dimension,seed_bits=count,
                encapsulations=calls,scalar_noise_draws=scalar_calls,
                random_bytes_upper=scalar_calls*certificate["draw_bytes"],
                scalar_noise_tv_upper=str(total),joint_noise_coupling_upper=str(coupling),
                ideal_lifetime_failure_upper=None if ideal_lifetime is None else str(ideal_lifetime),
                lifetime_noise_upper_if_key_norm_good=None if ideal_lifetime is None else str(min(1,ideal_lifetime+coupling)),
                q_alpha_and_ledger_matched=True,certificate_authenticity_verified=False,
                omitted=["bad key norm", "GPV TV/abort", "basis and resource failures",
                         "LWE estimates and full HIBE implementation"],
                security_claim="none",backend_admitted=False,parameters_are_formal=False)
