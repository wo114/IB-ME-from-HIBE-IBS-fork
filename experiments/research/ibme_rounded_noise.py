"""Finite dyadic CDF for CHKP's rounded CONTINUOUS Gaussian; Sage only.

Target is round(Y), Y having density exp(-pi*y^2/w^2)/w, w=q*alpha.
The tails are moved to the two finite endpoints, not conditioned away.
Interior CDFs are erf balls; floors of lower endpoints are made monotone.
Every sample consumes one fixed-size uniform word. No rejection, silent
resampling or integer-discrete-Gaussian substitution. Research/variable time.
"""

from bisect import bisect_right
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
import json

from sage.all import QQ,RealBallField

from ibme.core.errors import InvalidParameterError,RandomnessError
from ibme.core.randomness import SecureRandom
from .ibme_noise_budget import RoundedNoiseParams,SCHEMA


def cdf_integer_interval(field,scaled_width,half_numerator,total):
    """Enclose total*F(half_numerator/2), with outward endpoint rounding."""
    argument=field(QQ(half_numerator)/2)*field.pi().sqrt()/field(scaled_width)
    ball=total*(1+argument.erf())/2
    lower=max(0,min(total,int(ball.lower().floor())))
    upper=max(0,min(total,int(ball.upper().ceil())))
    if upper<lower:
        raise InvalidParameterError("invalid CDF interval")
    return lower,upper


@dataclass(frozen=True)
class RoundedNoiseTable:
    params: RoundedNoiseParams
    thresholds: tuple
    interval_error_units: int

    def __post_init__(self):
        if not isinstance(self.params,RoundedNoiseParams):
            raise InvalidParameterError("noise table needs a validated profile")
        if not isinstance(self.thresholds,tuple) or len(self.thresholds)!=2*self.radius+1:
            raise InvalidParameterError("wrong bounded noise CDF shape")
        if (any(type(v) is not int or not 0<=v<=self.total for v in self.thresholds) or
                self.thresholds[-1]!=self.total or
                any(a>b for a,b in zip(self.thresholds,self.thresholds[1:]))):
            raise InvalidParameterError("noise CDF must be canonical and monotone")
        if (type(self.interval_error_units) is not int or
                not 2*self.radius<=self.interval_error_units<=8*self.radius):
            raise InvalidParameterError("invalid noise CDF interval budget")

    @property
    def draw_bytes(self):
        return (self.params.mass_bits+7)//8

    @property
    def total(self):
        return 1<<self.params.mass_bits

    @property
    def radius(self):
        return self.params.radius

    @property
    def masses(self):
        previous=0
        values=[]
        for cutoff in self.thresholds:
            values.append(cutoff-previous)
            previous=cutoff
        return tuple(values)

    def map_word(self,word):
        if type(word) is not int or not 0<=word<self.total:
            raise RandomnessError("CDF word must be an exact integer in its bit range")
        return -self.radius+bisect_right(self.thresholds,word)

    def sample_signed(self,*,rng=None):
        source=SecureRandom() if rng is None else rng
        if not callable(getattr(source,"read",None)):
            raise RandomnessError("noise source must implement read(n)->bytes")
        raw=source.read(self.draw_bytes)
        if not isinstance(raw,bytes) or len(raw)!=self.draw_bytes:
            raise RandomnessError("noise source returned wrong byte type or count")
        return self.map_word(int.from_bytes(raw,"big")&(self.total-1))

    def sample_mod_q(self,*,rng=None):
        return self.sample_signed(rng=rng)%self.params.q

    def sample_vector(self,count,*,rng=None,mod_q=False):
        if type(count) is not int or not 0<=count<=65536 or type(mod_q) is not bool:
            raise InvalidParameterError("bounded integer noise count and boolean mod_q required")
        source=SecureRandom() if rng is None else rng
        draw=self.sample_mod_q if mod_q else self.sample_signed
        return tuple(draw(rng=source) for _ in range(count))

    def certificate(self):
        tail=Fraction(1,2**self.params.tail_bits)
        quant=Fraction(self.interval_error_units,self.total)
        body=dict(config=self.params.to_record(),thresholds=self.thresholds)
        return dict(schema=SCHEMA,config=self.params.to_record(),
                    support=[-self.radius,self.radius],support_count=len(self.thresholds),
                    draw_bytes=self.draw_bytes,cdf_interval_error_units=self.interval_error_units,
                    tail_tv_upper=str(tail),cdf_quantization_and_interval_tv_upper=str(quant),
                    random_rejection_abort_upper="0",tv_upper_including_abort=str(min(1,tail+quant)),
                    scaled_width=str(self.params.scaled_width),
                    target="round(continuous Gaussian of width q*alpha), then modulo q if requested",
                    finite_tail_policy="clamp to endpoints, no conditioning",
                    randomness_assumption="independent uniform bytes; errors of faulty sources propagate",
                    cdf_sha256=sha256(json.dumps(body,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                    constant_time=False,security_claim="none",backend_admitted=False)


def build_rounded_noise(params):
    if not isinstance(params,RoundedNoiseParams):
        raise InvalidParameterError("need RoundedNoiseParams")
    field=RealBallField(params.precision_bits)
    total=1<<params.mass_bits
    radius=params.radius
    cuts,previous,error_units=[],0,0
    for value in range(-radius,radius):
        lower,upper=cdf_integer_interval(field,QQ(params.scaled_width),2*value+1,total)
        # A monotone prefix maximum remains below the true monotone CDF.
        cutoff=max(previous,lower)
        if cutoff>upper or upper-lower>4:
            raise InvalidParameterError("CDF precision did not meet public error-unit budget")
        cuts.append(cutoff)
        error_units+=upper-cutoff
        previous=cutoff
    cuts.append(total)
    return RoundedNoiseTable(params,tuple(cuts),error_units)
