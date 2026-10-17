"""Opt-in structured SampleF via a certified matrix square-root series.

For an isotropic public target s I and residual a I-nu T T*, a=s-r^2,
evaluate sqrt(I-H), H=nu T T*/a, without dense coefficient matrices or
floating spectral decomposition. Every H product is exact ring arithmetic;
intermediate vectors are rounded to a fixed dyadic grid with a proved bound.
This samples one joint perturbation Gaussian approximately. It is not the
legacy sequential Schur sampler, a new wire backend, or a security admission.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path
from time import perf_counter

from sage.all import QQ, RealField, RealIntervalField

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.gaussian_reference import SamplingAbort
from .aggregate_budget import AggregateByteSource, MAX_BYTES, batch_certificate
from .convolution_bridge import center_normalizer_certificate
from .psf_bridge import _upper
from .structured_geometry import StructuredGeometry, master_operator
from .wide_scalar import WideScalarGaussian, WideScalarOptions


def _fraction(value):
    if isinstance(value,bool):
        raise ValueError("exact rational required")
    if callable(getattr(value,"numerator",None)):
        return Fraction(int(value.numerator()),int(value.denominator()))
    if not isinstance(value,(int,Fraction)):
        raise ValueError("exact rational required")
    return Fraction(value)


def _bounded(value,name,low,high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


@dataclass(frozen=True)
class SeriesOptions:
    precision_bits: int = 768
    ticket_bits: int = 512
    vector_dyadic_bits: int = 384
    series_error_bits: int = 256
    max_terms: int = 1024
    aggregate_abort_bits: int = 128
    max_dimension: int = 32768
    max_ring_products: int = 200000
    max_entropy_bytes: int = MAX_BYTES
    max_center_bits: int = 1024

    def __post_init__(self):
        for name,low,high in (
            ("precision_bits",128,2048),("ticket_bits",64,1024),
            ("vector_dyadic_bits",64,1024),("series_error_bits",64,512),
            ("max_terms",1,1024),("aggregate_abort_bits",8,512),
            ("max_dimension",2,32768),("max_ring_products",1,1000000),
            ("max_entropy_bytes",1,MAX_BYTES),("max_center_bits",1,1024)):
            _bounded(getattr(self,name),name,low,high)
        if self.precision_bits < self.ticket_bits+32:
            raise ValueError("normal precision must exceed ticket bits by32")


def _ceil_sqrt(value):
    value = _fraction(value)
    whole = -(-value.numerator//value.denominator)
    root = isqrt(whole)
    return root+int(root*root < whole)


def series_certificate(*,dimension,rho,scale_upper,scale_error,options):
    """An exact final-center error bound under the stated MPFR assumptions."""
    d = _bounded(dimension,"coefficient dimension",2,options.max_dimension)
    rho,scale,error = map(_fraction,(rho,scale_upper,scale_error))
    if not 0 < rho < 1 or scale <= 0 or error < 0:
        raise ValueError("strict contraction and valid scale enclosure required")
    # A fixed outward dyadic rho keeps certificates and exponentiation bounded.
    grid = 2**32
    rho = Fraction(-(-(rho*grid).numerator//(rho*grid).denominator),grid)
    if rho >= 1:
        raise ValueError("public contraction is too close to one")
    power = rho
    for terms in range(1,options.max_terms+1):
        power *= rho
        tail = power/(1-rho)
        if tail <= Fraction(1,2**options.series_error_bits):
            break
    else:
        raise ValueError("series truncation exceeds the public term budget")
    b,p = options.ticket_bits,options.precision_bits
    radius,unit = 2*(b+1),Fraction(1,2**(p-2))
    pairs = (d+1)//2
    # q0 is rounded once to the same dyadic grid, so all its denominators
    # have a proved bound independent of the MPFR normal's binary exponent.
    normal_radius = 2*d*radius
    operator_rounding = Fraction(d,2**options.vector_dyadic_bits)/(1-rho)
    selected = None
    for bad_bits in range(1,b+1):
        exponent = (2+bad_bits-b)//2
        grid_error = (Fraction(2**exponent) if exponent >= 0 else Fraction(1,2**-exponent))
        grid_error += Fraction(8*radius,2**(b+1))
        normal_error = d*(grid_error+128*radius*unit+Fraction(1,2**options.vector_dyadic_bits))
        center_error = scale*(normal_error+tail*normal_radius+operator_rounding)
        center_error += error*(normal_radius+operator_rounding)
        bad = Fraction(pairs,2**bad_bits)
        bound = _upper(bad+240*d*center_error)
        if selected is None or bound < selected[0]:
            selected = bound,bad_bits,bad,center_error
    bound,bad_bits,bad,center_error = selected
    return {
        "dimension":d,"rho_upper_exact":str(rho),"terms":terms,
        "sqrt_series_operator_error_upper":str(_upper(tail)),
        "operator_vector_rounding_l2_error_upper":str(operator_rounding),
        "box_muller_bad_event_bits":bad_bits,"box_muller_bad_event_upper":str(_upper(bad)),
        "final_center_coordinate_error_upper":str(Fraction(-(-(center_error*2**256).numerator//
            (center_error*2**256).denominator),2**256)),
        "finite_center_to_ideal_continuous_rounding_tv_upper":str(bound),
        "scale_upper_exact":str(scale),"scale_absolute_error_upper_exact":str(error),
        "normal_input_further_quantized":True,
        "assumptions":["independent uniform bytes",
            "correct round-to-nearest MPFR rational conversion,pi,log,sqrt,sin,cos; no exponent failure",
            "directed interval scale enclosure; exact ring products and exact nearest dyadic rounding",
            "verified 0<=H<=rho I and r>=1; Peikert continuous branch applies"],
    }


class StructuredSampleF:
    """A private prepared joint perturbation sampler; no global private cache."""

    def __init__(self,geometry,*,bound_kind,witness_norm_squared_cap=None,
                 center=None,options=None,scalar_options=None):
        if not isinstance(geometry,StructuredGeometry):
            raise ValueError("validated StructuredGeometry required")
        self.geometry = geometry
        self.options = opt = SeriesOptions() if options is None else options
        if not isinstance(opt,SeriesOptions):
            raise ValueError("explicit SeriesOptions required")
        rows,cols,n = geometry.upper_polynomials,geometry.lower_polynomials,geometry.degree
        self.dimension = d = (rows+cols)*n
        _bounded(d,"coefficient dimension",2,opt.max_dimension)
        widths = geometry.top_squared+(geometry.lower_squared,)
        if len(set(widths)) != 1:
            raise ValueError("this series profile requires an isotropic public target")
        self.width = width = geometry.rounding_squared
        a = geometry.lower_squared-width
        if a <= 0 or width < 1:
            raise ValueError("positive residual scalar and rounding width>=1 required")
        values = tuple(coefficient for row in geometry.witness for poly in row for coefficient in poly.list())
        if any(value.denominator() != 1 or abs(int(value)).bit_length() > 128 for value in values):
            raise ValueError("bounded integer witness coefficients required")
        if bound_kind == "cbd1":
            if witness_norm_squared_cap is not None or any(value not in (-1,0,1) for value in values):
                raise ValueError("CBD1 support without a private norm input required")
            from .spectral_bounds import public_support_class_bound
            spectral = public_support_class_bound(degree=n,rows=rows,columns=cols)
            beta = Fraction(spectral["t_spectral_squared_upper_exact"])
            origin = "entire real CBD1 coefficient support; negacyclic support-function bound"
        elif bound_kind == "public-norm-cap":
            cap = _fraction(witness_norm_squared_cap)
            if cap <= 0 or cap.denominator != 1 or cap.numerator.bit_length() > 256:
                raise ValueError("positive bounded public integer witness norm cap required")
            if sum(value*value for value in values) > QQ(cap.numerator):
                raise ValueError("witness violates the declared public norm cap")
            # Each singular value of a real negacyclic module operator occurs
            # at both conjugate roots. Thus ||M(V)||² <= ||M(V)||F²/2.
            beta = 1+Fraction(n,2)*cap
            origin = "declared public coefficient norm cap; conjugate-pair Frobenius bound"
        else:
            raise ValueError("CBD1 or declared public norm-cap class required")
        self.beta = beta
        rho = _fraction(geometry.noise_squared/a)*beta
        field = RealIntervalField(opt.precision_bits)
        scale_interval = (field(a)/(2*field.pi())).sqrt()
        scale_low,scale_high = (QQ(endpoint) for endpoint in scale_interval.endpoints())
        self.scale = (scale_low+scale_high)/2
        scale_error = (scale_high-scale_low)/2
        self.series = series_certificate(dimension=d,rho=rho,scale_upper=_fraction(scale_high),
            scale_error=_fraction(scale_error),options=opt)
        self.terms = self.series["terms"]
        if self.terms*2*(rows*cols+cols) > opt.max_ring_products:
            raise ValueError("series ring-product work exceeds public budget")
        self.multiplier = geometry.noise_squared/a
        self.scalar = WideScalarGaussian(width,width,options=scalar_options)
        batch = batch_certificate(self.scalar,d,error_bits=opt.aggregate_abort_bits,max_bytes=opt.max_entropy_bytes)
        fixed_bytes = 2*((d+1)//2)*((opt.ticket_bits+7)//8)
        self.byte_cap = batch["selected_cap_bytes"]+fixed_bytes
        if not batch["admitted"] or self.byte_cap > opt.max_entropy_bytes:
            raise ValueError("whole structured sampler entropy cap exceeds public budget")
        if center is None:
            center = (0,)*d
        if not isinstance(center,(tuple,list)) or len(center) != d:
            raise ValueError("exact coefficient center of full dimension required")
        self.center = tuple(QQ(_fraction(x).numerator)/_fraction(x).denominator for x in center)
        if any(max(abs(int(x.numerator())).bit_length(),int(x.denominator()).bit_length()) > opt.max_center_bits for x in self.center):
            raise ValueError("center exceeds the public rational-bit budget")
        self.noise_cap = QQ(scale_high)*(2*d*2*(opt.ticket_bits+1)+QQ(
            self.series["operator_vector_rounding_l2_error_upper"]))
        # q0 and all qj are B-bit dyadic; c_j has denominator dividing
        # 2^(2j). The weighted sum therefore has denominator dividing
        # 2^(B+2J), with exact accumulation. Multiplication by the fixed
        # rational scale and addition of each exact mean give a product
        # denominator bound, and the public magnitude bounds its numerator.
        scale_den_bits = int(self.scale.denominator()).bit_length()
        for x in self.center:
            denominator_bits = int(x.denominator()).bit_length()+scale_den_bits+opt.vector_dyadic_bits+2*self.terms
            magnitude_bits = int((abs(x)+self.noise_cap).ceil()+1).bit_length()
            if denominator_bits+magnitude_bits+2 > self.scalar.options.rational_bits:
                raise ValueError("series centers exceed scalar rational reserve")
            self.scalar.checked_inputs(width,abs(x)+self.noise_cap)
        smooth = center_normalizer_certificate(d,_fraction(width),80)
        eps = smooth["relative_error_upper_exact"]
        peikert = Fraction(1) if eps is None or Fraction(eps) > Fraction(1,2) else min(Fraction(1),8*Fraction(eps))
        numerical = Fraction(self.series["finite_center_to_ideal_continuous_rounding_tv_upper"])
        total = _upper(numerical+Fraction(batch["scalar_kernel_tv_including_aggregate_exact"])+peikert)
        self._certificate = {
            "algorithm":"isotropic joint SampleF; exact ring sqrt series and finite integer rounding",
            "degree":n,"upper_polynomials":rows,"lower_polynomials":cols,"dimension":d,
            "target_squared":str(geometry.lower_squared),"rounding_squared":str(width),
            "noise_squared":str(geometry.noise_squared),"witness_class":origin,
            "verified_witness_spectral_squared_upper":str(beta),
            "series":self.series,"scalar_batch":batch,
            "peikert_ideal_rounding_to_discrete_target_tv_upper":str(peikert),
            "full_target_integer_tv_upper_including_abort":str(total),
            "continuous_fixed_ticket_bytes":fixed_bytes,"whole_entropy_cap_bytes":self.byte_cap,
            "dense_coefficient_matrix_materialized":False,
            "reference":"D_Z^D,Sigma_p,center; Sigma_p=target I-noise T T*",
            "legacy_schur_law_equal":False,"security_claim":"none",
            "backend_admitted":False,"parameters_are_formal":False,
        }

    def __repr__(self):
        return "StructuredSampleF(private_witness_center_and_plans=<redacted>)"

    def public_certificate(self):
        from copy import deepcopy
        return deepcopy(self._certificate)

    def h_apply(self,polynomials):
        g = self.geometry
        return tuple(self.multiplier*x for x in g.factor_apply(g.factor_adjoint_apply(polynomials)))

    def sqrt_series_apply(self,polynomials):
        """Private deterministic path used by sample; all products are exact."""
        g,n = self.geometry,self.geometry.degree
        count = g.upper_polynomials+g.lower_polynomials
        current = g._vector(polynomials,count)
        output = current
        coefficient,scale = QQ(1)/2,2**self.options.vector_dyadic_bits
        for term in range(1,self.terms+1):
            applied = self.h_apply(current)
            current = tuple(g._ring([QQ((value[i]*scale+QQ(1)/2).floor())/scale for i in range(n)])
                            for value in applied)
            output = tuple(x-coefficient*y for x,y in zip(output,current))
            coefficient *= QQ(2*term-1)/(2*(term+1))
        return output

    def sample(self,*,rng=None):
        source = AggregateByteSource(SecureRandom() if rng is None else rng,self.byte_cap)
        field,opt = RealField(self.options.precision_bits),self.options
        size,bits = (opt.ticket_bits+7)//8,opt.ticket_bits
        normal = []
        for _ in range((self.dimension+1)//2):
            tickets = [int.from_bytes(source.read(size),"big") & ((1<<bits)-1) for _ in range(2)]
            u,v = (field(QQ(2*ticket+1)/2**(bits+1)) for ticket in tickets)
            radius,angle = (-2*u.log()).sqrt(),2*field.pi()*v
            normal.extend((radius*angle.cos(),radius*angle.sin()))
        # All midpoint normals are bounded. An arithmetic invariant failure is
        # an explicit abort; never retry/reselect a key or fall back to floats.
        if any(abs(x) > 4*(bits+1) for x in normal):
            raise SamplingAbort("Box-Muller numerical invariant failed")
        n = self.geometry.degree
        grid = 2**opt.vector_dyadic_bits
        polynomials = tuple(self.geometry._ring([QQ((x.exact_rational()*grid+QQ(1)/2).floor())/grid for x in normal[i:i+n]])
                            for i in range(0,self.dimension,n))
        transformed = self.sqrt_series_apply(polynomials)
        centers = tuple(mean+self.scale*poly[i] for poly,means in zip(transformed,
            (self.center[j:j+n] for j in range(0,self.dimension,n))) for i,mean in enumerate(means))
        for original,shifted in zip(self.center,centers):
            if abs(shifted-original) > self.noise_cap:
                raise SamplingAbort("structured all-path output invariant failed")
            self.scalar.checked_inputs(self.width,shifted)
        return tuple(int(self.scalar.sample(self.width,center,rng=source)) for center in centers)


def audit(*,degree=8,rank=1,digits=3,draws=2):
    """Public fixed fixture, not a service root or formal parameter instance."""
    _bounded(draws,"draws",1,8)
    from .formal_candidates import conditional_candidate
    c = conditional_candidate(degree=degree,rank=rank,digits=digits)
    # Explicit public fixture; it is never serialized as a real secret key.
    rng = DeterministicRandom(b"SRGG-public-structured-SampleF-fixture-v1")
    coefficients = [(value&1)-((value>>1)&1) for value in rng.read(2*rank*rank*digits*degree)]
    width = rank*digits*degree
    witness = tuple(tuple(tuple(coefficients[(i*rank*digits+j)*degree:(i*rank*digits+j+1)*degree])
        for j in range(rank*digits)) for i in range(2*rank))
    started = perf_counter()
    geometry = master_operator(degree=degree,rank=rank,digits=digits,base=c.base,witness=witness,
        first_squared=c.master_first_squared,second_squared=c.master_second_squared,r_squared=c.r_squared)
    plan = StructuredSampleF(geometry,bound_kind="cbd1")
    prepared = perf_counter()-started
    rows = []
    for index in range(draws):
        started = perf_counter()
        value = plan.sample(rng=DeterministicRandom(b"SRGG-structured-samplef-draw-v1"+index.to_bytes(2,"big")))
        rows.append({"index":index,"seconds":perf_counter()-started,"coefficients":len(value),
            "output_digest":hashlib.sha256(json.dumps(value).encode()).hexdigest(),
            "squared_norm":str(sum(x*x for x in value))})
    return {"schema":"IBME/SRGG-STRUCTURED-SAMPLEF/1","fixture":"public deterministic CBD1; not a service secret",
        "prepare_seconds":prepared,"certificate":plan.public_certificate(),"draws":rows,
        "production_randomness":False,"full_ibs_executed":False,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--degree",type=int,default=8)
    parser.add_argument("--rank",type=int,default=1)
    parser.add_argument("--digits",type=int,default=3)
    parser.add_argument("--draws",type=int,default=2)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    result = audit(degree=args.degree,rank=args.rank,digits=args.digits,draws=args.draws)
    encoded = json.dumps(result,ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(encoded,encoding="utf-8",newline="\n")
    else:
        print(encoded,end="")


if __name__ == "__main__":
    main()
