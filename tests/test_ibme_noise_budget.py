"""Portable configuration, truthful error ledger and shared-preamble counts."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from fractions import Fraction

import pytest

from ibme.core.errors import InvalidParameterError
from experiments.research.ibme_joint_parameters import plan_numeric_candidate,evaluate_noise
from experiments.research.ibme_noise_budget import RoundedNoiseParams,SCHEMA,attach_finite_noise_budget


def diagnostic_certificate(params):
    # Explicit simulated metadata for portable arithmetic tests; no claim that
    # these fields authenticate an actual Sage CDF table.
    units=2*params.radius
    tail=Fraction(1,2**params.tail_bits)
    quant=Fraction(units,2**params.mass_bits)
    return dict(schema=SCHEMA,config=params.to_record(),support=[-params.radius,params.radius],
                draw_bytes=(params.mass_bits+7)//8,cdf_interval_error_units=units,
                tail_tv_upper=str(tail),cdf_quantization_and_interval_tv_upper=str(quant),
                random_rejection_abort_upper="0",tv_upper_including_abort=str(min(1,tail+quant)),
                cdf_sha256="0"*64,security_claim="none",backend_admitted=False)


def test_exact_profile_radius_and_fixed_format_are_immutable():
    p=RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33))
    assert p.radius==288 and 2*p.radius+1==577
    assert p.scaled_width==Fraction(274877844481,2**33)
    assert p.to_record()["alpha"]=="1/8589934592"
    assert p.security_claim=="none" and not p.backend_admitted
    with pytest.raises(FrozenInstanceError):
        p.q=2


@pytest.mark.parametrize("field,value", [
    ("q",True),("q",17.0),("q",1),("q",2**61),
    ("alpha",0),("alpha",1),("alpha",0.1),("alpha","1e10000000"),("alpha","1/0"),
    ("alpha",Fraction(1,2**30)),("alpha","1/"+"9"*2401),
    ("tail_bits",7),("tail_bits",True),("mass_bits",7),("mass_bits",513),
    ("precision_bits",127),("precision_bits",1025),("precision_bits",150),
    ("max_radius",0),("max_radius",16385),("max_radius",1),
])
def test_invalid_profile_has_no_fallback(field,value):
    values=dict(q=257,alpha=Fraction(1,64),mass_bits=128)
    values[field]=value
    with pytest.raises(InvalidParameterError):
        RoundedNoiseParams(**values)


def test_shared_prefix_draws_are_D_plus_L_and_include_every_encapsulation():
    p=RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33))
    ideal=plan_numeric_candidate(n=1,q=p.q)["conditional_noise"]
    certificate=diagnostic_certificate(p)
    r=attach_finite_noise_budget(ideal,certificate)
    assert r["scalar_noise_draws"]==2**20*(1335+256)==1668284416
    assert r["random_bytes_upper"]==16*r["scalar_noise_draws"]
    delta=Fraction(certificate["tv_upper_including_abort"])
    assert Fraction(r["joint_noise_coupling_upper"])==r["scalar_noise_draws"]*delta
    assert Fraction(r["lifetime_noise_upper_if_key_norm_good"])==Fraction(1,2**36)+r["scalar_noise_draws"]*delta
    assert not r["certificate_authenticity_verified"] and not r["backend_admitted"]


def test_insufficient_ideal_margin_does_not_gain_a_correctness_bound():
    p=RoundedNoiseParams(q=257,alpha=Fraction(1,64))
    ideal=evaluate_noise(q=p.q,dimension=30,width_squared=15952640,alpha=p.alpha)
    r=attach_finite_noise_budget(ideal,diagnostic_certificate(p))
    assert r["lifetime_noise_upper_if_key_norm_good"] is None
    assert r["joint_noise_coupling_upper"] is not None


@pytest.mark.parametrize("field,value", [
    ("schema","wrong"),("tail_tv_upper","0"),("cdf_quantization_and_interval_tv_upper","0"),
    ("random_rejection_abort_upper","1/2"),("tv_upper_including_abort","0"),
    ("cdf_interval_error_units",0),("cdf_interval_error_units",True),
    ("cdf_sha256","broken"),("draw_bytes",17),("draw_bytes",True),
    ("support",[-1,1]),("security_claim","128-bit"),("backend_admitted",True),
])
def test_modified_certificate_fields_are_rejected(field,value):
    p=RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33))
    certificate=diagnostic_certificate(p)
    certificate[field]=value
    with pytest.raises(InvalidParameterError):
        attach_finite_noise_budget(plan_numeric_candidate(n=1,q=p.q)["conditional_noise"],certificate)


@pytest.mark.parametrize("field", ["tail_tv_upper","cdf_interval_error_units","config","draw_bytes"])
def test_missing_obligations_do_not_default_to_zero(field):
    p=RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33))
    certificate=diagnostic_certificate(p)
    del certificate[field]
    with pytest.raises(InvalidParameterError):
        attach_finite_noise_budget(plan_numeric_candidate(n=1,q=p.q)["conditional_noise"],certificate)


@pytest.mark.parametrize("change", ["alpha","q","noncanonical","unknown"])
def test_certificate_config_is_bound_to_exact_q_and_alpha(change):
    p=RoundedNoiseParams(q=274877844481,alpha=Fraction(1,2**33))
    certificate=diagnostic_certificate(p)
    if change=="alpha":
        certificate["config"]["alpha"]="1/17179869184"
    elif change=="q":
        certificate["config"]["q"]-=1
    elif change=="noncanonical":
        certificate["config"]["alpha"]="2/17179869184"
    else:
        certificate["config"]["extra"]=1
    with pytest.raises(InvalidParameterError):
        attach_finite_noise_budget(plan_numeric_candidate(n=1,q=p.q)["conditional_noise"],certificate)


@pytest.mark.parametrize("field,value", [("conditional_lifetime_failure_upper","0"),
                                        ("conditional_noise_sufficient",True),("integer_phase_radius",0)])
def test_ideal_budget_is_recomputed_before_attaching_sampler(field,value):
    p=RoundedNoiseParams(q=257,alpha=Fraction(1,64))
    ideal=evaluate_noise(q=p.q,dimension=30,width_squared=15952640,alpha=p.alpha)
    ideal[field]=value
    with pytest.raises(InvalidParameterError):
        attach_finite_noise_budget(ideal,diagnostic_certificate(p))
