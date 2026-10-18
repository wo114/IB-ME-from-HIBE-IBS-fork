"""Exact finite model of SRGG's global mixed-domain PSF reference.

Sample U from a target-independent domain law and E uniformly in [0,p)^H,
then Y=canonical_head(U+J E). With A=[I,A_tail], f_A(Y)=AY mod Q.
Conditioning on f_A(Y)=h is exactly the repair of U conditioned on the
approximate-fiber union. No zero-center Gaussian approximation is used.

The finite examples are public synthetic laws, not SRGG sampler transcripts.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
from itertools import product
import json
from pathlib import Path


MAX_STATES = 4096
MAX_DIMENSION = 64


def _int(value, name, low=1, high=2**20):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def _prob(value, name):
    if type(value) not in (int, Fraction):
        raise ValueError("exact rational probability required: "+name)
    result = Fraction(value)
    if not 0 <= result <= 1 or max(result.numerator.bit_length(), result.denominator.bit_length()) > 16384:
        raise ValueError("probability range or bit budget exceeded: "+name)
    return result


def _law(law):
    if not isinstance(law, dict) or not 1 <= len(law) <= MAX_STATES:
        raise ValueError("bounded finite law required")
    result, dimension = {}, None
    for point, mass in law.items():
        if not isinstance(point, tuple) or not 1 <= len(point) <= MAX_DIMENSION:
            raise ValueError("finite law must have integer-vector atoms without abort")
        if any(type(x) is not int or abs(x).bit_length() > 128 for x in point):
            raise ValueError("bounded exact integer coordinates required")
        if dimension is None:
            dimension = len(point)
        if len(point) != dimension:
            raise ValueError("constant vector dimension required")
        value = _prob(mass, "atom mass")
        if value:
            result[point] = value
    if sum(result.values(), Fraction(0)) != 1:
        raise ValueError("law must be normalized exactly")
    return result, dimension


def _layout(a, dimension, modulus):
    q = _int(modulus, "modulus", 2)
    if not isinstance(a, (tuple, list)) or not 1 <= len(a) <= dimension:
        raise ValueError("matrix A with identity first head block required")
    head = len(a)
    for i, row in enumerate(a):
        if not isinstance(row, (tuple, list)) or len(row) != dimension:
            raise ValueError("rectangular public matrix required")
        if any(type(x) is not int or abs(x).bit_length() > 128 for x in row):
            raise ValueError("bounded exact public coefficients required")
        if any(row[j] % q != int(i == j) for j in range(head)):
            raise ValueError("first head block of A must equal I modulo Q")
    return head, q


def _target(target, head, q):
    if not isinstance(target, tuple) or len(target) != head or any(
            type(x) is not int or not 0 <= x < q for x in target):
        raise ValueError("canonical public target required")
    return target


def _forward(a, point, q):
    return tuple(sum(x*y for x, y in zip(row, point)) % q for row in a)


def _center(value, q):
    return (value+q//2) % q-q//2


def _repair(point, error, q):
    head = len(error)
    return tuple(_center(point[i]+error[i], q) for i in range(head))+point[head:]


def mixed_domain_law(raw_domain, *, head, p, modulus):
    """Global SampleDom law, independent of A and target, canonical head only."""
    raw, dimension = _law(raw_domain)
    _int(head, "head dimension", 1, dimension)
    q = _int(modulus, "modulus", 2)
    _int(p, "p", 1, q)
    if len(raw)*p**head > MAX_STATES:
        raise ValueError("finite mixed-domain enumeration budget exceeded")
    answer = {}
    weight = Fraction(1, p**head)
    for point, mass in raw.items():
        for error in product(range(p), repeat=head):
            repaired = _repair(point, error, q)
            answer[repaired] = answer.get(repaired, Fraction(0))+mass*weight
    return answer


def image_law(domain, a, *, modulus):
    law, dimension = _law(domain)
    _, q = _layout(a, dimension, modulus)
    result = {}
    for point, mass in law.items():
        image = _forward(a, point, q)
        result[image] = result.get(image, Fraction(0))+mass
    return result


def conditional_preimage_law(domain, a, target, *, modulus):
    law, dimension = _law(domain)
    head, q = _layout(a, dimension, modulus)
    h = _target(target, head, q)
    kept = {point:mass for point,mass in law.items() if _forward(a,point,q) == h}
    total = sum(kept.values(), Fraction(0))
    if not total:
        raise ValueError("target has zero probability in this finite reference")
    return {point:mass/total for point,mass in kept.items()}, total


def repaired_union_law(raw_domain, a, target, *, p, modulus):
    """Condition U on its union; unique e(h,U) is repaired, never redrawn."""
    raw, dimension = _law(raw_domain)
    head, q = _layout(a, dimension, modulus)
    _int(p, "p", 1, q)
    h = _target(target, head, q)
    kept, total = {}, Fraction(0)
    for point, mass in raw.items():
        image = _forward(a, point, q)
        error = tuple((x-y) % q for x,y in zip(h,image))
        if any(value >= p for value in error):
            continue
        repaired = _repair(point,error,q)
        if _forward(a,repaired,q) != h:
            raise ArithmeticError("repair relation invariant failed")
        kept[repaired] = kept.get(repaired,Fraction(0))+mass
        total += mass
    if not total:
        raise ValueError("approximate union has zero probability in finite reference")
    return {point:mass/total for point,mass in kept.items()}, total


def filter_with_abort(law, predicate):
    """Apply the same norm predicate to an already defined ideal output law."""
    source, _ = _law(law)
    result = {}
    for point, mass in source.items():
        accepted = predicate(point)
        if type(accepted) is not bool:
            raise ValueError("explicit Boolean acceptance predicate required")
        atom = point if accepted else None
        result[atom] = result.get(atom,Fraction(0))+mass
    return result


def image_uniformity_bound(kernel_coset_relative_error, *, unconditional_norm_reject=0):
    """Inherited image TV, then optional global domain-success conditioning.

    If each coset mass is within 1+-eps of the same constant, image TV is at
    most eps/(1-eps). Adding independent uniform E contracts image TV. Head
    canonicalization preserves the image. Conditioning the GLOBAL domain on
    norm success costs at most its unconditional rejection probability.
    This is not a per-identity norm-success bound.
    """
    eps = _prob(kernel_coset_relative_error, "kernel relative error")
    reject = _prob(unconditional_norm_reject, "global norm rejection")
    if eps == 1:
        raise ValueError("strictly subunit kernel error required")
    original = min(Fraction(1), eps/(1-eps))
    return {
        "unfiltered_image_to_uniform_tv_upper_exact": str(original),
        "unfiltered_point_probability_lower_multiplier_of_uniform_exact": str((1-eps)/(1+eps)),
        "unfiltered_point_probability_upper_multiplier_of_uniform_exact": str((1+eps)/(1-eps)),
        "globally_success_conditioned_image_to_uniform_tv_upper_exact": str(min(Fraction(1),original+reject)),
        "per_target_norm_reject_certified": False,
        "hash_may_be_treated_as_exactly_uniform_image": False,
    }


def conditional_atom_upper(*, unwrapped_domain_atom_upper, canonical_head_wrap_upper,
                           target_image_probability_lower):
    """Generic sufficient atom/min-entropy bound, all assumptions supplied.

    Mixing by translations cannot raise max atom before canonicalization.
    Canonicalization adds at most its coupling-failure probability. Divide
    by an explicit image-probability lower bound to condition on the target.
    """
    mass = _prob(unwrapped_domain_atom_upper, "unwrapped max atom")
    wrap = _prob(canonical_head_wrap_upper, "canonical head wrap")
    image = _prob(target_image_probability_lower, "image probability lower")
    if not mass:
        raise ValueError("positive max atom bound required for a normalized discrete law")
    if not image:
        raise ValueError("positive target image probability lower bound required")
    atom = min(Fraction(1), (mass+wrap)/image)
    bits = 0
    while atom <= Fraction(1,2**(bits+1)) and bits < 16384:
        bits += 1
    return {"conditional_max_atom_upper_exact": str(atom),
            "conditional_min_entropy_bits_lower": bits,
            "supplied_assumptions_verified_here": False,
            "oneway_or_signature_security_certified": False}


def build_report():
    raw = {(-1,0):Fraction(1,15), (0,0):Fraction(2,15), (1,0):Fraction(3,15),
           (0,1):Fraction(4,15), (1,1):Fraction(5,15)}
    a, q, p = ((1,2),), 15, 3
    domain = mixed_domain_law(raw,head=1,p=p,modulus=q)
    image = image_law(domain,a,modulus=q)
    rows = []
    for target, probability in sorted(image.items()):
        conditional, probability = conditional_preimage_law(domain,a,target,modulus=q)
        repaired, union_probability = repaired_union_law(raw,a,target,p=p,modulus=q)
        assert conditional == repaired and union_probability == p*probability
        gate = lambda point: sum(x*x for x in point) <= 1
        assert filter_with_abort(conditional,gate) == filter_with_abort(repaired,gate)
        rows.append({"target":list(target), "image_probability_exact":str(probability),
            "union_probability_exact":str(union_probability),
            "conditional_laws_identical":True,"identical_after_common_norm_gate_including_abort":True})
    return {"schema":"IBME/SRGG-MIXED-DOMAIN/1", "finite_public_example":rows,
        "unfiltered_image_bound_example":image_uniformity_bound(Fraction(1,2**128)),
        "conditional_entropy_supplied_assumptions_example":conditional_atom_upper(
            unwrapped_domain_atom_upper=Fraction(1,2**256),
            canonical_head_wrap_upper=Fraction(1,2**256),
            target_image_probability_lower=Fraction(1,2**32)),
        "global_domain_depends_on_target_or_trapdoor":False,
        "finite_example_is_actual_srgg_sampler_law":False,
        "gaussian_secret_SIG_or_oneway_correspondence_established":False,
        "security_claim":"none","backend_admitted":False,"parameters_are_formal":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args = parser.parse_args()
    encoded = json.dumps(build_report(),ensure_ascii=False,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(encoded,encoding="utf-8")
    else:
        print(encoded,end="")


if __name__ == "__main__":
    main()
