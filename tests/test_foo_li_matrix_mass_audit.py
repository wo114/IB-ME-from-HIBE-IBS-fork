"""Sage-only independent checks of draft arithmetic, not an IBS security test."""

from itertools import product

import pytest

pytest.importorskip("sage.all",reason="Use the prescribed WSL Sage environment")
from sage.all import GF, QQ, RealField, matrix

from experiments.research.foo_li_matrix_mass_audit import audit_report, good_matrix_bound


def test_outward_theta_budget_dominates_independent_high_precision_formula():
    c = good_matrix_bound(q=17,n=1,m=32,s=6,epsilon="1/1099511627776")
    f = RealField(320)
    # A larger explicit dual series is computed independently of the geometric
    # bound. Missing scalar tails here are far smaller than interval precision.
    scalar = sum((-f.pi()*36*j*j).exp() for j in range(-30,31))
    explicit_ambient = scalar**32-1
    ambient_upper = f(QQ(c["ambient_dual_theta_upper"]))
    assert 0 < explicit_ambient < ambient_upper
    expectation = explicit_ambient+(f(17)-1)*(f(1)/17+f(1)/6)**32
    rank = f(17)**-32
    assert rank+expectation*2**40 <= f(QQ(c["bad_matrix_upper_unclamped"]))
    assert 0 < QQ(c["bad_matrix_upper"]) < QQ(1)/10**6
    assert QQ(c["pointwise_relative_image_error"]) == QQ(2)/(2**40+1)


def test_poisson_conditional_atom_inequality_on_all_small_syndromes():
    f = RealField(192)
    s,q,m = f(3),3,2
    weights = {v:(-f.pi()*sum(x*x for x in v)/s**2).exp()
               for v in product(range(-15,16),repeat=m)}
    total = sum(weights.values())
    masses = [sum(w for v,w in weights.items() if sum(v)%q==u) for u in range(q)]
    eta = f("0.01")
    assert all((1-eta)/q < mass/total < (1+eta)/q for mass in masses)
    for u,mass in enumerate(masses):
        actual_atom = max(w/mass for v,w in weights.items() if sum(v)%q==u)
        assert actual_atom < q/((1-eta)*s**m)
    # This is a finite-box numerical cross-check only, not the uniform random-A proof.


def test_rank_failure_bound_dominates_exact_small_matrix_enumeration():
    q,n,m = 2,2,3
    count = sum(matrix(GF(q),n,m,v).rank()<n
                for v in product(range(q),repeat=n*m))
    observed = QQ(count)/q**(n*m)
    bound = sum(QQ(q)**(i-m) for i in range(n))
    assert observed == QQ(11)/32 and observed <= bound
    certificate = good_matrix_bound(q=q,n=n,m=m,s=3,epsilon="1/4")
    assert QQ(certificate["uniform_A_rank_failure_upper"]) >= bound


def test_weak_width_yields_vacuous_certificate_without_security_claim():
    c = good_matrix_bound(q=7,n=1,m=2,s=1,epsilon="1/16")
    assert QQ(c["bad_matrix_upper_unclamped"]) > 1 and c["bad_matrix_upper"] == "1"
    assert c["security_claim"] == "none" and c["gaussian_samples"] == 0


def test_larger_arithmetic_case_is_not_a_complete_lattice_parameter_set():
    report = audit_report()
    c = report["cases"][1]
    assert QQ(c["bad_matrix_upper"]) < QQ(1)/2**200
    assert QQ(c["conditional_column_max_atom_upper"]) < QQ(1)/2**360
    assert c["parameter_source"].startswith("hand-selected")
    assert report["matrices_generated"] == report["gaussian_samples"] == 0


def test_wide_boundary_remains_serializable_with_conservative_positive_floor():
    import json
    c = good_matrix_bound(q=257,n=2,m=256,s=64,epsilon="1/18446744073709551616")
    assert QQ(c["ambient_dual_theta_upper"]) > 0
    assert QQ(c["conditional_column_max_atom_upper"]) >= QQ(1)/2**512
    assert json.loads(json.dumps(c))["security_claim"] == "none"


@pytest.mark.parametrize("kwargs",[dict(q=4),dict(q=True),dict(n=3,m=2),dict(m=257),
    dict(s=0),dict(s=0.5),dict(s=65),dict(epsilon=0),dict(epsilon=1),
    dict(epsilon=0.1),dict(precision_bits=64)])
def test_unadmitted_inputs_do_not_receive_partial_certificates(kwargs):
    parameters = dict(q=7,n=1,m=2,s=3,epsilon="1/16")
    parameters.update(kwargs)
    with pytest.raises(ValueError):
        good_matrix_bound(**parameters)
