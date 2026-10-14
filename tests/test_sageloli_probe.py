"""Math-probe evidence only; this is not a complete IBS backend contract."""
import importlib

import pytest

pytest.importorskip("sage.all")
from sage.all import ZZ, matrix, vector

from ibme.core.randomness import DeterministicRandom
from ibme.ibs.luo_module_math import negacyclic_schoolbook


def probe():
    return importlib.import_module("experiments.research.candidates.sageloli.probe")


def test_digit_major_ternary_gadget():
    assert probe().gadget(2, 3) == matrix(ZZ, [[1, 0, 3, 0, 9, 0],
                                             [0, 1, 0, 3, 0, 9]])


def test_coset_gaussians_cover_every_syndrome_and_retain_randomness():
    p = probe()
    rng = DeterministicRandom(b"sageloli-carry-test")
    g = p.gadget(2, 4)
    samples = set()
    for target in range(81):
        u = (target, 80-target)
        x = p.ternary_preimage(u, 4, rng)
        assert tuple(int(z) % 81 for z in g*x) == u
        samples.add(tuple(int(z) for z in x))
    repeated = {tuple(p.ternary_preimage((5, 7), 4, rng)) for _ in range(16)}
    assert len(samples) == 81 and len(repeated) > 1


def test_ring_expansion_is_column_action_and_negacyclic():
    p = probe()
    polys = (((2, -1, 4, 3), (0, 1, 0, 0)),)
    inputs = ((1, 3, -2, 4), (-2, 1, 0, 5))
    expected = tuple(a+b for a, b in zip(*(negacyclic_schoolbook(a, b)
                         for a, b in zip(polys[0], inputs))))
    flat = vector(ZZ, [x for poly in inputs for x in poly])
    assert tuple(p.expand_polynomials(polys)*flat) == expected
    x = p.expand_polynomials((((0, 1, 0, 0),),))
    assert tuple(x*vector(ZZ, (0, 0, 0, 1))) == (-1, 0, 0, 0)


def test_prepare_rejects_wrong_relation_and_insufficient_width():
    p = probe()
    a = matrix(ZZ, [[0, 1, 3]])
    t = matrix(ZZ, [[0, 0]])
    with pytest.raises(ValueError):
        p.prepare_sampler(a, t, 2, 1, mode="global", block_size=1)
    with pytest.raises(ValueError):
        p.prepare_sampler(matrix(ZZ, [[0, 2, 3]]), t, 2, 2**20,
                          mode="global", block_size=1)


@pytest.mark.parametrize("kind,dimension,columns,mode", [
    ("matrix", 24, 8, "global"), ("ring", 124, 9, "block-schur")])
def test_real_delegation_and_signature_math(kind, dimension, columns, mode):
    result = probe().run_probe(kind)
    assert result["coefficient_dimension"] == dimension
    assert result["delegation_sample_calls"] == columns
    assert result["perturbation_mode"] == mode
    for name in ("root_relation", "delegated_relation", "sign_equation",
                 "raw_split_norm_passed", "centered_split_norm_passed",
                 "profile_norm_check_is_vacuous"):
        assert result[name] is True
    assert result["continuous_tv_certified"] is False
    assert result["security_claim"] == "none"
    assert result["backend_admitted"] is False
    assert result["complete_ibs_backend"] is False
    assert not {"trapdoor", "seed", "shape", "private_key"} & set(result)


def test_table_width_checks_use_conservative_constant():
    width = importlib.import_module("experiments.research.candidates.sageloli.width_check")
    results = width.check_widths()
    assert {r["kind"] for r in results} == {"matrix", "ring"}
    for result in results:
        assert result["C_upper"] == 38 and result["epsilon_bits"] == 64
        assert result["table_width_inequalities_pass"] is True
        assert result["security_claim"] == "none"


@pytest.mark.parametrize("kind", ["", "RSIS", None])
def test_probe_has_no_silent_profile_fallback(kind):
    with pytest.raises(ValueError):
        probe().run_probe(kind)
