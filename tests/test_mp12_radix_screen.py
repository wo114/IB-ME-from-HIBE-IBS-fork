"""Public full-3m radix geometry, coupled q and fail-closed feasibility gates."""

from fractions import Fraction
import pytest

pytest.importorskip("sage.all", reason="use prescribed WSL ~/miniconda3/envs/sage")
from sage.all import ZZ, matrix, previous_prime

from experiments.research import structured_target_screen as binary
from experiments.research import structured_radix_screen as radix
from experiments.research.blocked_3m_projection import project as binary_bytes
from ibme.core.randomness import SecureRandom
from ibme.lattice.chkp.basis import gram_schmidt_squared_lengths
from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV
from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian


@pytest.mark.parametrize("n", (128, 4096))
def test_binary_limit_reproduces_the_prior_complete_group_and_byte_rule(n):
    old, new = binary.select_group(n), radix.select_group(n, 1)
    for key, value in old.items():
        assert new[key] == value, key
    before, after = binary_bytes(old), radix.resource_projection(new)
    assert after["matrix_component_bytes"]["parent_R"] == before["parent_R_packed_bytes"]
    assert after["matrix_component_bytes"]["public_parent"] == before["parent_public_packed_bytes"]
    assert after["matrix_component_bytes"]["fixed_leaf"] == before["one_fixed_leaf_256_packed_bytes"]


@pytest.mark.parametrize("q,bits", ((3, 1), (257, 1), (257, 4), (65537, 8),
                                  (604462909807314587353111, 16),
                                  (604462909807314587353111, 32)))
def test_general_primitive_basis_is_complete_and_obeys_paper_GS_bound(q, bits):
    block = radix.public_gadget(q, bits)
    b = matrix(ZZ, block.basis_rows)
    a = matrix(ZZ, block.public.rows)
    assert abs(b.det()) == q and all(x % q == 0 for x in (a*b).list())
    assert b.nrows() == b.ncols() == ((q-1).bit_length()+bits-1)//bits
    assert max(gram_schmidt_squared_lengths(block.basis_rows)) <= (1 << (2*bits))+1


@pytest.mark.parametrize("bits", (2, 8, 16))
def test_selected_radix_prime_is_self_consistent_and_previous_prime_fails(bits):
    g = radix.select_group(128, bits)
    assert ZZ(g["q"]).is_prime(proof=True) and g["noise"]["conditional_noise_sufficient"]
    previous = int(previous_prime(g["q"]))
    p = radix.width_group(128, previous.bit_length(), bits)
    assert not binary.noise_condition(previous, p["leaf_dimension"], p["leaf_width_squared"], p["q_alpha"])["conditional_noise_sufficient"]
    assert g["leaf_dimension"] == 3*g["m"] and g["parent_sample_dimension"] == 2*g["m"]-g["w"]


def test_greater_radix_does_not_silently_keep_binary_noise_or_q():
    old = radix.select_group(4096, 1)
    changed = radix.width_group(4096, old["q_bits"], 8)
    assert changed["w"] < old["w"] and changed["gadget_width_squared"] > old["gadget_width_squared"]
    assert not binary.noise_condition(old["q"], changed["leaf_dimension"], changed["leaf_width_squared"], changed["q_alpha"])["conditional_noise_sufficient"]
    assert radix.select_group(4096, 8)["q"] > old["q"]


def test_binary_finite_ledger_matches_the_existing_probability_projection():
    old = binary.target_row(128)
    new = radix.target_row(128, 1)
    assert Fraction(new["finite_projection"]["modeled_lifetime_upper"]) == Fraction(old["finite_projection"]["modeled_lifetime_upper"])
    assert new["finite_projection"]["target_lifetime_met"]


def test_higher_radix_screen_reads_no_entropy_and_never_samples_or_builds_keys(monkeypatch):
    from ibme.lattice.matrix_sampling.mp12_blocked import PackedTrapdoor, BlockedPreimageSampler
    def forbidden(*args, **kwargs): pytest.fail("public radix screen attempted private work")
    monkeypatch.setattr(SecureRandom, "read", forbidden)
    monkeypatch.setattr(MatrixFiniteGaussian, "sample", forbidden)
    monkeypatch.setattr(MatrixFiniteGPV, "sample", forbidden)
    monkeypatch.setattr(PackedTrapdoor, "__init__", forbidden)
    monkeypatch.setattr(BlockedPreimageSampler, "__init__", forbidden)
    r = radix.target_row(128, 8)
    assert r["finite_projection"]["gadget"]["complete_kernel_verified"]
    assert r["finite_projection"]["target_lifetime_met"]
    assert (r["root_or_key_generations"], r["entropy_reads"], r["sampler_calls"]) == (0, 0, 0)
    assert (r["security_claim"], r["backend_admitted"], r["parameters_are_formal"]) == ("none", False, False)


def decision_fixture():
    return dict(estimator_results={role:{a+"-"+m:dict(status="finite_estimate", rop_log2=150.0)
        for a in ("primal_usvp", "dual") for m in ("classical", "quantum")}
        for role in ("root_lwe", "ciphertext_lwe")},
        resources=dict(necessary_payload_fits_research_budget=True, current_scalar_width_domain=True),
        finite_projection=dict(status="computed_resource_conditional", target_lifetime_met=True))


@pytest.mark.parametrize("failure", ("root-low", "ciphertext-low", "error", "missing", "nan", "infinity", "payload", "scalar", "probability"))
def test_one_failing_or_unknown_gate_cannot_select_an_implementation_candidate(failure):
    r = decision_fixture()
    estimate = r["estimator_results"]["root_lwe"]["dual-quantum"]
    if failure == "root-low": estimate["rop_log2"] = 127.0
    if failure == "ciphertext-low": r["estimator_results"]["ciphertext_lwe"]["dual-quantum"]["rop_log2"] = 127.0
    if failure == "error": estimate.update(status="error", rop_log2=None)
    if failure == "missing": del r["estimator_results"]["ciphertext_lwe"]
    if failure == "nan": estimate["rop_log2"] = float("nan")
    if failure == "infinity": estimate["rop_log2"] = float("inf")
    if failure == "payload": r["resources"]["necessary_payload_fits_research_budget"] = False
    if failure == "scalar": r["resources"]["current_scalar_width_domain"] = False
    if failure == "probability": r["finite_projection"]["target_lifetime_met"] = False
    assert radix.decision(r)["implementation_candidate"] is False
    if failure in ("error", "missing", "nan", "infinity"):
        assert radix.decision(r)["status"] == "unresolved_missing_or_failed_model"
    assert radix.decision(decision_fixture())["implementation_candidate"] is True
    assert radix.decision(decision_fixture())["HIBE_backend_admitted"] is False


@pytest.mark.parametrize("args", ((True, 77, 1), (4096, True, 1), (4096, 77, True),
                                 (4096, 77, 0), (4096, 77, 33), (16385, 77, 1)))
def test_invalid_counting_domain_is_rejected_without_large_allocations(args):
    with pytest.raises(ValueError): radix.width_group(*args)
