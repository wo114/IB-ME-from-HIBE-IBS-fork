"""Actual AP09 roots and original ABB bit semantics; no full-backend claim."""

from dataclasses import replace
from fractions import Fraction

import pytest

pytest.importorskip("sage.all", reason="use WSL ~/miniconda3/envs/sage; skip is not pass")
from sage.all import GF, QQ, ZZ, matrix

from ibme.core.errors import InvalidParameterError, RandomnessError
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.abb_rom import (ABBTrapGenParams, abb_trapgen, ABBBitPublic,
    ABBBitCiphertext, ABBBitEncryptor, ABBBitDecryptor, abb_decode_phase, abb_decrypt_bit)
from ibme.lattice.research import KernelBasis, ModMatrixReference, SamplingAbort
from experiments.research.chkp_basis import gram_schmidt_squared_lengths


class NoEntropy:
    calls = 0
    def read(self, n):
        self.calls += 1
        raise AssertionError("invalid input consumed entropy")


def small_params():
    return ABBTrapGenParams(1, 5, 6, 6, 24, hadamard_scale=8)


def assert_root(result):
    a = matrix(GF(result.params.q), result.basis.public.rows)
    b = matrix(ZZ, result.basis.basis_rows)
    assert a.rank() == result.params.n
    assert a * matrix(GF(result.params.q), b) == 0
    assert abs(b.det()) == result.params.q**result.params.n
    assert 0 < result.entropy_bytes <= result.params.random_tape_bytes
    assert result.security_claim == "none" and not result.backend_admitted


def test_ap09_root_uses_real_entropy_and_exact_short_full_basis():
    params = small_params()
    first = abb_trapgen(params, rng=DeterministicRandom(b"ABB-AP09-required-root"))
    replay = abb_trapgen(params, rng=DeterministicRandom(b"ABB-AP09-required-root"))
    actual = abb_trapgen(params)
    assert_root(first)
    assert_root(actual)
    assert first.basis == replay.basis
    assert first.basis.public != actual.basis.public
    assert max(gram_schmidt_squared_lengths(first.basis.basis_rows)) <= params.gs_squared_bound
    assert max(gram_schmidt_squared_lengths(actual.basis.basis_rows)) <= params.gs_squared_bound
    assert "basis_rows" not in repr(first)


def test_actual_ap09_root_above_legacy_192_dimension():
    params = ABBTrapGenParams(1, 65537, 48, 48, 160, hadamard_scale=24)
    result = abb_trapgen(params, rng=DeterministicRandom(b"ABB-AP09-208-required-root"))
    assert_root(result)
    assert result.basis.public.ncols == 208
    cert = params.certificate()
    assert cert["paper_setup_dimension_sufficient"]
    assert QQ(cert["output_vs_uniform_tv_upper_including_abort"]) < 1
    assert cert["full_ABB_HIBE"] is False


def test_wide_q_root_parameters_and_upward_uniformity_certificate():
    # This is a public preflight, not a newly generated 1122-dimensional key.
    q = int(ZZ(2**127).next_prime())
    params = ABBTrapGenParams(1, q, 400, 400, 1056, hadamard_scale=64)
    cert = params.certificate()
    bound = QQ(cert["paper_matrix_tv_upper_before_rank_abort"])
    target = QQ(params.m2**2 * q) / 2**params.random_rows
    assert 0 < bound < QQ(1)/2**120 and bound**2 >= target
    assert (bound - QQ(params.m2)/2**256)**2 < target
    assert cert["paper_setup_dimension_sufficient"]
    assert params.gs_squared_bound > 0
    assert cert["parameters_are_formal"] is False


@pytest.mark.parametrize("change", [
    {"q": 2}, {"q": 9}, {"q": True}, {"n": 1.0}, {"random_rows": 3},
    {"m1": 5}, {"m2": 15}, {"hadamard_scale": 1},
    {"max_entropy_bytes": 1}, {"m2": 1536},
])
def test_ap09_invalid_domain_rejected_before_entropy(change):
    with pytest.raises(InvalidParameterError):
        replace(small_params(), **change)


def test_ap09_rank_abort_keeps_one_attempt():
    class Zero:
        calls = 0
        def read(self, n):
            self.calls += 1
            return bytes(n)
    rng = Zero()
    with pytest.raises(SamplingAbort, match="rank failure"):
        abb_trapgen(small_params(), rng=rng)
    assert rng.calls == small_params().n * small_params().m1


def test_ap09_rng_contract_and_uniform_abort():
    class Bad:
        def read(self, n):
            return bytearray(n)
    with pytest.raises(RandomnessError):
        abb_trapgen(small_params(), rng=Bad())
    class High:
        def read(self, n):
            return b"\xff" * n
    with pytest.raises(SamplingAbort, match="Uniform"):
        abb_trapgen(replace(small_params(), uniform_trials=1), rng=High())


def public_gadget_fixture():
    # Public short gadget basis, deliberately NOT a TrapGen or HIBE key.
    q = 2**31 - 1
    m = (q - 1).bit_length()
    a = ModMatrixReference((tuple(2**j for j in range(m)),), q)
    rows = [[0] * m for _ in range(m)]
    for j in range(m - 1):
        rows[j][j] = 2
        rows[j + 1][j] = -1
    for i in range(m):
        rows[i][-1] = (q >> i) & 1
    basis = KernelBasis(a, rows)
    public = ABBBitPublic(a, (123456789,))
    factor = (2 * m * (1 + 2**128) - 1).bit_length()
    width = 8 * max(gram_schmidt_squared_lengths(rows)) * factor
    return public, basis, width


def test_original_abb_bit_formula_real_rounding_and_gpv_decryption():
    public, basis, width = public_gadget_fixture()
    encryptor = ABBBitEncryptor(public, Fraction(4, public.matrix.q))
    for index, bit in enumerate([0, 1, 1, 0]):
        ct = encryptor.encrypt(bit, rng=DeterministicRandom(f"ABB-Encrypt-{index}".encode()))
        recovered = abb_decrypt_bit(public, basis, ct, width,
            rng=DeterministicRandom(f"ABB-Decrypt-{index}".encode()))
        assert recovered == bit
    cert = encryptor.certificate()
    assert cert["noise_draws_per_bit"] == public.matrix.ncols + 1
    assert cert["scaled_width"] == "4"
    assert cert["anchor_modulus_used_for_ciphertext"] is False
    assert cert["scalar_certificate"]["target"].startswith("round(continuous")
    assert not cert["full_ABB_HIBE"]


def test_public_n1_attack_needs_no_private_basis_or_preimage():
    from experiments.attacks.abb_small_dimension import recover_n1_bit
    public, _, _ = public_gadget_fixture()
    encryptor = ABBBitEncryptor(public, Fraction(4, public.matrix.q))
    for bit in [0, 1]:
        ct = encryptor.encrypt(bit, rng=DeterministicRandom(f"ABB-n1-public-attack-{bit}".encode()))
        result = recover_n1_bit(public, ct, encryptor.noise.radius)
        assert result["candidate_bits"] == [bit]
        assert result["candidate_pairs"] == 1 and not result["private_inputs"]


def test_each_bit_uses_fresh_uniform_vector_and_fresh_noises():
    public, _, _ = public_gadget_fixture()
    encryptor = ABBBitEncryptor(public, Fraction(4, public.matrix.q))
    class Counting:
        source = DeterministicRandom(b"ABB-independent-bit-randomness")
        lengths = []
        def read(self, n):
            self.lengths.append(n)
            return self.source.read(n)
    rng = Counting()
    a = encryptor.encrypt(0, rng=rng)
    count = len(rng.lengths)
    b = encryptor.encrypt(0, rng=rng)
    assert a.c1 != b.c1
    assert count == public.matrix.ncols + 2
    assert rng.lengths[count:] == rng.lengths[:count]


def test_prepared_geometry_never_caches_sampled_decryption_preimage(monkeypatch):
    public, basis, width = public_gadget_fixture()
    encryptor = ABBBitEncryptor(public, Fraction(4, public.matrix.q))
    decryptor = ABBBitDecryptor(public, basis, width)
    actual_sample = decryptor.sampler.sample
    calls = []
    def fresh(syndrome, *, rng=None):
        output = actual_sample(syndrome, rng=rng)
        calls.append(output)
        return output
    monkeypatch.setattr(decryptor.sampler, "sample", fresh)
    ct = encryptor.encrypt(1, rng=DeterministicRandom(b"ABB-prepared-Encrypt"))
    assert decryptor.decrypt(ct, rng=DeterministicRandom(b"ABB-prepared-Decrypt1")) == 1
    assert decryptor.decrypt(ct, rng=DeterministicRandom(b"ABB-prepared-Decrypt2")) == 1
    assert len(calls) == 2 and calls[0] != calls[1]


@pytest.mark.parametrize("bit", [True, -1, 2, 1.0])
def test_bad_bit_rejected_without_entropy(bit):
    public, _, _ = public_gadget_fixture()
    encryptor = ABBBitEncryptor(public, Fraction(4, public.matrix.q))
    rng = NoEntropy()
    with pytest.raises(InvalidParameterError):
        encryptor.encrypt(bit, rng=rng)
    assert rng.calls == 0


def test_abb_integer_threshold_at_strict_boundaries():
    q = 23
    assert [abb_decode_phase(x, q) for x in [6, 7, 11, 15, 16]] == [0, 1, 1, 1, 0]
    # At q=5, nearest phase and ABB's strict floor(q/4) condition differ.
    assert abb_decode_phase(1, 5) == 0
    assert abb_decode_phase(2, 5) == 1
    with pytest.raises(InvalidParameterError):
        abb_decode_phase(0, 4)


def test_bit_dimensions_moduli_and_foreign_basis_reject_before_sampling():
    public, basis, width = public_gadget_fixture()
    encryptor = ABBBitEncryptor(public, Fraction(4, public.matrix.q))
    ct = encryptor.encrypt(1, rng=DeterministicRandom(b"ABB-malformed-CT-fixture"))
    rng = NoEntropy()
    for malformed in [ABBBitCiphertext(5, 0, (0, 0)),
                      ABBBitCiphertext(ct.q, ct.c0, ct.c1[:-1])]:
        with pytest.raises(InvalidParameterError):
            abb_decrypt_bit(public, basis, malformed, width, rng=rng)
    with pytest.raises(InvalidParameterError):
        ABBBitCiphertext(ct.q, ct.q, ct.c1)
    with pytest.raises(InvalidParameterError):
        ABBBitPublic(public.matrix, (0, 1))
    assert rng.calls == 0


def test_legacy_ap09_and_basisdel_resource_guards_unchanged():
    from experiments.research.chkp_genbasis import AP09Parameters
    from ibme.hibe.abb_rom import FiniteSampleR
    with pytest.raises(ValueError):
        AP09Parameters(1, 65537, 48, 48, 160, hadamard_scale=16)
    with pytest.raises(InvalidParameterError):
        FiniteSampleR(65537, 208, 16)
