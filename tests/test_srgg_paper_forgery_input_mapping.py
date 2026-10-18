"""Independent checks for the source-to-verifier forgery instance mapping."""
from itertools import product

from sage.all import ZZ, matrix, vector

from experiments.research.candidates.srgg.paper_algebra import (
    PaperRing, identity_target, message_challenge, public_matrix,
)
from experiments.research.candidates.srgg.paper_forgery_input_mapping import build_report
from experiments.research.candidates.srgg.paper_objects import PublicKey
from experiments.research.candidates.srgg.paper_parameters import PaperParams


def _negacyclic_block(poly):
    n = len(poly)
    result = matrix(ZZ, n, n)
    for exponent, coefficient in enumerate(poly):
        for column in range(n):
            position = exponent + column
            result[position % n, column] += coefficient * (-1 if position >= n else 1)
    return result


def _lattice_index(columns, modulus):
    augmented = columns.augment(modulus * matrix.identity(ZZ, columns.nrows()))
    return ZZ.prod(abs(value) for value in augmented.elementary_divisors())


def test_small_ring_affine_target_membership_is_exact():
    # Deliberately independent integer matrix; n=4, d=1, Q=15.
    n, Q = 4, 15
    one = (1, 0, 0, 0)
    h = (1, 2, 3, 4)
    zeta = (1, 0, -1, 0)
    A = (one, (2, 1, 0, 0), (0, 3, 1, 0), (4, 0, 2, 1))
    M = matrix.block([[_negacyclic_block(tuple(2 * a for a in poly))
                       for poly in A] + [
        _negacyclic_block(tuple(Q * a - 2 * b for a, b in zip(zeta, h)))
    ]])
    image_index = _lattice_index(M, 2 * Q)
    assert image_index == 2**(n // 2)

    c = vector(ZZ, (1, 1, 0, 1))
    shift = Q * _negacyclic_block(zeta) * c
    # For every parity pattern of the selected commitment w, Smith index
    # checks membership of w+Qjc in the actual mod-2Q image.
    for bits in product((0, 1), repeat=n):
        target = vector(ZZ, bits) + shift
        in_image = _lattice_index(M.augment(matrix(ZZ, n, 1, target)), 2 * Q) == image_index
        assert in_image == (bits[0] == bits[2] and bits[1] == bits[3])


def test_original_param_i_zero_commitment_has_a_public_representative():
    # This public object is algebraic and deliberately NOT an accepted Setup root.
    params = PaperParams("PARAM-I")
    ring = PaperRing(params)
    seed = bytes([17]) * 32
    a_hat = public_matrix(params, seed)
    public = PublicKey(params, seed, a_hat, ring.gadget())
    zero = ring.constant(0)
    commitment = (zero,) * params.rank
    h = identity_target(public, b"fixed-identity")
    c = message_challenge(public, commitment, b"fresh-message")
    head = tuple(ring.multiply(hi, c, params.modulus) for hi in h)
    tail = (zero,) * (params.columns - params.rank)
    shifted = ((head[0][0] + params.modulus,) + head[0][1:],) + head[1:]
    negative_lift = ((head[0][0] - params.modulus,) + head[0][1:],) + head[1:]
    compensated_head = tuple(tuple(a-b for a, b in zip(hi, public.a_hat[i][0]))
                             for i, hi in enumerate(head))
    compensated_tail = (ring.constant(1),) + tail[1:]
    broken = ((head[0][0] + 1,) + head[0][1:],) + head[1:]
    for x, expected in ((head + tail, True), (shifted + tail, True),
                        (negative_lift + tail, True),
                        (compensated_head + compensated_tail, True),
                        (broken + tail, False)):
        z = x + (c,)
        assert len(z) == params.columns + 1
        qary_holds = ring.matvec(ring.public_a(public), x, params.modulus) == head
        assert qary_holds is expected
        assert (ring.recover(public, h, z, c) == commitment) is qary_holds
    # No norm assertion: an unrestricted preimage is not a short forgery.


def test_three_original_rows_and_security_scope():
    report = build_report()
    assert report["security_claim"] == "none"
    assert report["backend_admitted"] is False
    assert report["parameters_are_formal"] is False
    assert report["nist_security_category"] is None
    assert [(row["integer_response_dimension"],
             row["integer_target_dimension"],
             row["integer_kernel_determinant"])
            for row in report["rows"]] == [
                (4608, 1024, {"Q_power": 1024, "two_power": 256}),
                (6656, 1536, {"Q_power": 1536, "two_power": 256}),
                (8704, 2048, {"Q_power": 2048, "two_power": 256}),
            ]
    assert all(row["actual_short_solution_or_attack_cost"] is None
               and row["author_table5_forgery_bits_reproduced"] is False
               for row in report["rows"])
