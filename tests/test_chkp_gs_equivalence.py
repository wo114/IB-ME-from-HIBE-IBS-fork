"""Exact GS optimization: public matrices, every intermediate gate, test RNG.

The legacy oracle retains the former residual projection and generic rational
gate. These fixtures contain no generated root, parent, or leaf key material.
"""

from fractions import Fraction
from hashlib import sha256

import pytest

pytest.importorskip("sage.all")
from sage.all import QQ, ZZ, matrix, vector

from ibme.core.randomness import DeterministicRandom
from ibme.lattice.chkp import finite_gpv
from ibme.lattice.chkp.root_basis import private_root_basis


def legacy_geometry(rows, bits, *, gate=None):
    gate = finite_gpv._bounded_rational if gate is None else gate
    columns = tuple(matrix(ZZ, rows).columns())
    orthogonal, squared, weights = [], [], []
    for column in columns:
        current = vector(QQ, column)
        for g, norm in zip(orthogonal, squared):
            current -= (current.dot_product(g) / norm) * g
            for entry in current:
                gate(entry, "GS intermediate", bits)
        norm = gate(current.dot_product(current), "GS squared length", bits)
        if norm <= 0:
            raise ValueError("Basis must have full integer rank")
        weight = tuple(gate(x / norm, "GS weight", bits) for x in current)
        current.set_immutable()
        column.set_immutable()
        orthogonal.append(current)
        squared.append(norm)
        weights.append(weight)
    return columns, tuple(squared), tuple(weights)


def public_dense_rows(dimension):
    # Strict diagonal dominance fixes full rank; all entries are public.
    return [[(dimension * 1024 if i == j else 0) +
             int.from_bytes(sha256(f"PUBLIC-GS/{i}/{j}".encode()).digest()[:2], "big") % 1024 - 512
             for j in range(dimension)] for i in range(dimension)]


def outcome(call):
    try:
        return ("ok", call())
    except (ValueError, TypeError, ZeroDivisionError) as exc:
        return (type(exc).__name__, str(exc))


@pytest.mark.parametrize("bits", [1, 7, 64, 8192])
def test_internal_gate_matches_generic_at_signed_integer_fraction_boundaries(bits):
    edge = ZZ(2)**bits
    values = [QQ(0), QQ(1), QQ(-1), QQ(edge-1), QQ(edge), QQ(-edge+1), QQ(-edge),
              QQ(1)/(edge-1), QQ(1)/edge, -QQ(1)/(edge-1), -QQ(1)/edge,
              QQ(edge-1)/(edge-2) if bits > 1 else QQ(1)]
    for value in values:
        assert outcome(lambda: finite_gpv._bounded_qq(value, "x", bits)) == outcome(
            lambda: finite_gpv._bounded_rational(value, "x", bits))


@pytest.mark.parametrize("value", [True, 0.5, complex(1), object(), "1e1000000", "1/0"])
def test_external_input_gate_still_rejects_invalid_types_and_text(value):
    with pytest.raises(ValueError):
        finite_gpv._bounded_rational(value, "public", 64)


@pytest.mark.parametrize("value", [3, ZZ(-3), Fraction(2, 7), " -2/7 "])
def test_external_input_gate_still_accepts_its_exact_types(value):
    assert finite_gpv._bounded_rational(value, "public", 64) == QQ(value)


PUBLIC_ROWS = [
    [[1]], [[-7]], [[0]], [[2, 0], [0, 3]],
    [[3, 2, -1], [1, 4, 3], [2, -2, 5]],
    [[1, 2**40, -2**63], [0, 1, 2**37], [0, 0, 1]],
    [[1, 2], [2, 4]], public_dense_rows(9),
    [[2**20, 2**20+1, 2**63], [1, 1, 0], [0, 0, 1]],
]


@pytest.mark.parametrize("rows", PUBLIC_ROWS)
@pytest.mark.parametrize("bits", [1, 8, 64, 8192])
def test_every_intermediate_gate_value_order_and_rejection_match(monkeypatch, rows, bits):
    old_trace, new_trace = [], []
    old_gate, new_gate = finite_gpv._bounded_rational, finite_gpv._bounded_qq

    def recording_old(value, name, limit):
        old_trace.append((value, name, limit))
        return old_gate(value, name, limit)

    def recording_new(value, name, limit):
        new_trace.append((value, name, limit))
        return new_gate(value, name, limit)

    old = outcome(lambda: legacy_geometry(rows, bits, gate=recording_old))
    monkeypatch.setattr(finite_gpv, "_bounded_qq", recording_new)
    new = outcome(lambda: finite_gpv._gs_geometry(rows, bits))
    assert new == old
    assert new_trace == old_trace
    if new[0] == "ok":
        assert all(column.is_immutable() for column in new[1][0])


def test_intermediate_overflow_is_rejected_even_when_final_geometry_fits():
    rows = [[2**20, 2**20+1, 2**63], [1, 1, 0], [0, 0, 1]]
    # An unchecked final-only gate would admit this matrix: after all
    # projections b3*=(0,0,1), but after its first projection an 84-bit
    # numerator exceeds the 64-bit intermediate budget.
    _, squared, weights = legacy_geometry(rows, 8192)
    assert all(finite_gpv._bounded_rational(x, "final", 64) == x
               for x in (*squared, *(x for row in weights for x in row)))
    for geometry in (legacy_geometry, finite_gpv._gs_geometry):
        with pytest.raises(ValueError, match="GS intermediate exceeds"):
            geometry(rows, 64)


class RecordingSource:
    def __init__(self):
        self.rng = DeterministicRandom(b"PUBLIC-GS-FIXED-STREAM")
        self.reads = []

    def read(self, count):
        self.reads.append(count)
        return self.rng.read(count)


def test_constructor_geometry_preserves_certificate_samples_and_every_rng_read(monkeypatch):
    basis = private_root_basis([[1, 3]],
        [[1, -2, 1, 0, 2], [-1, 0, 2, 1, -2]], 17)
    new = finite_gpv.FirstFiniteGPV(basis, 2**28, epsilon_bits=128)
    monkeypatch.setattr(finite_gpv, "_gs_geometry", legacy_geometry)
    old = finite_gpv.FirstFiniteGPV(basis, 2**28, epsilon_bits=128)
    assert new.certificate() == old.certificate()
    assert new._path_resources == old._path_resources
    left, right = RecordingSource(), RecordingSource()
    for syndrome in ((0,), (1,), (8,), (16,)):
        assert new.sample(syndrome, rng=left) == old.sample(syndrome, rng=right)
    assert left.reads == right.reads
