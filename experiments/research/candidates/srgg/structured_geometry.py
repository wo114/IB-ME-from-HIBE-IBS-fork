"""Exact SRGG shape operators over QQ[X]/(X^n+1), without dense expansion.

This is an engineering component, not a sampler or IBS backend. It implements
the current shape algebra including the anisotropic signature top diagonal.
Only the scalar lower-block margin is admitted here; full shape positivity,
sampling distributions, finite errors, objects and wire are separate concerns.
Witnesses and intermediate polynomials may be private in future callers.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import pickle
import platform
import sys
from time import perf_counter

from sage.all import PolynomialRing, QQ, ZZ
from sage.version import version as sage_version


MAX_DEGREE = 4096
MAX_MODULE_ROWS = 128
MAX_MODULE_COLUMNS = 128
MAX_WITNESS_COEFFICIENTS = 2**20
MAX_RATIONAL_BITS = 4096
SCHEMA = "IBME/SRGG-STRUCTURED-GEOMETRY/1"


def _dimension(value, name, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("bounded positive integer required: " + name)
    return value


def _rational(value):
    if isinstance(value, bool) or not isinstance(value, (int, Fraction, type(ZZ(0)), type(QQ(0)))):
        raise ValueError("exact integer/rational coefficient required")
    value = QQ(value)
    if max(abs(int(value.numerator())).bit_length(), int(value.denominator()).bit_length()) > MAX_RATIONAL_BITS:
        raise ValueError("structured coefficient rational resource limit exceeded")
    return value


@dataclass(frozen=True, repr=False)
class StructuredGeometry:
    degree: int
    witness: tuple = field(repr=False)
    top_squared: tuple
    lower_squared: object
    noise_squared: object
    rounding_squared: object
    _ring: object = field(init=False, repr=False)
    _modulus: object = field(init=False, repr=False)
    _adjoint: tuple = field(init=False, repr=False)

    def __post_init__(self):
        n = _dimension(self.degree, "degree", MAX_DEGREE)
        if n < 2 or n & (n-1):
            raise ValueError("power-of-two negacyclic degree at least two required")
        if not isinstance(self.witness, (tuple, list)) or not self.witness:
            raise ValueError("finite nonempty witness matrix required")
        rows = _dimension(len(self.witness), "witness rows", MAX_MODULE_ROWS)
        first = self.witness[0]
        if not isinstance(first, (tuple, list)):
            raise ValueError("rectangular witness matrix required")
        columns = _dimension(len(first), "witness columns", MAX_MODULE_COLUMNS)
        if rows*columns*n > MAX_WITNESS_COEFFICIENTS:
            raise ValueError("structured witness coefficient budget exceeded")
        if any(not isinstance(row, (tuple, list)) or len(row) != columns for row in self.witness):
            raise ValueError("rectangular witness matrix required")
        if not isinstance(self.top_squared, (tuple, list)) or len(self.top_squared) != rows:
            raise ValueError("top diagonal must have one exact width per witness row")
        ring = PolynomialRing(QQ, "x")
        object.__setattr__(self, "_ring", ring)
        object.__setattr__(self, "_modulus", ring.gen()**n+1)
        witness = tuple(tuple(self._poly(poly) for poly in row) for row in self.witness)
        top = tuple(_rational(width) for width in self.top_squared)
        lower, noise, rounding = map(_rational, (self.lower_squared, self.noise_squared, self.rounding_squared))
        if min(top+(lower, noise, rounding)) <= 0:
            raise ValueError("positive exact squared widths required")
        if lower-noise <= rounding:
            raise ValueError("lower scalar margin must exceed the rounding floor")
        adjoint = tuple(tuple(self._conjugate(witness[i][j]) for i in range(rows)) for j in range(columns))
        object.__setattr__(self, "witness", witness)
        object.__setattr__(self, "top_squared", top)
        object.__setattr__(self, "lower_squared", lower)
        object.__setattr__(self, "noise_squared", noise)
        object.__setattr__(self, "rounding_squared", rounding)
        object.__setattr__(self, "_adjoint", adjoint)

    def __repr__(self):
        return "StructuredSrggGeometry(private_witness=<redacted>, sampler_implemented=False)"

    @property
    def upper_polynomials(self):
        return len(self.witness)

    @property
    def lower_polynomials(self):
        return len(self.witness[0])

    @property
    def lower_scalar(self):
        return self.lower_squared-self.noise_squared

    def _poly(self, value):
        if callable(getattr(value, "parent", None)) and value.parent() is self._ring:
            if value.degree() >= self.degree:
                raise ValueError("canonical polynomial degree less than n required")
            for coefficient in value.list():
                _rational(coefficient)
            return value
        if not isinstance(value, (tuple, list)) or len(value) != self.degree:
            raise ValueError("fixed-degree coefficient vector required")
        return self._ring([_rational(coefficient) for coefficient in value])

    def _conjugate(self, value):
        # X^-i = -X^(n-i) for 1<=i<n in the negacyclic quotient.
        coefficients = [QQ(0)]*self.degree
        coefficients[0] = value[0]
        for i in range(1, self.degree):
            coefficients[self.degree-i] = -value[i]
        return self._ring(coefficients)

    def _vector(self, value, count):
        if not isinstance(value, (tuple, list)) or len(value) != count:
            raise ValueError("ring vector module dimension mismatch")
        return tuple(self._poly(poly) for poly in value)

    def _matvec(self, matrix, vector):
        # No n-by-n coefficient operator is formed. Polynomial multiplication
        # uses Sage's exact QQ polynomial implementation, followed by reduction.
        return tuple(sum((poly*x for poly, x in zip(row, vector)), self._ring.zero()) % self._modulus
                     for row in matrix)

    def v_apply(self, lower):
        return self._matvec(self.witness, self._vector(lower, self.lower_polynomials))

    def v_adjoint_apply(self, upper):
        return self._matvec(self._adjoint, self._vector(upper, self.upper_polynomials))

    def factor_apply(self, lower):
        lower = self._vector(lower, self.lower_polynomials)
        return self._matvec(self.witness, lower)+lower

    def factor_adjoint_apply(self, full):
        full = self._vector(full, self.upper_polynomials+self.lower_polynomials)
        upper, lower = full[:self.upper_polynomials], full[self.upper_polynomials:]
        return tuple(x+y for x, y in zip(self._matvec(self._adjoint, upper), lower))

    def perturbation_apply(self, full):
        full = self._vector(full, self.upper_polynomials+self.lower_polynomials)
        gram = self.factor_apply(self.factor_adjoint_apply(full))
        widths = self.top_squared+(self.lower_squared,)*self.lower_polynomials
        return tuple(width*x-self.noise_squared*g for width, x, g in zip(widths, full, gram))

    def conditional_apply(self, upper):
        upper = self._vector(upper, self.upper_polynomials)
        gram = self._matvec(self.witness, self._matvec(self._adjoint, upper))
        scale = self.noise_squared*self.lower_squared/self.lower_scalar
        return tuple(width*x-scale*g for width, x, g in zip(self.top_squared, upper, gram))

    def conditioned_center(self, lower):
        scale = -self.noise_squared/self.lower_scalar
        return tuple(scale*x for x in self.v_apply(lower))

    def shifted_schur_apply(self, upper):
        upper = self._vector(upper, self.upper_polynomials)
        gram = self._matvec(self.witness, self._matvec(self._adjoint, upper))
        scale = self.noise_squared*(self.lower_squared-self.rounding_squared)/(
            self.lower_scalar-self.rounding_squared)
        return tuple((width-self.rounding_squared)*x-scale*g
                     for width, x, g in zip(self.top_squared, upper, gram))

    def public_metadata(self):
        rows, columns, n = self.upper_polynomials, self.lower_polynomials, self.degree
        return {
            "degree": n, "upper_polynomials": rows, "lower_polynomials": columns,
            "coefficient_dimension": (rows+columns)*n,
            "stored_witness_polynomials": rows*columns,
            "stored_adjoint_polynomials": rows*columns,
            "coefficient_slots_in_witness_and_adjoint": 2*rows*columns*n,
            "dense_shape_entries_if_expanded": ((rows+columns)*n)**2,
            "top_squared": list(map(str, self.top_squared)),
            "lower_squared": str(self.lower_squared), "noise_squared": str(self.noise_squared),
            "rounding_squared": str(self.rounding_squared), "lower_scalar": str(self.lower_scalar),
            "coefficient_matrices_materialized": False,
            "full_positive_definiteness_checked": False,
            "sampler_implemented": False,
        }


def master_operator(*, degree, rank, digits, base, witness,
                    first_squared, second_squared, r_squared):
    _dimension(rank, "rank", MAX_MODULE_ROWS//2)
    _dimension(digits, "digits", MAX_MODULE_COLUMNS)
    _dimension(base, "base", 2**16)
    if base < 3 or base % 2 == 0:
        raise ValueError("odd gadget base at least three required")
    if len(witness) != 2*rank or any(len(row) != digits*rank for row in witness):
        raise ValueError("master witness must have 2d by wd ring entries")
    result = StructuredGeometry(degree, witness, (first_squared,)*(2*rank),
                                second_squared, base**2*_rational(r_squared), r_squared)
    if any(coefficient not in (-1, 0, 1) for row in result.witness for poly in row for coefficient in poly.list()):
        raise ValueError("master witness requires the current CBD1 coefficient support")
    return result


def signature_operator(*, degree, rank, digits, user_vector,
                       first_squared, second_squared, r_squared, noise_factor=2):
    _dimension(rank, "rank", MAX_MODULE_ROWS)
    _dimension(digits, "digits", MAX_MODULE_ROWS)
    if type(noise_factor) is not int or noise_factor not in (1, 2):
        raise ValueError("explicit factor1/factor2 interpretation required")
    columns = (2+digits)*rank
    if len(user_vector) != columns:
        raise ValueError("full user vector must have (2+w)d ring entries")
    # The original signature geometry has wd top rows at second_squared,
    # followed by the one lower block at second_squared. Keep this anisotropy.
    top = (first_squared,)*(2*rank)+(second_squared,)*(digits*rank)
    return StructuredGeometry(degree, tuple((poly,) for poly in user_vector), top,
                              second_squared, noise_factor*_rational(r_squared), r_squared)


def _rss_kib():
    try:
        import resource

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if platform.system() == "Linux" else None
    except (ImportError, AttributeError):
        return None


def _summary(vector):
    data = [[str(coefficient) for coefficient in poly.list()] for poly in vector]
    return {"ring_polynomials": len(vector),
            "coefficient_sha256": hashlib.sha256(json.dumps(data).encode()).hexdigest()}


def audit_large(*, degree=512, rank=2, digits=8) -> dict:
    """Actual public operator execution; never a key generation or sampler run."""

    from .formal_candidates import conditional_candidate

    candidate = conditional_candidate(degree=degree, rank=rank, digits=digits)
    before = _rss_kib()
    witness = tuple(tuple(tuple(((i+3*j+5*k) % 3)-1 for k in range(degree))
                          for j in range(digits*rank)) for i in range(2*rank))
    user = tuple(tuple(((3*i+5*k) % 3)-1 for k in range(degree))
                 for i in range(candidate.columns))
    results = []
    for name, build in (
        ("master", lambda: master_operator(degree=degree, rank=rank, digits=digits, base=candidate.base,
            witness=witness, first_squared=candidate.master_first_squared,
            second_squared=candidate.master_second_squared, r_squared=candidate.r_squared)),
        ("signature", lambda: signature_operator(degree=degree, rank=rank, digits=digits,
            user_vector=user, first_squared=candidate.signature_first_squared,
            second_squared=candidate.signature_second_squared, r_squared=candidate.r_squared)),
    ):
        setup_started = perf_counter()
        operator = build()
        setup_seconds = perf_counter()-setup_started
        lower = tuple(tuple(((i+2*k) % 5)-2 for k in range(degree)) for i in range(operator.lower_polynomials))
        upper = tuple(tuple(((2*i+3*k) % 5)-2 for k in range(degree)) for i in range(operator.upper_polynomials))
        full = upper+lower
        operations = {}
        for operation, invoke in (
            ("v_apply", lambda: operator.v_apply(lower)),
            ("v_adjoint_apply", lambda: operator.v_adjoint_apply(upper)),
            ("factor_apply", lambda: operator.factor_apply(lower)),
            ("factor_adjoint_apply", lambda: operator.factor_adjoint_apply(full)),
            ("perturbation_apply", lambda: operator.perturbation_apply(full)),
            ("conditional_apply", lambda: operator.conditional_apply(upper)),
            ("conditioned_center", lambda: operator.conditioned_center(lower)),
            ("shifted_schur_apply", lambda: operator.shifted_schur_apply(upper)),
        ):
            started = perf_counter()
            output = invoke()
            elapsed = perf_counter()-started
            operations[operation] = {"elapsed_seconds": elapsed, **_summary(output)}
        metadata = operator.public_metadata()
        serialized = pickle.dumps((operator.witness, operator._adjoint), protocol=5)
        shallow = sum(sys.getsizeof(poly) for mat in (operator.witness, operator._adjoint)
                      for row in mat for poly in row)
        results.append({"operator": name, "metadata": metadata, "setup_seconds": setup_seconds,
                        "operations": operations, "ru_maxrss_kib": _rss_kib(),
                        "public_fixture_polynomial_pickle_bytes": len(serialized),
                        "polynomial_shallow_object_bytes": shallow,
                        "storage_measurement_scope": "public fixture serialization and shallow objects; not a wire format or full heap accounting"})
    cpu = platform.processor()
    if platform.system() == "Linux":
        try:
            cpu = next(line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                       if line.startswith("model name"))
        except (OSError, StopIteration):
            pass
    sources = (Path(__file__), Path(__file__).with_name("geometry.py"),
               Path(__file__).with_name("formal_candidates.py"))
    return {
        "schema": SCHEMA,
        "environment": {"python": sys.version, "sage": sage_version,
                        "platform": platform.platform(), "processor": cpu,
                        "source_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}},
        "fixture": {"degree": degree, "rank": rank, "digits": digits,
                    "source": "public deterministic integer patterns; neither master trapdoor nor issued user key",
                    "repetitions": 1, "identity_bytes": None, "message_bytes": None},
        "candidate_name": candidate.name, "rss_before_fixture_kib": before, "operators": results,
        "scope": "exact structured operator component only; no Gaussian output, signature or IBS lifecycle",
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "full_tv_certificate": False, "full_ibs_execution": False,
        "resource_limits": {"degree_max": MAX_DEGREE, "module_rows_max": MAX_MODULE_ROWS,
                            "module_columns_max": MAX_MODULE_COLUMNS,
                            "witness_coefficient_slots_max": MAX_WITNESS_COEFFICIENTS,
                            "rational_bits_max": MAX_RATIONAL_BITS},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    encoded = json.dumps(audit_large(), ensure_ascii=False, sort_keys=True, indent=2)+"\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8", newline="\n")
    print(encoded, end="")


if __name__ == "__main__":
    main()
