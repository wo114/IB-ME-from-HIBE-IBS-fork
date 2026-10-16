"""Bounded public product samplers for the opt-in SRGG reduction experiment.

No trapdoor, key service, production backend, or whole-batch retry is used.
The n512 command produces only zero-entropy certificates. Actual draw functions
are separately callable research functions using the frozen scalar law.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import platform

from sage.version import version as sage_version

from ibme.core.randomness import SecureRandom
from experiments.research.gaussian_reference import draw_uniform_integer
from .aggregate_budget import MAX_BYTES, MAX_COUNT, AggregateByteSource, batch_certificate, sample_batch
from .wide_scalar import WideScalarGaussian, WideScalarOptions


SCHEMA = "IBME/SRGG-REDUCTION-PUBLIC-SAMPLERS/1"


def _int(value, name, low=1, high=MAX_COUNT):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: " + name)
    return value


@dataclass(frozen=True)
class ReductionParameters:
    """Only public dimensions and squared widths, no private execution object."""

    degree: int = 512
    rank: int = 2
    digits: int = 8
    p: int = 16383
    master_squared: int = 1031865954433
    signature_squared: int = 22159188660729268928705

    def __post_init__(self):
        _int(self.degree, "degree", 2, 4096)
        if self.degree & (self.degree-1):
            raise ValueError("power-of-two degree required")
        _int(self.rank, "rank", high=16)
        _int(self.digits, "digits", high=64)
        _int(self.p, "p", high=2**64)
        _int(self.master_squared, "master squared width", high=2**96)
        _int(self.signature_squared, "signature squared width", high=2**96)
        for name, count in (("N", self.N), ("D", self.D), ("H", self.H)):
            _int(count, name)

    @property
    def N(self):
        return (2+self.digits)*self.rank*self.degree

    @property
    def D(self):
        return self.N+self.degree

    @property
    def H(self):
        return self.rank*self.degree


def _params(params):
    if not isinstance(params, ReductionParameters):
        raise ValueError("validated public ReductionParameters required")
    return params


def deep_scalar_options():
    """Exactly the frozen query-bounded-deep scalar profile, without Series."""
    return WideScalarOptions(tail_bits=192, mass_bits=256, precision_bits=384,
        gaussian_abort_bits=192, max_uniform_trials=256, target_tv_bits=160)


def gaussian_product_certificate(width_squared, count, *, error_bits=192, max_bytes=MAX_BYTES):
    """Distance to ideal isotropic D_Z^count with density exp(-pi||x||²/v)."""
    _int(width_squared, "squared width", high=2**96)
    _int(count, "coordinate count")
    sampler = WideScalarGaussian(width_squared, width_squared, options=deep_scalar_options())
    batch = batch_certificate(sampler, count, error_bits=error_bits, max_bytes=max_bytes)
    return {"squared_width": str(width_squared), "count": count,
        "target": "independent D_Z,0,width_squared coordinate product",
        "scalar": sampler.certificate(), "batch": batch,
        "finite_to_ideal_tv_upper_including_abort_exact": batch["scalar_kernel_tv_including_aggregate_exact"],
        "abort_upper_exact": batch["abort_upper_including_aggregate_exact"],
        "whole_batch_retries": 0, "partial_output_on_abort": False}


def _sample_product(width_squared, count, *, rng, error_bits, max_bytes):
    # Validate and certify all public inputs before accessing even the first byte.
    certificate = gaussian_product_certificate(width_squared, count,
        error_bits=error_bits, max_bytes=max_bytes)
    if not certificate["batch"]["admitted"]:
        raise ValueError("Gaussian product aggregate cap exceeds public byte budget")
    sampler = WideScalarGaussian(width_squared, width_squared, options=deep_scalar_options())
    return sample_batch(sampler, width_squared, (0,)*count, rng=rng,
        error_bits=error_bits, max_bytes=max_bytes)


def sample_public_u(params, *, rng=None, error_bits=192, max_bytes=MAX_BYTES):
    """Bounded draw near D_Z^N,master; abort propagates without retry."""
    params = _params(params)
    return _sample_product(params.master_squared, params.N, rng=rng,
        error_bits=error_bits, max_bytes=max_bytes)


def sample_simulator_z(params, *, rng=None, error_bits=192, max_bytes=MAX_BYTES):
    """Bounded draw near D_Z^D,signature; no Rec or norm conditioning here."""
    params = _params(params)
    return _sample_product(params.signature_squared, params.D, rng=rng,
        error_bits=error_bits, max_bytes=max_bytes)


def uniform_vector_certificate(bound, count, *, max_trials=256, max_bytes=MAX_BYTES):
    """Mask/reject per coordinate; the byte cap covers every bounded path."""
    _int(bound, "uniform bound", high=2**64)
    _int(count, "uniform count")
    _int(max_trials, "uniform trials", high=4096)
    _int(max_bytes, "uniform byte budget", high=MAX_BYTES)
    bits = (bound-1).bit_length()
    if bits*max_trials > 8192:
        raise ValueError("uniform rejection exact-certificate bit budget exceeded")
    candidate_bytes = (bits+7)//8
    rejection = Fraction(2**bits-bound, 2**bits)
    abort = rejection**max_trials
    cap = count*max_trials*candidate_bytes
    return {"bound": bound, "count": count, "candidate_bits": bits,
        "candidate_bytes": candidate_bytes, "max_trials_per_coordinate": max_trials,
        "candidate_rejection_probability_exact": str(rejection),
        "per_coordinate_abort_probability_exact": str(abort),
        "batch_abort_formula": "1-(1-rho^T)^count",
        "batch_abort_upper_exact": str(min(Fraction(1), count*abort)),
        "finite_to_ideal_tv_upper_including_abort_exact": str(min(Fraction(1), count*abort)),
        "conditional_on_success_exact_uniform_product": True,
        "all_path_byte_cap": cap, "public_max_bytes": max_bytes,
        "admitted": cap <= max_bytes, "extra_budget_abort_probability_exact": "0",
        "whole_batch_retries": 0, "partial_output_on_abort": False,
        "requires_independent_uniform_bytes": True}


def sample_uniform_e(params, *, rng=None, max_trials=256, max_bytes=MAX_BYTES):
    """Exact uniform [0,p)^H conditional on success, retaining bounded abort."""
    params = _params(params)
    cert = uniform_vector_certificate(params.p, params.H,
        max_trials=max_trials, max_bytes=max_bytes)
    if not cert["admitted"]:
        raise ValueError("uniform-vector worst-path cap exceeds public byte budget")
    source = AggregateByteSource(SecureRandom() if rng is None else rng,
        max(1, cert["all_path_byte_cap"]))
    return tuple(draw_uniform_integer(source, params.p, max_trials=max_trials)
        for _ in range(params.H))


def binary_vector_certificate(degree):
    _int(degree, "binary challenge length")
    return {"degree": degree, "random_bytes": (degree+7)//8,
        "target": "exact independent uniform n-bit coefficient vector",
        "coefficient_order": "coefficient j is bit j of the big-endian integer",
        "unused_high_bits_discarded": (-degree) % 8,
        "finite_to_ideal_tv_upper_including_abort_exact": "0",
        "abort_probability_exact": "0", "whole_batch_retries": 0,
        "requires_independent_uniform_bytes": True}


def sample_binary_challenge(degree, *, rng=None):
    """Exactly uniform bits; unused high byte bits are discarded, never reduced."""
    cert = binary_vector_certificate(degree)
    source = AggregateByteSource(SecureRandom() if rng is None else rng, cert["random_bytes"])
    value = int.from_bytes(source.read(cert["random_bytes"]), "big")
    return tuple((value >> j) & 1 for j in range(degree))


def build_report(params=None):
    """Pure certificate path: constructs no random source and performs no draw."""
    params = ReductionParameters() if params is None else _params(params)
    public_u = gaussian_product_certificate(params.master_squared, params.N)
    simulator_z = gaussian_product_certificate(params.signature_squared, params.D)
    uniform_e = uniform_vector_certificate(params.p, params.H)
    challenge = binary_vector_certificate(params.degree)
    paths = (Path(__file__), Path(__file__).with_name("wide_scalar.py"),
        Path(__file__).with_name("aggregate_budget.py"),
        Path(__file__).parents[2]/"gaussian_reference.py",
        Path(__file__).parents[4]/"src/ibme/lattice/chkp/gaussian.py")
    return {"schema": SCHEMA, "parameters": asdict(params),
        "dimensions": {"N": params.N, "D": params.D, "H": params.H},
        "scalar_profile": "query-bounded-deep", "aggregate_error_bits": 192,
        "public_u": public_u, "simulator_z": simulator_z,
        "uniform_e": uniform_e, "binary_challenge": challenge,
        "all_samplers_admitted_under_public_caps": all((public_u["batch"]["admitted"],
            simulator_z["batch"]["admitted"], uniform_e["admitted"])),
        "actual_entropy_bytes": 0, "draw_performed": False,
        "environment": {"platform": platform.platform(), "python": platform.python_version(),
            "sage": sage_version, "machine": platform.machine(), "processor": platform.processor()},
        "source_sha256": {str(path.relative_to(Path(__file__).parents[4])):
            hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
        "scope": "independent public product laws only; no repair, Rec, norm gate, oracle programming, service or IBS lifecycle",
        "production_backend_modified": False, "private_trapdoor_read": False,
        "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False,
        "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(build_report(), indent=2)+"\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    main()
