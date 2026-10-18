"""Opt-in wide SRGG scalar Gaussian, using the unchanged finite rejection law.

No production class, bound, backend or wire is changed. This standalone profile
validates all its own admissions; it never bypasses OnlineScalarGaussian's
constructor. Only shared exact/interval/uniform/tape primitives are reused.
Run with the prescribed WSL Sage environment. Variable time; research only.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
from time import perf_counter

from sage.all import QQ, RealIntervalField
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom, SecureRandom
from experiments.research.gaussian_reference import SamplingAbort, draw_uniform_integer, interval_bounds
from experiments.research.mp12_sampled_reference import FiniteByteTape
from experiments.research.online_gaussian_reference import (
    capped_exp_minus_pi, exact_integer, exact_rational, interval_upper,
)


SCHEMA = "IBME/SRGG-WIDE-SCALAR/1"


@dataclass(frozen=True)
class WideScalarOptions:
    tail_bits: int = 128
    mass_bits: int = 192
    precision_bits: int = 256
    gaussian_abort_bits: int = 128
    max_uniform_trials: int = 192
    max_gaussian_trials: int = 100000
    max_radius: int = 2**56
    rational_bits: int = 8192
    max_tape_bytes: int = 256*1024*1024
    max_width_squared: int = 2**96
    max_output_bits: int = 1024
    target_tv_bits: int = 96

    def __post_init__(self):
        ranges = {"tail_bits": (8, 1024), "mass_bits": (32, 2048),
            "precision_bits": (96, 4096), "gaussian_abort_bits": (8, 1024),
            "max_uniform_trials": (1, 4096), "max_gaussian_trials": (1, 1000000),
            "max_radius": (1, 2**80), "rational_bits": (128, 8192),
            "max_tape_bytes": (1, 256*1024*1024), "max_width_squared": (1, 2**128),
            "max_output_bits": (16, 8192), "target_tv_bits": (8, 512)}
        for name, (low, high) in ranges.items():
            object.__setattr__(self, name, exact_integer(getattr(self, name), name,
                minimum=low, maximum=high))


def _rational(value, name, options):
    # Bound text before Sage parsing; prohibit exponent/arbitrary expression input.
    if isinstance(value, str) and (len(value) > 2*options.rational_bits+8 or
            re.fullmatch(r"[+-]?[0-9]+(?:/[0-9]+|\.[0-9]+)?", value) is None):
        raise ValueError("bounded plain exact rational text required: " + name)
    return exact_rational(value, name, max_bits=options.rational_bits)


class _ByteBudget:
    def __init__(self, source, maximum):
        if not callable(getattr(source, "read", None)):
            raise ValueError("random source must implement read(n)->bytes")
        self.source, self.maximum, self.used = source, maximum, 0

    def read(self, size):
        if type(size) is not int or size < 0 or self.used+size > self.maximum:
            raise SamplingAbort("wide scalar entropy budget exhausted; no fallback")
        data = self.source.read(size)
        if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != size:
            raise ValueError("invalid wide scalar random byte count or type")
        data = bytes(data)
        if len(data) != size:
            raise ValueError("wide scalar bytes conversion changed the byte count")
        self.used += size
        return data


class WideScalarGaussian:
    """The same uniform-box / interval-rounded Bernoulli law, new public class.

    Independent validation deliberately avoids inheritance or monkeypatching of
    the legacy constructor. A profile admits a range, but very wide ratios may
    fail acceptance/trial/tape or total-TV admission even below the width cap.
    """

    def __init__(self, width_min_squared, width_max_squared, *, options=None):
        self.options = WideScalarOptions() if options is None else options
        if not isinstance(self.options, WideScalarOptions):
            raise ValueError("explicit WideScalarOptions required")
        opts = self.options
        self.v_min = _rational(width_min_squared, "minimum squared width", opts)
        self.v_max = _rational(width_max_squared, "maximum squared width", opts)
        if not 1 <= self.v_min <= self.v_max <= opts.max_width_squared:
            raise ValueError("wide squared widths outside the explicit public class")
        self.field = RealIntervalField(opts.precision_bits)
        self.cap_bits = max(opts.mass_bits, opts.tail_bits, opts.precision_bits)+64
        e = (opts.mass_bits-1).bit_length()
        if opts.precision_bits < e+24:
            raise ValueError("insufficient precision for uniform weight rounding")
        self.weight_width = QQ(2)**(e+8-opts.precision_bits)
        self.tail_target = QQ(1)/2**opts.tail_bits

        def tail_at(radius):
            a = capped_exp_minus_pi((QQ((radius+1)**2)-QQ(1)/4)/self.v_max,
                self.field, self.cap_bits)
            ratio = capped_exp_minus_pi(QQ(2*(radius+1)+1)/self.v_max,
                self.field, self.cap_bits)
            denominator = 1-ratio
            if interval_bounds(denominator)[0] <= 0:
                return None
            return interval_upper(2*a/denominator)

        high = opts.max_radius
        tail = tail_at(high)
        if tail is None or tail > self.tail_target:
            raise ValueError("wide public radius cannot certify the tail target")
        low = 0
        while low+1 < high:
            middle = (low+high)//2
            trial = tail_at(middle)
            if trial is not None and trial <= self.tail_target:
                high = middle
            else:
                low = middle
        self.radius = high
        self.tail_upper = tail_at(high)
        if self.tail_upper is None or self.tail_upper > self.tail_target:
            raise ValueError("wide final radius tail certificate failed")
        self.max_support_count = 2*high+2
        a = capped_exp_minus_pi(self.v_min, self.field, self.cap_bits)
        self.theta = interval_upper(2*a/(1-a**3))
        if not 0 <= self.theta < 1:
            raise ValueError("wide Poisson normalizer bound not certified")
        self.quantization_error = self.max_support_count*(self.weight_width+QQ(1)/2**opts.mass_bits)
        normalizer_min = interval_bounds(self.field(self.v_min).sqrt()*(1-self.field(self.theta)))[0]
        self.acceptance_mass_lower = max(QQ(1), normalizer_min-self.tail_upper-self.quantization_error)
        self.acceptance_probability_lower = self.acceptance_mass_lower/self.max_support_count
        if not 0 < self.acceptance_probability_lower <= 1:
            raise ValueError("invalid wide uniform acceptance lower bound")
        ln2_upper = interval_upper(self.field(2).log())
        self.gaussian_trials = int((opts.gaussian_abort_bits*ln2_upper/self.acceptance_probability_lower).ceil())+1
        if self.gaussian_trials > opts.max_gaussian_trials:
            raise ValueError("wide public Gaussian rejection budget insufficient")
        self.uniform_abort_upper = self.gaussian_trials*QQ(1)/2**opts.max_uniform_trials
        self.rejection_abort_upper = QQ(1)/2**opts.gaussian_abort_bits
        self.abort_upper = self.rejection_abort_upper+self.uniform_abort_upper
        self.tv_upper = min(QQ(1), self.tail_upper+self.quantization_error+self.abort_upper)
        if self.tv_upper > QQ(1)/2**opts.target_tv_bits:
            raise ValueError("wide scalar total-TV budget not certified")
        self.bernoulli_bytes = (opts.mass_bits+7)//8
        self.candidate_bytes = ((self.max_support_count-1).bit_length()+7)//8
        self.random_tape_bytes = self.gaussian_trials*(opts.max_uniform_trials*self.candidate_bytes+self.bernoulli_bytes)
        if self.random_tape_bytes > opts.max_tape_bytes:
            raise ValueError("wide public scalar tape exceeds resource budget")
        if (self.radius+1).bit_length() > opts.max_output_bits:
            raise ValueError("wide zero-center output exceeds public coefficient budget")

    def checked_inputs(self, width_squared, center):
        width = _rational(width_squared, "squared width", self.options)
        center = _rational(center, "center", self.options)
        if not self.v_min <= width <= self.v_max:
            raise ValueError("width outside the wide public class")
        # Every possible accepted output is checked, before reading any entropy.
        if int(abs(center).ceil()+self.radius+1).bit_length() > self.options.max_output_bits:
            raise ValueError("wide all-path output coefficient budget exceeded")
        shift = int(center.floor())
        fractional = center-shift
        closest = 0 if fractional <= QQ(1)/2 else 1
        low, high = -self.radius, self.radius+int(fractional != 0)
        return width, shift, fractional, closest, low, high

    def integer_weight(self, value, width, fractional, closest):
        argument = ((value-fractional)**2-(closest-fractional)**2)/width
        if argument < 0:
            raise ValueError("negative relative Gaussian exponent")
        if argument >= self.options.mass_bits:
            return 0
        lower = interval_bounds(capped_exp_minus_pi(argument, self.field, self.cap_bits))[0]
        mass = int((2**self.options.mass_bits*lower).floor())
        if not 0 <= mass <= 2**self.options.mass_bits:
            raise ValueError("wide integer Bernoulli mass outside its exact range")
        return mass

    def sample(self, width_squared, center=0, *, rng=None):
        width, shift, fractional, closest, low, high = self.checked_inputs(width_squared, center)
        source = _ByteBudget(SecureRandom() if rng is None else rng, self.random_tape_bytes)
        for _ in range(self.gaussian_trials):
            value = low+draw_uniform_integer(source, high-low+1,
                max_trials=self.options.max_uniform_trials)
            mass = self.integer_weight(value, width, fractional, closest)
            ticket = int.from_bytes(source.read(self.bernoulli_bytes), "big") & ((1 << self.options.mass_bits)-1)
            if ticket < mass:
                return shift+value
        raise SamplingAbort("wide Gaussian rejection budget exhausted; no retry or fallback")

    def sample_from_tape(self, width_squared, center, tape):
        self.checked_inputs(width_squared, center)
        if not isinstance(tape, (bytes, bytearray, memoryview)) or len(tape) != self.random_tape_bytes:
            raise ValueError("wide scalar tape must have the public fixed length")
        source = FiniteByteTape(tape)
        if len(source.data) != self.random_tape_bytes:
            raise ValueError("wide scalar tape byte count changed during conversion")
        return self.sample(width_squared, center, rng=source)

    def finite_distribution(self, width_squared, center=0, *, max_points=4096):
        """Exact normalized integer law conditional on success; small QA only."""
        width, shift, fractional, closest, low, high = self.checked_inputs(width_squared, center)
        limit = exact_integer(max_points, "enumeration limit", minimum=1, maximum=200000)
        if high-low+1 > limit:
            raise ValueError("wide audit enumeration exceeds max_points")
        masses = {shift+x: self.integer_weight(x, width, fractional, closest) for x in range(low, high+1)}
        total = sum(masses.values())
        return {x: QQ(m)/total for x, m in masses.items() if m}

    def certificate(self):
        return {"schema": SCHEMA, "algorithm": "same finite uniform-box rejection and interval-rounded Bernoulli",
            "density": "exp(-pi*(x-c)^2/width_squared)",
            "squared_width_class": [str(self.v_min), str(self.v_max)],
            "uniform_in_admitted_rational_centers": True,
            "rational_input_bit_budget": self.options.rational_bits,
            "internal_exponent_rational_bit_upper": 3*self.options.rational_bits+2*(self.radius+2).bit_length()+4,
            "center_admission": "exact rational and abs(center)+radius+1 fits max_output_bits",
            "radius": self.radius, "max_support_count": self.max_support_count,
            "support_or_centers_precomputed": 0, "CDF_tables": 0,
            "tail_upper": str(self.tail_upper), "relative_weight_interval_width_upper": str(self.weight_width),
            "integer_weight_quantization_tv_upper": str(self.quantization_error),
            "Poisson_theta_upper": str(self.theta), "acceptance_mass_lower": str(self.acceptance_mass_lower),
            "acceptance_probability_lower": str(self.acceptance_probability_lower),
            "max_gaussian_trials": self.gaussian_trials,
            "uniform_integer_abort_upper_per_call": str(QQ(1)/2**self.options.max_uniform_trials),
            "uniform_abort_union_upper": str(self.uniform_abort_upper),
            "gaussian_rejection_abort_upper": str(self.rejection_abort_upper),
            "abort_upper": str(self.abort_upper), "tv_upper_including_abort": str(self.tv_upper),
            "admission_tv_target": str(QQ(1)/2**self.options.target_tv_bits),
            "candidate_bytes_per_uniform_trial": self.candidate_bytes,
            "bernoulli_bytes_per_gaussian_trial": self.bernoulli_bytes,
            "public_tape_bytes": self.random_tape_bytes, "tape_exhaustion_at_public_length_upper": "0",
            "finite_options": asdict(self.options),
            "rounding_assumption": "correctly-rounded directed rational conversion, pi, sqrt, log, arithmetic and exp in MPFR/MPFI; exponent clipping before underflow",
            "randomness": "independent uniform bytes; test seeds do not establish this assumption",
            "production_API_modified": False, "constant_time": False,
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False}


def conditional_widths(candidate):
    """Actual Z-kernel widths; gadget bZ+a rescales to r^2, center -a/b."""
    return {"rounding_and_signing_u": candidate.r_squared,
            "master_lower": candidate.master_second_squared-candidate.base**2*candidate.r_squared,
            "signature_lower": candidate.signature_second_squared-2*candidate.r_squared}


class _CountingSource:
    def __init__(self, source):
        self.source, self.bytes = source, 0

    def read(self, size):
        result = self.source.read(size)
        self.bytes += size
        return result


def audit(*, repetitions=32):
    """Public candidate scalar draws only, never an n512 IBS lifecycle."""
    from .formal_candidates import conditional_candidate
    repetitions = exact_integer(repetitions, "repetitions", minimum=1, maximum=4096)
    rows = []
    for rank in (2, 3, 4):
        candidate = conditional_candidate(degree=512, rank=rank, digits=8)
        for name, width in conditional_widths(candidate).items():
            started = perf_counter()
            sampler = WideScalarGaussian(width, width)
            prepare_seconds = perf_counter()-started
            seed = f"IBME/SRGG-wide-scalar/n512/d{rank}/{name}".encode()
            source = _CountingSource(DeterministicRandom(seed))
            started = perf_counter()
            values = [sampler.sample(width, QQ(-7)/3, rng=source) for _ in range(repetitions)]
            draw_seconds = perf_counter()-started
            replay = DeterministicRandom(seed)
            replay_ok = values == [sampler.sample(width, QQ(-7)/3, rng=replay) for _ in range(repetitions)]
            system_source = _CountingSource(SecureRandom())
            system_value = sampler.sample(width, 0, rng=system_source)
            rows.append({"candidate": candidate.name, "stage": name, "width_squared": str(width),
                "width_role": "actual Z-kernel scalar width in the candidate algorithm",
                "certificate": sampler.certificate(), "prepare_seconds": prepare_seconds,
                "deterministic_draw_seconds": draw_seconds, "deterministic_repetitions": repetitions,
                "deterministic_seed_utf8": seed.decode(), "deterministic_center": "-7/3",
                "deterministic_entropy_bytes": source.bytes, "deterministic_replay_matches": replay_ok,
                "deterministic_max_output_bits": max(abs(v).bit_length() for v in values),
                "output_sha256": hashlib.sha256(json.dumps(values).encode()).hexdigest(),
                "system_random_draws": 1, "system_random_entropy_bytes": system_source.bytes,
                "system_random_output_bits": abs(system_value).bit_length(),
                "system_random_output_retained": False})
    repository = Path(__file__).parents[4]
    sources = (Path(__file__), Path(__file__).parents[2]/"online_gaussian_reference.py",
        Path(__file__).parents[2]/"mp12_sampled_reference.py", Path(__file__).with_name("formal_candidates.py"),
        repository/"src/ibme/lattice/chkp/gaussian.py", repository/"src/ibme/core/randomness.py")
    cpu_lines = Path("/proc/cpuinfo").read_text().splitlines() if Path("/proc/cpuinfo").exists() else []
    cpu = next((line.split(":", 1)[1].strip() for line in cpu_lines if line.startswith("model name")), platform.processor())
    return {"schema": SCHEMA, "environment": {"platform": platform.platform(),
            "python": platform.python_version(), "sage": sage_version, "cpu_model": cpu,
            "logical_cpu_count": os.cpu_count()},
            "source_sha256": {str(p.name): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
            "cases": rows, "actual_scalar_draws": len(rows)*(repetitions+1),
            "replay_draws_additional": len(rows)*repetitions, "identities": None, "messages": None,
            "gadget_coset_correspondence": "x=a+b*k converts bZ+a width b^2*r^2 and center 0 to Z width r^2 and center -a/b; old tables unchanged",
            "actual_n512_IBS_lifecycle": False, "full_vector_entropy_admitted": False,
            "security_claim": "none", "backend_admitted": False, "parameters_are_formal": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repetitions", type=int, default=32)
    arguments = parser.parse_args()
    report = audit(repetitions=arguments.repetitions)
    payload = json.dumps(report, indent=2)
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(payload+"\n", encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
