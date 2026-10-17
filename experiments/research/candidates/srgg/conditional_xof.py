"""Bounded classical ideal-XOF conditional raw trajectories, retaining abort.

One uniform source word supplies both the accept/reject decision and lift.
This does not program SHAKE, implement a QRO, or implement success-conditioned
K_h. The n512 report path performs no draws and constructs no random source.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import platform

from ibme.core.randomness import SecureRandom
from .seeded_xof import DEFAULT_INPUT, _dyadic_upper, rejection_layout


SCHEMA = "IBME/SRGG-CONDITIONAL-RAW-XOF/1"
MAX_BYTES = 256*1024*1024
MAX_COUNT = 2**20


def _int(value, name, low=0, high=MAX_BYTES):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+name)
    return value


def _shape(q, count, max_trials, max_bytes):
    _int(q, "modulus", 2, 2**128)
    _int(count, "target count", 1, MAX_COUNT)
    _int(max_trials, "maximum trials", 1, 4096)
    _int(max_bytes, "byte cap", 1, MAX_BYTES)
    width = ((q-1).bit_length()+7)//8
    return width, width*count*max_trials


def _targets(q, targets):
    if not isinstance(targets, (tuple, list)) or not 1 <= len(targets) <= MAX_COUNT:
        raise ValueError("bounded explicit canonical target list required")
    return tuple(_int(value, "target coefficient", 0, q-1) for value in targets)


def map_word(word, target, *, q, word_bits):
    """Exact deterministic pushforward; also callable on small-bit test models."""
    layout = rejection_layout(q, word_bits)
    _int(word, "raw word", 0, layout["word_range_size"]-1)
    _int(target, "target coefficient", 0, q-1)
    return word if word >= layout["limit"] else target+q*(word//q)


def conditional_certificate(*, q, count, max_trials=256, max_bytes=MAX_BYTES,
                            raw_query_budget=None):
    """Exact all-path certificate for G_h, including the original trial abort."""
    width, worst = _shape(q, count, max_trials, max_bytes)
    if raw_query_budget is None:
        query_budget = count*4096
    else:
        query_budget = _int(raw_query_budget, "raw query byte budget", 1, MAX_BYTES)
    layout = rejection_layout(q, 8*width)
    rho = Fraction(layout["rho"])
    bound, exponent = _dyadic_upper(min(Fraction(1), count*rho**max_trials))
    required = max(worst, query_budget)
    admitted = required <= max_bytes
    # Keep huge dyadics symbolic: q=2^128-1,T=4096 can have >10^5 bits.
    return {**layout, "word_bytes": width, "coefficient_count": count,
        "max_trials_per_coefficient": max_trials,
        "trajectory_random_bytes_all_paths": worst,
        "raw_query_budget_bytes": query_budget,
        "raw_query_budget_covers_complete_decoder": query_budget >= worst,
        "point_random_bytes_all_paths": required,
        "public_max_bytes": max_bytes, "admitted": admitted,
        "exact_original_abort_probability_expression": "1-(1-rho^T)^count",
        "original_abort_union_bound_factored": {"factor": count,
            "rejected_words": layout["rejected_words"],
            "word_range_size": layout["word_range_size"], "exponent": max_trials},
        "original_abort_upper_dyadic_exponent": exponent,
        "original_abort_upper_dyadic_expression": "0" if bound == 0 else f"2^({exponent})",
        "conditional_kernel_is": "G_h including original abort; not K_h conditioned on success",
        "helper_rejection_trials": 0, "helper_extra_abort_probability_exact": "0",
        "extra_runtime_byte_cap_abort_probability_exact": "0" if admitted else None,
        "finite_to_ideal_G_h_tv_exact": "0" if admitted else None,
        "requires_independent_uniform_source_bytes": True,
        "whole_trajectory_retries": 0, "suffix_restarts": 0,
        "raw_abort_remains_queryable": True,
        "invalid_or_overbudget_query_rejected_before_new_entropy": True}


@dataclass(frozen=True)
class Trajectory:
    q: int
    word_bytes: int
    words: tuple[int, ...]
    accepted: tuple[int, ...]
    success: bool

    @property
    def raw_prefix(self):
        return b"".join(word.to_bytes(self.word_bytes, "big") for word in self.words)


class _Source:
    def __init__(self, source, cap):
        if not callable(getattr(source, "read", None)):
            raise TypeError("source with read(n) required")
        self.source, self.cap, self.used = source, cap, 0

    def read(self, size):
        _int(size, "source request")
        if self.used+size > self.cap:
            raise ValueError("conditional-XOF source cap exhausted")
        data = self.source.read(size)
        if type(data) is not bytes or len(data) != size:
            raise ValueError("source returned wrong byte count/type")
        self.used += size
        return data


def _draw(q, targets, max_trials, width, source):
    size = 1 << (8*width)
    limit = size//q*q
    words, accepted = [], []
    for target in targets:
        for _ in range(max_trials):
            value = int.from_bytes(source.read(width), "big")
            if value >= limit:
                words.append(value)
                continue
            # Every lift k has exactly q preimages k*q,...,(k+1)*q-1.
            words.append(target+q*(value//q))
            accepted.append(target)
            break
        else:
            return Trajectory(q, width, tuple(words), tuple(accepted), False)
    return Trajectory(q, width, tuple(words), tuple(accepted), True)


def generate_trajectory(q, targets, *, rng=None, max_trials=256, max_bytes=MAX_BYTES):
    """Bounded executable G_h; returned success=False preserves raw failure."""
    # Admission is before constructing a production random source.
    _int(q, "modulus", 2, 2**128)
    targets = _targets(q, targets)
    width, worst = _shape(q, len(targets), max_trials, max_bytes)
    if worst > max_bytes:
        raise ValueError("conditional trajectory all-path byte cap not admitted")
    source = _Source(SecureRandom() if rng is None else rng, worst)
    return _draw(q, targets, max_trials, width, source)


class ConditionalPoint:
    """One classical raw point, fixed on its first nonempty prefix/offset read.

    Empty reads do not touch it. A failed decoding trajectory remains fixed
    and its raw bytes/suffix remain available. Entropy-source errors block the
    point instead of retrying. No table of adaptive identities is implemented.
    """
    def __init__(self, q, targets, *, rng=None, max_trials=256, max_bytes=MAX_BYTES,
                 raw_query_budget=None):
        _int(q, "modulus", 2, 2**128)
        self.targets = _targets(q, targets)
        self.certificate = conditional_certificate(q=q, count=len(self.targets),
            max_trials=max_trials, max_bytes=max_bytes, raw_query_budget=raw_query_budget)
        if not self.certificate["admitted"]:
            raise ValueError("conditional point all-path byte cap not admitted")
        if rng is not None and not callable(getattr(rng, "read", None)):
            raise TypeError("source with read(n) required")
        self.q, self.max_trials = q, max_trials
        self.rng = rng
        self._source, self._buffer, self._blocked = None, bytearray(), False
        self.trajectory, self.first_touches, self.position = None, 0, 0

    @property
    def source_bytes(self):
        return 0 if self._source is None else self._source.used

    @property
    def cached_bytes(self):
        return len(self._buffer)

    def read_at(self, offset, size):
        _int(offset, "raw offset")
        _int(size, "raw read length")
        end = offset+size
        if end > self.certificate["raw_query_budget_bytes"]:
            raise ValueError("raw-XOF query exceeds admitted byte budget")
        if self._blocked:
            raise ValueError("conditional point blocked after source failure; no reselection")
        if size == 0:
            return b""
        try:
            if self.trajectory is None:
                self.first_touches += 1
                self._source = _Source(SecureRandom() if self.rng is None else self.rng,
                    self.certificate["point_random_bytes_all_paths"])
                self.trajectory = _draw(self.q, self.targets, self.max_trials,
                    self.certificate["word_bytes"], self._source)
                self._buffer.extend(self.trajectory.raw_prefix)
            if end > len(self._buffer):
                self._buffer.extend(self._source.read(end-len(self._buffer)))
            return bytes(self._buffer[offset:end])
        except BaseException:
            self._blocked = True
            raise

    def prefix(self, size):
        return self.read_at(0, size)

    def read(self, size):
        result = self.read_at(self.position, size)
        self.position += size
        return result


def build_report(input_path=DEFAULT_INPUT):
    """Actual frozen n512 q/count certificate; zero entropy, no source creation."""
    path = Path(input_path)
    data = path.read_bytes()
    source = json.loads(data)
    if source.get("schema") != "IBME/SRGG-INTEGRATED-BRIDGE/1":
        raise ValueError("known integrated bridge schema required")
    params = source["profiles"][0]["parameters"]
    n, d = params["degree"], params["rank"]
    q = params["p"]*params["base"]**params["digits"]
    project = Path(__file__).resolve().parents[4]
    names = ("experiments/research/candidates/srgg/conditional_xof.py",
        "experiments/research/candidates/srgg/seeded_xof.py",
        "experiments/research/candidates/srgg/structured_execution.py",
        "experiments/research/candidates/wang_pw/hashing.py")
    return {"schema": SCHEMA, "input_path": path.as_posix(),
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "source_sha256": {name: hashlib.sha256((project/name).read_bytes()).hexdigest() for name in names},
        "parameters": params,
        "matrix": conditional_certificate(q=q, count=n*d*d),
        "identity": conditional_certificate(q=q, count=n*d),
        "actual_entropy_bytes": 0, "draw_performed": False,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "algorithm": "single-word deterministic accept-lift pushforward",
        "scope": "bounded classical per-point ideal-byte G_h and consistent raw reads",
        "success_conditioned_K_h_implemented": False,
        "whole_adaptive_reduction_implemented": False,
        "production_SHAKE_or_QRO_programmed": False,
        "security_claim": "none", "backend_admitted": False,
        "parameters_are_formal": False, "nist_security_category": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
