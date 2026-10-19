"""A strict but deliberately weak bound on the original Setup backend gap.

Let A be mathematical positivity of the master residual for a raw CBD1
witness, and B_plan successful preparation by the current source-Schur
backend.  The all-zero witness belongs to both sets for every original Table 4
row.  Its exact CBD1 probability is 2^(-2*d*(w*d)*n), so

    Pr_R[A and not B_plan] <= 1 - 2^(-2*d*(w*d)*n).

For the complete first Setup attempt, fix the uniformly drawn 32-byte public
seed to zero as well.  This gives the weaker joint seed/witness bound with an
additional 256 in the exponent.  The executable witness below checks the
actual backend, including public-key construction, rather than assuming that
numerical preparation succeeds.  It assumes independent uniform source bytes,
the current deterministic Python/Sage code, and no external machine faults.

These bounds are almost one.  They do not close the numerical acceptance gap,
the 64-attempt failure budget, or any security claim.  Setup draws its seed
once, and a non-geometry preparation exception terminates the call; raising
the one-attempt success probability to the 64th power would be unsound.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from .paper_parameters import PaperParams
from .paper_profiles import SOURCE_PDF, SOURCE_SHA256, profiles
from .paper_schur_backend import SourceSchurBackend
from .paper_setup_conditioning import residual_threshold_squared


SCHEMA = "IBME/SRGG-PAPER-SETUP-BACKEND-GAP-ZERO-ATOM/1"
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")


class _AllZeroBytes:
    """Replay one particular uniform-byte atom without relying on RNG state."""

    def __init__(self) -> None:
        self.requests: list[int] = []

    def read(self, size: int) -> bytes:
        if type(size) is not int or size < 0:
            raise AssertionError("backend made an invalid random-byte request")
        self.requests.append(size)
        return bytes(size)


def zero_atom_row(profile_name: str, interpretation: str) -> dict:
    if type(profile_name) is not str or profile_name not in tuple(p.name for p in profiles):
        raise ValueError("one original Table 4 profile required")
    if type(interpretation) is not str or interpretation not in INTERPRETATIONS:
        raise ValueError("one explicit paper Gaussian interpretation required")
    params = PaperParams(profile_name, interpretation)
    if (params.degree != 512 or params.base != 31 or params.digits != 2 or
            params.rank not in (2, 3, 4)):
        raise ValueError("original Table 4 shape required")
    threshold = residual_threshold_squared(
        params.master_first_squared, params.master_second_squared,
        params.r_squared, params.base)
    if threshold <= 0:
        raise AssertionError("zero witness does not satisfy the mathematical gate")

    witness_coefficients = 2 * params.rank * (params.digits * params.rank) * params.degree
    rng = _AllZeroBytes()
    backend = SourceSchurBackend(rng=rng, setup_max_attempts=1)
    public, master = backend.setup(params)
    if (rng.requests != [32, witness_coefficients] or backend.setup_attempts != 1 or
            public.seed != bytes(32) or public.params != params or
            master.public_key is not public or
            any(coefficient != 0 for row in master.witness
                for poly in row for coefficient in poly) or
            backend.last_master_certificate is None or
            backend.last_master_certificate.get(
                "fixed_witness_residual_positive_definiteness_certified") is not True):
        raise AssertionError("complete zero-seed/zero-witness Setup atom was not accepted")
    # Force the exact public object codec used in a normal successful Setup.
    if type(public.to_bytes()) is not bytes:
        raise AssertionError("zero atom public key did not serialize")

    return {
        "profile": profile_name,
        "interpretation": interpretation,
        "rank_d": params.rank,
        "degree": params.degree,
        "gadget_digits_w": params.digits,
        "positive_gate_threshold_squared_exact": str(threshold),
        "zero_witness_fourier_operator_norm_squared": 0,
        "complete_zero_seed_zero_witness_setup_accepted": True,
        "first_attempt_entropy_requests_bytes": rng.requests,
        "witness_coefficient_count": witness_coefficients,
        "zero_witness_probability_exact": f"2^-{witness_coefficients}",
        "plan_gap_probability_upper_exact": f"1-2^-{witness_coefficients}",
        "zero_seed_and_witness_probability_exact": f"2^-{witness_coefficients + 256}",
        "full_first_attempt_gap_probability_upper_exact":
            f"1-2^-{witness_coefficients + 256}",
        "numerically_useful_for_64_attempt_abort": False,
        "actual_backend_all_accepted_roots_gap_closed": False,
        "all_positive_roots_uniform_numerical_acceptance_bound": None,
        "useful_64_attempt_abort_upper": None,
        "complete_fault_history_law_upper": None,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


def build_report() -> dict:
    root = Path(__file__).resolve().parents[4]
    if sha256((root / SOURCE_PDF).read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("frozen original paper checksum differs")
    if tuple(p.name for p in profiles) != ("PARAM-I", "PARAM-II", "PARAM-III"):
        raise ValueError("frozen Table 4 profile set/order differs")
    return {
        "schema": SCHEMA,
        "source_pdf": SOURCE_PDF,
        "source_sha256": SOURCE_SHA256,
        "paper_locations": "Algorithm 1 p.7; Table 4 pp.9-10",
        "scope": "strict atom lower bound for deterministic source-Schur Setup acceptance",
        "iid_uniform_source_bytes_assumed": True,
        "external_machine_faults_excluded": True,
        "first_seed_drawn_once_for_all_setup_retries": True,
        "non_geometry_preparation_errors_terminate_setup": True,
        "cannot_raise_first_attempt_failure_bound_to_64th_power": True,
        "all_positive_roots_uniform_numerical_acceptance_bound": None,
        "useful_64_attempt_abort_upper": None,
        "complete_fault_history_law_upper": None,
        "rows": [zero_atom_row(p.name, i) for p in profiles for i in INTERPRETATIONS],
        "known_missing": [
            "uniform numerical acceptance certificate over mathematically positive witnesses",
            "probability of interval-inconclusive, leaf-floor, gain, and preflight failures",
            "useful full-Setup retry, accepted-root distribution, or security bound",
        ],
        "source_parameters_unchanged": True,
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }
