"""PUBLIC, finite CHKP full-3m/MP12 radix feasibility screen; no key generation.

MP12 (fixed 2011 author version) Theorem 4.1 permits base b>=2 with
k=ceil(log_b(q)) and gadget GS^2<=b^2+1. Algorithm 3 uses Sigma_G+2;
the existing rejection implementation also requires a trace ratio <=1/2.
Both costs are propagated through the ENTIRE parent/leaf/noise/q chain.
The computational root, complete H blocks and Frobenius recipe are retained.
This does not implement, register or admit a higher-radix HIBE backend.
"""

import argparse
from contextlib import contextmanager
from functools import lru_cache
from fractions import Fraction
from hashlib import sha256
import json
from math import isfinite, isqrt
from pathlib import Path
import platform
import sys
from unittest.mock import patch

from .structured_target_screen import ALLOCATION, noise_condition
from ibme.lattice.chkp.joint_parameters import ceil_sqrt, smoothing_factor

SCHEMA = "CHKP-3M-RADIX-PUBLIC-SCREEN/1"
DEFAULT_DIMENSIONS = (512, 1024, 2048, 3072, 4096, 6144, 8192, 12288, 16384)
DEFAULT_RADIX_BITS = tuple(range(1, 33))
DEFAULT_RAM_BUDGET = 8*2**30


def integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(name+" requires an exact bounded integer")
    return value


def width_group(n, q_bits, radix_bits):
    n = integer(n, "screen n", 2, 16384)
    q_bits = integer(q_bits, "modulus bits", 2, 256)
    radix_bits = integer(radix_bits, "power-of-two radix bits", 1, 32)
    base = 1 << radix_bits
    digits = (q_bits+radix_bits-1)//radix_bits
    w, m = n*digits, n*(digits+2)
    root_squared = 4*n+1
    root_bound = 2*n*w*root_squared
    r_squared = 4*smoothing_factor(w, ALLOCATION["epsilon_bits"])
    gadget_gs = base*base+1
    def output(bound):
        return max((gadget_gs+2)*r_squared*(1+bound),
                   2*gadget_gs*r_squared*(w+bound))
    parent_squared = output(root_bound)
    parent_dimension = 2*m-w
    parent_bound = parent_dimension*w*parent_squared
    leaf_squared = output(parent_bound)
    return dict(n=n, q_bits=q_bits, radix_bits=radix_bits, base=base,
        gadget_digits=digits, gadget_GS_squared_upper=gadget_gs, w=w, m=m,
        root_r_squared=root_squared, root_R_bound=root_bound,
        r_squared=r_squared, gadget_width_squared=gadget_gs*r_squared,
        parent_sample_dimension=parent_dimension, parent_width_squared=parent_squared,
        parent_R_bound=parent_bound, leaf_dimension=3*m,
        leaf_width_squared=leaf_squared, q_alpha=isqrt(4*n)+1)


def select_group(n, radix_bits):
    """Find the first proven prime passing this self-consistent finite recipe."""
    from sage.all import next_prime
    for bits in range(2, 257):
        g = width_group(n, bits, radix_bits)
        check = noise_condition(2**bits-1, g["leaf_dimension"],
                                g["leaf_width_squared"], g["q_alpha"])
        if not check["conditional_noise_sufficient"]:
            continue
        rounding = Fraction(check["rounding_error_upper"])
        continuous = Fraction(check["continuous_squared_upper"])
        phase = rounding.__ceil__()+ceil_sqrt(continuous)
        while phase-1 > rounding and (phase-1-rounding)**2 >= continuous:
            phase -= 1
        q = int(next_prime(max(2**(bits-1)+1, 4*phase+3)-1, proof=True))
        if q >= 2**bits:
            continue
        budget = noise_condition(q, g["leaf_dimension"], g["leaf_width_squared"], g["q_alpha"])
        if not budget["conditional_noise_sufficient"]:
            raise ArithmeticError("selected radix prime failed the exact noise condition")
        return dict(g, q=q, q_prime_proved=True, noise=budget)
    raise ValueError("no complete radix group in the declared q<=256-bit domain")


def public_gadget(q, radix_bits):
    """Only the k-square PUBLIC primitive kernel; no n-by-m matrix or samples."""
    from sage.all import ZZ, matrix
    from ibme.lattice.chkp.basis import KernelBasis, ModMatrixReference
    from ibme.lattice.matrix_sampling.prime_gadget import _modulus
    q = _modulus(q)
    radix_bits = integer(radix_bits, "power-of-two radix bits", 1, 32)
    base = 1 << radix_bits
    k = ((q-1).bit_length()+radix_bits-1)//radix_bits
    basis = matrix(ZZ, k, k)
    for j in range(k-1):
        basis[j, j], basis[j+1, j] = base, -1
    for j in range(k):
        basis[j, k-1] = (q >> (j*radix_bits)) & (base-1)
    return KernelBasis(ModMatrixReference((tuple(base**j for j in range(k)),), q), basis)


@lru_cache(maxsize=32)
def finite_options():
    from ibme.lattice.matrix_sampling.scalar import MatrixFiniteOptions
    return MatrixFiniteOptions(tail_bits=192, gaussian_abort_bits=192,
        mass_bits=320, precision_bits=384, max_uniform_trials=256)


@lru_cache(maxsize=64)
def root_scalar(n):
    from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian
    return MatrixFiniteGaussian(4*n+1, 4*n+1, options=finite_options())


def resource_projection(g, ram_budget=DEFAULT_RAM_BUDGET):
    """Byte counts, not allocations, runtime, RSS, or an implemented codec."""
    from ibme.lattice.matrix_sampling.packed import coordinate_bytes, MAGIC
    ram_budget = integer(ram_budget, "resident research budget", 2**20, 2**40)
    n, w, m, d = (g[x] for x in ("n", "w", "m", "parent_sample_dimension"))
    header = len(MAGIC)+41
    parent_width = coordinate_bytes(isqrt(d*g["parent_width_squared"]), True)
    public_width = coordinate_bytes(g["q"]-1, False)
    sizes = dict(root_R=header+2*n*w*coordinate_bytes(root_scalar(n).radius, True),
        public_root=header+n*m*public_width,
        parent_R=header+d*w*parent_width,
        public_parent=header+2*n*m*public_width,
        fixed_leaf=header+256*3*m*coordinate_bytes(isqrt(3*m*g["leaf_width_squared"]), True))
    persistent = sum(sizes.values())
    # These H1/H2 objects are also resident in the CURRENT probe during leaf
    # sampling. Context tuples, caches, Python/native overhead and workspaces
    # are still excluded, so even this sum is only a necessary payload floor.
    probe_floor = persistent+2*(header+n*m*public_width)
    return dict(matrix_component_bytes=sizes, parent_R_coordinate_bytes=parent_width,
        parent_R_entries=d*w, resident_research_budget_bytes=ram_budget,
        persistent_matrix_payload_floor_bytes=persistent,
        current_probe_live_matrix_payload_floor_bytes=probe_floor,
        necessary_payload_fits_research_budget=probe_floor <= ram_budget,
        parent_proposal_scalar_draws_at_least=d*w,
        leaf_proposal_scalar_draws_at_least=256*3*m,
        scalar_products_in_one_dense_parent_R_times_vector=d*w,
        maximum_public_kernel_entries=g["gadget_digits"]**2,
        current_binary_profile_accepts_radix=g["radix_bits"] == 1,
        current_prototype_shape_gate=(g["n"] <= 4096 and 3*m <= 8192 and d*w <= 2**24),
        current_scalar_width_domain=g["leaf_width_squared"] <= 2**192,
        byte_rule="existing fixed public-bound signed/unsigned widths; new outer radix codec is not implemented",
        omitted=["outer metadata", "context/Python integer copies", "native caches", "solve/work buffers", "OS"],
        full_matrices_allocated=0, actual_RSS_bytes=None, actual_seconds=None)


@lru_cache(maxsize=64)
def noise_profile(chi):
    from sage.all import QQ, RealBallField
    from ibme.lattice.chkp.rounded_noise import cdf_integer_interval
    radius = ceil_sqrt(chi*chi*193)
    if radius > 8192:
        raise ValueError("public noise CDF resource limit")
    field, total, previous, units = RealBallField(384), 2**320, 0, 0
    digest = sha256()
    for x in range(-radius, radius):
        lower, upper = cdf_integer_interval(field, QQ(chi), 2*x+1, total)
        cutoff = max(previous, lower)
        if cutoff > upper or upper-lower > 4:
            raise ValueError("public noise CDF interval precision")
        units += upper-cutoff
        digest.update(cutoff.to_bytes(41, "big")); previous = cutoff
    digest.update(total.to_bytes(41, "big"))
    return dict(scaled_width=chi, radius=radius, cdf_interval_error_units=units,
        cdf_sha256=digest.hexdigest(), scalar_TV_upper=str(Fraction(1, 2**192)+Fraction(units, 2**320)),
        modulus_independent=True, actual_noise_samples=0)


def finite_projection(g):
    """Resource-CONDITIONAL finite probability ledger; never security bits."""
    from sage.all import QQ
    from ibme.lattice.chkp.basis import gram_schmidt_squared_lengths
    from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV
    from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian
    from ibme.lattice.matrix_sampling.mp12_bounds import convolution_tv_upper
    if g["leaf_width_squared"] > MatrixFiniteGaussian.MAX_SQUARED_WIDTH:
        return dict(status="outside_current_scalar_width_domain", modeled_lifetime_upper=None,
            target_lifetime_met=False, arithmetic_or_runtime_admitted=False)
    kernel = public_gadget(g["q"], g["radix_bits"])
    actual_gs = max(gram_schmidt_squared_lengths(kernel.basis_rows))
    gadget = MatrixFiniteGPV(kernel,
        g["gadget_width_squared"], epsilon_bits=192, options=finite_options(),
        max_dimension=256, max_arithmetic_content_bytes=32*2**20)
    if actual_gs > g["gadget_GS_squared_upper"]:
        raise ArithmeticError("public radix gadget GS bound failed")
    phases = {}
    for name, d, bound, squared in (
        ("parent", g["parent_sample_dimension"], g["root_R_bound"], g["parent_width_squared"]),
        ("leaf", g["leaf_dimension"], g["parent_R_bound"], g["leaf_width_squared"])):
        scalar = MatrixFiniteGaussian(squared, squared, options=finite_options())
        normalizer = d*scalar.theta <= QQ(1)/2
        smoothing = squared >= 2*g["gadget_GS_squared_upper"]*(bound+1)*smoothing_factor(d, 192)
        trace = Fraction(g["gadget_width_squared"]*(g["w"]+bound), squared)
        if not normalizer or not smoothing or trace > Fraction(1, 2):
            raise ArithmeticError("radix group failed a public sampler condition")
        coupling = min(Fraction(1), 512*(d*Fraction(str(scalar.tv_upper))+
            Fraction(str(scalar.weight_width))+Fraction(1, 2**320))+
            Fraction(3, 4)**512+g["n"]*Fraction(str(gadget.tv_upper))+convolution_tv_upper(192))
        phases[name] = dict(dimension=d, squared_width=str(squared),
            scalar=scalar.certificate(), sample_TV_including_abort_upper=str(coupling),
            ideal_norm_abort_upper=str(Fraction(1, 2**min(d, 256))*Fraction(2**192+1, 2**192-1)),
            target_smoothing_verified=True, proposal_normalizer_verified=True,
            perturbation_trace_ratio=str(trace),
            worst_sample_request_tape_bytes=512*(d*scalar.random_tape_bytes+40)+g["n"]*gadget.random_tape_bytes)
    n, w = g["n"], g["w"]
    root = root_scalar(n)
    noise = noise_profile(g["q_alpha"])
    terms = dict(root_uniform_abort=Fraction(n*n, 2**256),
        root_scalar_coupling=2*n*w*Fraction(str(root.tv_upper)),
        ideal_root_norm_abort=Fraction(1, 2**min(2*n*w, 256)),
        parent_sample_coupling=2*w*Fraction(phases["parent"]["sample_TV_including_abort_upper"]),
        parent_norm_abort=2*w*Fraction(phases["parent"]["ideal_norm_abort_upper"]),
        leaf_sample_coupling=4*256*Fraction(phases["leaf"]["sample_TV_including_abort_upper"]),
        leaf_norm_abort=4*256*Fraction(phases["leaf"]["ideal_norm_abort_upper"]),
        finite_noise_coupling=2**20*(g["leaf_dimension"]+256)*Fraction(noise["scalar_TV_upper"]),
        ciphertext_uniform_abort=Fraction(2**20*n, 2**192),
        ideal_decode_failure_if_norm_good=Fraction(256*2**20, 2**160),
        ideal_RO_uniform_abort=Fraction(n*(g["m"]+256)*2**20, 2**192))
    total = min(Fraction(1), sum(terms.values(), Fraction(0)))
    return dict(status="computed_resource_conditional", modeled_lifetime_upper=str(total),
        probability_dyadic_exponent=(total.denominator//total.numerator).bit_length()-1,
        target_lifetime_met=total <= Fraction(1, 2**128),
        phases=phases, noise=noise, root_scalar=root.certificate(),
        gadget=dict(block_dimension=gadget.dimension, GS_squared_actual_max=str(actual_gs),
            complete_kernel_verified=True, C1_exec_verified=True, tv_upper=str(gadget.tv_upper),
            random_tape_bytes=gadget.random_tape_bytes),
        terms={k:str(min(Fraction(1), v)) for k,v in terms.items()},
        arithmetic_or_runtime_admitted=False,
        excluded=["whole-operation entropy-cap aborts", "precision-solve/resource aborts", "OS failures",
                  "literal rounded-noise hardness", "security reductions and multi-target losses"])


def target_row(n, radix_bits, *, ram_budget=DEFAULT_RAM_BUDGET, with_finite=True):
    g = select_group(n, radix_bits)
    common = dict(n=n, q=g["q"], secret="small-Gaussian")
    return dict(family="mp12-3m-radix-2pow"+str(radix_bits), n=n, q_bits=g["q_bits"],
        complete_group=g, allocation=ALLOCATION,
        root_lwe=dict(common, m=n, squared_width=g["root_r_squared"], independent_columns=g["w"],
            scope="one computational-root column, no multi-target/reduction loss applied"),
        ciphertext_lwe=dict(common, m=2*g["m"], squared_width=g["q_alpha"]**2,
            all_two_H_block_samples_included=True, estimator_distribution_is_literal=False,
            scope="discrete Gaussian comparator for the leading-error normal form; terminal columns omitted"),
        resources=resource_projection(g, ram_budget), estimator_results={},
        finite_projection=(finite_projection(g) if with_finite else dict(status="not_requested", target_lifetime_met=False)),
        actual_full_HIBE_execution=False, root_or_key_generations=0, entropy_reads=0, sampler_calls=0,
        security_claim="none", backend_admitted=False, parameters_are_formal=False)


def decision(row, *, cost_floor=128):
    """Select parameter studies independently of the advisory hardware budget."""
    cost_floor = integer(cost_floor, "comparison-model cost floor", 1, 512)
    keys = {attack+"-"+mode for attack in ("primal_usvp", "dual") for mode in ("classical", "quantum")}
    results, costs = row["estimator_results"], []
    complete = True
    minima = {}
    for role in ("root_lwe", "ciphertext_lwe"):
        r = results.get(role, {})
        if set(r) != keys or any(v.get("status") != "finite_estimate" or
                type(v.get("rop_log2")) not in (int, float) or not isfinite(v["rop_log2"])
                for v in r.values()):
            complete = False; minima[role] = None
        else:
            minima[role] = min(v["rop_log2"] for v in r.values())
            costs += [minima[role]]
    cost_ok = complete and len(costs) == 2 and min(costs) >= cost_floor
    finite_ok = row["finite_projection"].get("target_lifetime_met") is True
    resources_ok = row["resources"]["necessary_payload_fits_research_budget"]
    profile_ok = row["resources"]["current_scalar_width_domain"]
    passed = cost_ok and finite_ok and profile_ok
    if not complete: status = "unresolved_missing_or_failed_model"
    elif not cost_ok: status = "comparison_model_cost_below_threshold"
    elif not profile_ok: status = "needs_scalar_profile_study"
    elif row["finite_projection"].get("status") == "computed_resource_conditional" and not finite_ok:
        status = "conditional_probability_target_not_met"
    elif passed: status = "candidate_for_implementation_study"
    else: status = "unresolved_conditional_probability_profile"
    return dict(status=status,
        comparison_model_floor_log2_rop=cost_floor, all_eight_estimates_finite=complete,
        role_minimum_log2_rop=minima, model_cost_floor_met=cost_ok,
        conditional_probability_target_met=finite_ok, scalar_profile_met=profile_ok,
        necessary_resident_payload_budget_met=resources_ok,
        hardware_budget_is_advisory=True,
        deployment_status=("necessary_payload_within_budget_overhead_unmeasured" if resources_ok
                           else "current_probe_payload_exceeds_advisory_budget"),
        parameter_screen_candidate=passed, implementation_candidate=passed, HIBE_backend_admitted=False,
        runtime_and_peak_RSS_still_unmeasured=True)


def reclassify(raw, *, source_commit, cost_floor=128, ram_budget=DEFAULT_RAM_BUDGET):
    """Replay only decisions on an immutable completed PUBLIC input receipt.

    Mathematical/model provenance stays attached to its original commit. The
    new decision policy has separate provenance; no estimates are recomputed.
    """
    integer(cost_floor, "comparison-model cost floor", 1, 512)
    integer(ram_budget, "advisory resident budget", 2**20, 2**40)
    report = json.loads(raw)
    if (report.get("schema") != SCHEMA or report.get("status") != "completed_public_screen"
            or report.get("estimator", {}).get("completed") is not True
            or "reclassification" in report):
        raise ValueError("an original completed public model screen is required")
    for field in ("key_generations", "sampler_calls", "entropy_reads", "full_matrices_allocated"):
        if report.get(field) != 0:
            raise ValueError("reclassification accepts only public, nonsampling receipts")
    report["reclassification"] = dict(policy="hardware-budget-advisory/1",
        source_commit=source_commit, source_module_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
        input_sha256=sha256(raw).hexdigest(), input_source_commit=report["source_commit"],
        original_cost_floor=report["cost_floor"], original_resident_budget_bytes=report["resident_budget_bytes"],
        original_implementation_candidates=report["implementation_candidates"],
        estimates_reused_without_recomputation=True, geometry_and_finite_certificates_reused=True)
    report.update(cost_floor=cost_floor, resident_budget_bytes=ram_budget,
                  hardware_budget_is_advisory=True)
    for row in report["rows"]:
        resources = row["resources"]
        resources.update(resident_research_budget_bytes=ram_budget,
            necessary_payload_fits_research_budget=resources["current_probe_live_matrix_payload_floor_bytes"] <= ram_budget)
        row["decision"] = decision(row, cost_floor=cost_floor)
    report["implementation_candidates"] = sum(row["decision"]["implementation_candidate"] for row in report["rows"])
    report["parameter_screen_candidates"] = report["implementation_candidates"]
    return report


@contextmanager
def public_work_only():
    """Fail visibly on every project entropy/sample call during the screen."""
    from ibme.core.randomness import SecureRandom
    from ibme.lattice.matrix_sampling.scalar import MatrixFiniteGaussian
    from ibme.lattice.matrix_sampling.gpv import MatrixFiniteGPV
    def forbidden(*args, **kwargs):
        raise AssertionError("public radix screen attempted entropy or sampling")
    with patch.object(SecureRandom, "read", forbidden), patch.object(MatrixFiniteGaussian, "sample", forbidden), patch.object(MatrixFiniteGPV, "sample", forbidden):
        yield


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dimensions", type=int, nargs="+", default=DEFAULT_DIMENSIONS)
    p.add_argument("--radix-bits", type=int, nargs="+", default=DEFAULT_RADIX_BITS)
    p.add_argument("--resident-budget-bytes", type=int, default=DEFAULT_RAM_BUDGET)
    p.add_argument("--cost-floor", type=int, default=128)
    p.add_argument("--estimator-path", type=Path)
    p.add_argument("--geometry-only", action="store_true")
    p.add_argument("--reclassify-from", type=Path,
                   help="reuse a completed public receipt; change only screening/deployment decisions")
    p.add_argument("--source-commit", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.reclassify_from:
        if a.geometry_only or a.estimator_path:
            p.error("reclassification cannot request geometry or new estimator execution")
        report = reclassify(a.reclassify_from.read_bytes(), source_commit=a.source_commit,
                           cost_floor=a.cost_floor, ram_budget=a.resident_budget_bytes)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        with a.output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True)+"\n")
        print(json.dumps(dict(status="completed_decision_reclassification", groups=len(report["rows"]),
            parameter_screen_candidates=report["parameter_screen_candidates"])), flush=True)
        return
    if (len(set(a.dimensions)) != len(a.dimensions) or len(set(a.radix_bits)) != len(a.radix_bits)
            or len(a.dimensions)*len(a.radix_bits) > 512):
        p.error("distinct dimensions/radices and at most 512 public groups required")
    for n in a.dimensions: integer(n, "screen n", 2, 16384)
    for b in a.radix_bits: integer(b, "radix bits", 1, 32)
    integer(a.resident_budget_bytes, "resident budget", 2**20, 2**40)
    integer(a.cost_floor, "comparison-model cost floor", 1, 512)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x", encoding="utf-8") as stream: stream.write('{"status":"started"}\n')
    report = dict(schema=SCHEMA, status="started", source_commit=a.source_commit,
        dimensions=a.dimensions, radix_bits=a.radix_bits, cost_floor=a.cost_floor,
        resident_budget_bytes=a.resident_budget_bytes, hardware_budget_is_advisory=True, rows=[], uses_ROM=True,
        interpretation="finite declared family with Frobenius recipe; not an impossibility result for CHKP/MP12",
        fixed=dict(leaf_blocks=3, full_H_blocks=True, root_prefix_rows="2n", leaf_targets=256,
            identity_bytes=86, seed_bytes=32, root_width_recipe="4n+1", security_proofs_added=0),
        source_paper="MP12 fixed 2011 author version Theorem4.1, Algorithm3 and Algorithm4; CHKP full-3m consumer",
        runtime_defaults_wire_registry_changed=False, private_state_files_opened=0,
        security_claim="none", backend_admitted=False, parameters_are_formal=False,
        environment=dict(python=platform.python_version(), platform=platform.platform()))
    def save(): a.output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    with public_work_only():
        for n in a.dimensions:
            for b in a.radix_bits:
                row = target_row(n, b, ram_budget=a.resident_budget_bytes, with_finite=not a.geometry_only)
                report["rows"].append(row); save()
            print(json.dumps(dict(n=n, complete_public_groups=len(report["rows"]))), flush=True)
        if a.estimator_path:
            from .abb_rom.scaled_parameter_screen import run_estimators
            run_estimators(report, a.estimator_path, checkpoint=save)
        for row in report["rows"]: row["decision"] = decision(row, cost_floor=a.cost_floor)
    report["source_providers"] = {}
    for name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None)
        if path and path.endswith(".py") and name.startswith(("ibme.", "experiments.research.")):
            file = Path(path).resolve()
            report["source_providers"][name] = dict(path=str(file), sha256=sha256(file.read_bytes()).hexdigest())
    report.update(status="completed_public_geometry" if a.geometry_only else "completed_public_screen",
        implementation_candidates=sum(row["decision"]["implementation_candidate"] for row in report["rows"]),
        parameter_screen_candidates=sum(row["decision"]["parameter_screen_candidate"] for row in report["rows"]),
        entropy_reads=0, sampler_calls=0, key_generations=0, full_matrices_allocated=0)
    save()
    print(json.dumps(dict(status=report["status"], groups=len(report["rows"]),
                          implementation_candidates=report["implementation_candidates"])), flush=True)


if __name__ == "__main__": main()
