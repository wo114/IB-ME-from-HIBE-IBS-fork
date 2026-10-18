"""A0: same-input matrix-HIBE projections and separate LWE attack roles.

This tool never constructs a high-dimensional matrix, key, or runtime Params.
It keeps the existing implementation limits. Gaussian *scalar certificates*
are evaluated by the existing engine; no sample or random byte is requested.
Projected profiles and Gaussian attack comparators are not secure presets.
"""

import argparse
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path
import platform
import sys
import time

from ibme.lattice.chkp.joint_parameters import smoothing_factor


Q61 = 2**61 - 1
Q104 = 10141204801825835211973625643089
Q160 = 730750818665451459101842416358141509827966271787
BITS, ERROR_BITS, SEED_BITS, CALLS = 128, 128, 256, 2**20


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} requires an exact integer in {low}..{high}")
    return value


def _ceil_sqrt(value):
    value = Fraction(value)
    root = isqrt(value.numerator // value.denominator)
    return root + int(root * root < value)


def strict_noise_width(n):
    """Smallest integer chi with chi > 2 sqrt(n), including square n."""
    return isqrt(4 * _integer(n, "n", 1, 16384)) + 1


def conditional_noise(q, dimension, squared_width, chi, *, abb=False,
                      error_bits=ERROR_BITS):
    """Conditional rounded-continuous-noise bound, without runtime caps.

    CHKP uses the exact conservative integer radius from joint_parameters.
    ABB retains its separate q/5 bound and integer decoder threshold.
    This assumes ||d||^2 <= dimension*squared_width; no norm event is proved.
    """
    _integer(q, "q", 23, 2**256 - 1)
    _integer(dimension, "dimension", 1, 2**26)
    _integer(squared_width, "squared_width", 1, 2**1024)
    _integer(chi, "chi", 1, q - 1)
    _integer(error_bits, "error_bits", 8, 4096)
    norm = dimension * squared_width
    rounding = Fraction(1 + _ceil_sqrt(dimension * norm), 2)
    if abb:
        continuous = chi * _ceil_sqrt(1 + norm) * _ceil_sqrt(error_bits + 1)
        radius = Fraction(q, 5)
        sufficient = rounding + continuous < radius
        continuous_squared = continuous**2
    else:
        radius = Fraction((q // 2 - 1) // 2)
        continuous_squared = chi**2 * (norm + 1) * (error_bits + 1)
        sufficient = radius > rounding and continuous_squared <= (radius - rounding)**2
    return dict(conditional_noise_sufficient=sufficient,
        assumed_preimage_norm_squared=str(norm), rounding_error_upper=str(rounding),
        continuous_squared_upper=str(continuous_squared), phase_radius=str(radius),
        scaled_continuous_width=chi, alpha=str(Fraction(chi, q)),
        error_bits=error_bits, bits_per_seed=SEED_BITS, encapsulations=CALLS,
        conditional_ideal_noise_lifetime_upper=(str(Fraction(SEED_BITS * CALLS, 2**error_bits))
                                               if sufficient else None),
        preimage_norm_event_proved=False, total_sampler_TV_or_failure_upper=None)


def maximum_abb_scaled_width(q, dimension, squared_width, *, error_bits=ERROR_BITS):
    """Largest integer q*alpha satisfying the public conditional q/5 bound.

    This is only the honest-decryption inequality. It neither supplies the
    strict Regev lower bound nor certifies a finite sampler or LWE hardness.
    """
    _integer(q, "q", 23, 2**256 - 1)
    _integer(dimension, "dimension", 1, 2**26)
    _integer(squared_width, "squared_width", 1, 2**1024)
    _integer(error_bits, "error_bits", 8, 4096)
    norm = dimension * squared_width
    rounding = Fraction(1 + _ceil_sqrt(dimension * norm), 2)
    coefficient = _ceil_sqrt(1 + norm) * _ceil_sqrt(error_bits + 1)
    available = Fraction(q, 5) - rounding
    if available <= 0:
        return 0
    # width*coefficient < available; subtract one numerator unit for the
    # strict inequality instead of relying on floating-point nextafter.
    return max(0, (available.numerator - 1) // (available.denominator * coefficient))


def _wire_and_gates(family, n, q, root, parent, leaf, *, prefix=None):
    """Lower bounds may EXCLUDE a codec budget; they cannot prove it fits."""
    coefficient_bytes = ((q - 1).bit_length() + 7) // 8
    abb = family == "abb-rom"
    lower = dict(public_root_residues=n * root * coefficient_bytes,
        root_full_basis=6 * root**2, parent_stored_full_basis=6 * parent**2,
        leaf_material=(6 * leaf**2 if abb else 6 * leaf * SEED_BITS),
        capsule_coefficients=(SEED_BITS * (leaf + 1) if abb else leaf + SEED_BITS) * coefficient_bytes)
    if prefix is not None:
        # Existing JSON intermediary contains quoted signed decimal integers.
        lower["compact_parent_intermediate"] = 4 * prefix * n * (q - 1).bit_length()
    capsule = 4 * 2**20
    component = 16 * 2**20
    dimension_cap = 1536 if abb else 512
    gates = dict(root_n_within_current_cap=n <= 64,
        root_dimension_within_current_cap=root <= (1536 if abb else 1024),
        parent_dimension_within_current_cap=parent <= dimension_cap,
        leaf_dimension_within_current_cap=leaf <= (1536 if abb else 256),
        modulus_within_current_cap=q <= (2**256 - 1 if abb else Q61),
        root_wire_not_excluded_by_lower_bound=lower["root_full_basis"] <= (128 * 2**20 if abb else 64 * 2**20),
        parent_wire_not_excluded_by_lower_bound=lower["parent_stored_full_basis"] <= (128 * 2**20 if abb else component),
        leaf_wire_not_excluded_by_lower_bound=lower["leaf_material"] <= (128 * 2**20 if abb else component),
        Hybrid_capsule_not_excluded_by_lower_bound=lower["capsule_coefficients"] <= capsule,
        Hybrid_parent_not_excluded_by_lower_bound=lower["parent_stored_full_basis"] <= component)
    if family == "chkp-rom":
        # This public backend explicitly selects ExtendedGPV at 512, not its
        # compatibility constructor's default 256.
        gates["leaf_dimension_within_current_cap"] = leaf <= 512
        gates["root_dimension_within_current_cap"] = root <= 512
        gates["root_wire_not_excluded_by_lower_bound"] = lower["root_full_basis"] <= component
    if prefix is not None:
        gates["DelTrap_prefix_within_current_cap"] = prefix <= 256
        gates["parent_dimension_within_current_cap"] = parent <= 1024
    return lower, gates


def _ciphertext_role(n, q, dimension, chi, *, abb):
    return dict(n=n, q=q, m=dimension, secret="uniform-mod-q",
        squared_width=chi**2, distribution="rounded-continuous-Gaussian",
        estimator_distribution="DiscreteGaussian(sigma=chi/sqrt(2*pi)) comparator ONLY",
        attack_goal="recover fresh encryption vector from public preamble, then decode message",
        independently_encrypted_seed_bits=SEED_BITS if abb else None,
        fresh_vector_per_bit=abb,
        known_plaintext_samples_per_vector=dimension + (1 if abb else SEED_BITS),
        samples_from_different_fresh_vectors_pooled=False,
        literal_noise_distribution_estimate=False, multi_target_or_reduction_loss_applied=False)


def mp12_projection(n, q=Q61):
    """Computational [I|Ahat] root, DelTrap parent, fixed256 CHKP leaf."""
    _integer(n, "n", 2, 16384)
    _integer(q, "q", 23, Q61)
    k, chi = (q - 1).bit_length(), strict_noise_width(n)
    w, mbar = n * k, 2 * n
    m, prefix = mbar + w, 2 * mbar + w
    root_gs = 10 * (1 + mbar * w * chi**2)
    s1 = 4 * root_gs * smoothing_factor(2 * m, BITS)
    parent_gs = 10 * (1 + w * prefix * s1)
    s2 = 4 * parent_gs * smoothing_factor(3 * m, BITS)
    lower, gates = _wire_and_gates("mp12-chkp", n, q, m, 2 * m, 3 * m, prefix=prefix)
    gates["leaf_unit_scalar_width_within_cap"] = s2 <= 2**88
    gates["byte_backend_current_noise_recipe"] = chi == 4
    noise = conditional_noise(q, 3 * m, s2, chi)
    noise["strict_Regev_noise_prerequisite"] = chi**2 > 4 * n
    return dict(family="mp12-chkp", root_algorithm="MP12 computational [I|Ahat] GenTrap",
        parent_algorithm="MP12 Algorithm4 DelTrap", leaf_algorithm="CHKP fixed256 SampleD",
        n=n, q=q, q_bits=k, root_dimension=m, parent_dimension=2*m, leaf_dimension=3*m,
        root_gs_squared_bound=str(root_gs), parent_width_squared=str(s1),
        parent_gs_squared_bound=str(parent_gs), leaf_width_squared=str(s2),
        root_R_width_squared=chi**2, root_statistical_uniformity_upper=None,
        root_lwe=dict(n=n, q=q, m=n, secret="small-Gaussian", squared_width=chi**2,
            distribution="ideal D_Z,s in both secret and error; finite PMF coupling separate",
            independent_columns=w, target_columns_for_alternative_trapdoor=w,
            attack_goal="one root column search/decision; not full trapdoor recovery",
            multi_target_or_reduction_loss_applied=False),
        ciphertext_lwe=_ciphertext_role(n, q, 3*m, chi, abb=False),
        noise=noise, minimum_wire_bytes=lower, current_execution_gates=gates)


def _minimum_entropy_columns(n, q, w, mass=Fraction(319, 10)):
    # The existing finite D_Z,32 scalar certifies acceptance_mass_lower >31.9.
    # Use an exact integer binary search, with the old root's public LHL rule.
    target = w**2 * q**n * 2**(2*BITS)
    low, high = 0, 1
    while mass**high < target:
        high *= 2
    while low + 1 < high:
        middle = (low + high) // 2
        if mass**middle >= target:
            high = middle
        else:
            low = middle
    return high


def chkp_projection(n, q=Q61):
    """Statistical MP12/full-basis root, original CHKP RandBasis parent."""
    from ibme.lattice.matrix_sampling.chkp_profiles import CHKPFiniteGaussian
    _integer(n, "n", 2, 16384)
    _integer(q, "q", 344, Q61)
    scalar = CHKPFiniteGaussian(1024, 1024)
    mass = scalar.acceptance_mass_lower
    if Fraction(int(mass.numerator()), int(mass.denominator())) <= Fraction(319, 10):
        raise ValueError("fixed root mass does not certify the projection floor")
    k, chi = (q-1).bit_length(), strict_noise_width(n)
    w = n*k
    mbar = _minimum_entropy_columns(n, q, w)
    m = mbar+w
    root_gs = 10*(1+mbar*w*scalar.radius**2)
    s1 = 4*root_gs*smoothing_factor(2*m, BITS)
    parent_gs = s1*(2*m)
    s2 = 4*parent_gs*smoothing_factor(3*m, BITS)
    lower, gates = _wire_and_gates("chkp-rom", n, q, m, 2*m, 3*m)
    gates["leaf_unit_scalar_width_within_cap"] = s2 <= 2**88
    noise = conditional_noise(q, 3*m, s2, chi)
    noise["strict_Regev_noise_prerequisite"] = chi**2 > 4*n
    return dict(family="chkp-rom", root_algorithm="MP12 statistical GenTrap/full-basis",
        parent_algorithm="CHKP ExtBasis/RandBasis/ToBasis", leaf_algorithm="CHKP fixed256 SampleD",
        n=n, q=q, q_bits=k, m_bar=mbar, root_dimension=m, parent_dimension=2*m, leaf_dimension=3*m,
        root_R_width_squared=1024, root_R_support_radius=scalar.radius,
        root_entropy_mass_floor="319/10", root_regularity_target_bits=BITS,
        root_gs_squared_bound=str(root_gs), parent_width_squared=str(s1),
        parent_gs_squared_bound=str(parent_gs), leaf_width_squared=str(s2),
        root_statistical_uniformity_upper=str(Fraction(1, 2**BITS)),
        root_uniformity_scope="ideal LHL term only; finite sampler/rank/abort contributions separate",
        root_lwe=None, root_lwe_absence_reason="statistical root; not the computational [I|Ahat] root",
        ciphertext_lwe=_ciphertext_role(n, q, 3*m, chi, abb=False),
        noise=noise, minimum_wire_bytes=lower, current_execution_gates=gates)


def abb_projection(n, q, *, noise_width=None):
    """AP09 conservative 8*n*ceil(log2 q) family, with no quality conditioning."""
    from ibme.lattice.matrix_sampling import MatrixFiniteGaussian
    _integer(n, "n", 1, 16384)
    _integer(q, "q", 23, 2**256-1)
    k, minimum_chi = (q-1).bit_length(), strict_noise_width(n)
    chi = minimum_chi if noise_width is None else _integer(noise_width, "noise_width", 1, q - 1)
    d = max(2*n*k, n*k+2*(BITS+2)+32)
    while True:
        m2 = 2*n*k+2*d
        # q^n <= 2^(n*k), m2 <= 2^ceil(log2 m2); upward dyadic LHL.
        lhl_exponent = (m2-1).bit_length() + (n*k-d+1)//2
        if lhl_exponent <= -(BITS+2):
            break
        d += 1
    m = d+m2
    hadamard = 1 << ((2*d).bit_length()-1)
    scale = _ceil_sqrt(Fraction(4*d*m2, hadamard))
    root_gs = max((scale+3)**2*d+5, 8*n*k+2)
    factor = smoothing_factor(m, BITS)
    r_squared = 4*root_gs*factor
    scalar = MatrixFiniteGaussian(r_squared, r_squared)
    operator = m**2*scalar.radius**2
    s1 = 4*root_gs*operator*factor
    parent_gs = s1*m
    s2 = 4*parent_gs*operator*factor
    tau = 4*s2*m*factor
    lower, gates = _wire_and_gates("abb-rom", n, q, m, m, m)
    # Necessary obstruction from product(GS^2)=q^(2n), without enormous powers.
    # m>=8*n*k gives min(GS^2)<=q^(2n/m)<=2^(1/4)<2.
    gates["leaf_scalar_not_excluded_by_determinant_bound"] = s2 <= 2**193
    gates["decrypt_scalar_not_excluded_by_determinant_bound"] = tau <= 2**193
    gates["byte_backend_current_noise_recipe"] = chi == 4
    noise = conditional_noise(q, m, tau, chi, abb=True)
    noise["strict_Regev_noise_prerequisite"] = chi**2 > 4*n
    noise["minimum_strict_Regev_scaled_width"] = minimum_chi
    noise["maximum_conditional_correctness_scaled_width"] = maximum_abb_scaled_width(q, m, tau)
    noise["scaled_width_selection"] = "strict-minimum" if noise_width is None else "explicit"
    return dict(family="abb-rom", root_algorithm="AP09 Algorithm1/section3.3",
        parent_algorithm="ABB SampleR/BasisDel/RandBasis", leaf_algorithm="ABB BasisDel/fresh SamplePre per bit",
        n=n, q=q, q_bits=k, random_rows=d, m1=d, m2=m2, hadamard_scale=scale,
        root_dimension=m, parent_dimension=m, leaf_dimension=m,
        root_gs_squared_bound=str(root_gs), matrix_R_width_squared=str(r_squared),
        matrix_R_support_radius=scalar.radius, transformation_operator_squared_bound=str(operator),
        parent_width_squared=str(s1), parent_gs_squared_bound=str(parent_gs),
        leaf_width_squared=str(s2), decrypt_width_squared=str(tau),
        normalized_quality_conditioning_used=False,
        paper_strict_setup_dimension_sufficient=m>6*n*k,
        root_LHL_dyadic_upper=f"2^{lhl_exponent}", root_regularity_target_bits=BITS,
        root_uniformity_scope="LHL term only; rank/uniform-byte abort separate",
        root_lwe=None, root_lwe_absence_reason="AP09 statistical root; no computational MP12 root LWE role",
        ciphertext_lwe=_ciphertext_role(n, q, m, chi, abb=True),
        noise=noise, minimum_wire_bytes=lower, current_execution_gates=gates)


def build_report(dimensions=(128, 512, 2048, 8192, 16384)):
    from sage.all import ZZ
    from sage.version import version as sage_version
    if not dimensions or len(set(dimensions)) != len(dimensions):
        raise ValueError("distinct nonempty projection dimensions required")
    for n in dimensions:
        _integer(n, "n", 2, 16384)
    for q in (Q61, Q104, Q160):
        if not ZZ(q).is_prime(proof=True):
            raise ValueError("projection modulus is not a proven prime")
    rows = []
    for n in dimensions:
        rows.extend((mp12_projection(n), chkp_projection(n)))
        rows.extend(abb_projection(n, q) for q in (Q61, Q104, Q160))
    for row in rows:
        row.update(projection_only=True, root_or_key_generated=False,
            private_entropy_bytes=0, security_claim="none", backend_admitted=False,
            parameters_are_formal=False, estimator_results={})
    source_root = Path(__file__).resolve().parents[3]
    sources = ["experiments/research/abb_rom/scaled_parameter_screen.py",
        "src/ibme/hibe/abb_rom/params.py", "src/ibme/hibe/abb_rom/trapgen.py",
        "src/ibme/lattice/matrix_sampling/scalar.py",
        "src/ibme/lattice/matrix_sampling/chkp_profiles.py",
        "experiments/research/first_suite/hibe_reference.py",
        "experiments/research/first_suite/computational_root.py"]
    return dict(schema="A/MATRIX-HIBE-SCALED-SCREEN/1", rows=rows,
        common_inputs=dict(identity_bytes_per_level=86, seed_bytes=32,
            epsilon_bits=BITS, noise_error_bits=ERROR_BITS, encapsulations=CALLS,
            noise_width_rule="smallest integer chi > 2*sqrt(n)",
            finite_tail_bits=128, finite_mass_bits=256, finite_precision_bits=320),
        environment=dict(python=sys.version.split()[0], sage=sage_version, platform=platform.platform()),
        source_sha256={p: hashlib.sha256((source_root/p).read_bytes()).hexdigest() for p in sources},
        size_scope="codec coefficient/entry LOWER bounds; no headers, nested caches, workspace or RSS",
        projected_process_peak_RSS=None, projected_stage_seconds=None,
        root_or_key_generations=0, private_entropy_bytes=0,
        secure_candidate_selected=False, security_claim="none", backend_admitted=False,
        parameters_are_formal=False,
        unresolved=["literal finite/rounded-noise attack estimates", "all relevant attack families",
            "query/multi-target/256-bit reduction losses", "formal HIBE/ROM mapping",
            "full sampler TV and aborts", "complete-basis runtime and workspace"])


def run_estimators(report, estimator_path, *, checkpoint=None):
    from experiments.research.luo_parameter_screen import verify_estimator_checkout
    root, revision = verify_estimator_checkout(Path(estimator_path))
    sys.path.insert(0, str(root))
    import estimator
    from estimator import LWE, ND
    from estimator.reduction import ADPS16
    from sage.all import RR, log, oo
    if not Path(estimator.__file__).resolve().is_relative_to(root):
        raise ValueError("foreign estimator import")
    report["estimator"] = dict(repository="https://github.com/malb/lattice-estimator", commit=revision,
        models="ADPS16 classical/quantum Core-SVP; primal-uSVP LGSA and plain dual",
        attack_families=["primal_usvp", "dual"], excluded_attacks=["BDD/hybrid", "BKW", "algebraic"],
        scope="Gaussian comparators; estimated costs are not proven security bits", completed=False)
    for row in report["rows"]:
        for role in ("root_lwe", "ciphertext_lwe"):
            spec = row[role]
            if spec is None:
                continue
            sigma = RR(spec["squared_width"]).sqrt() / (2*RR.pi()).sqrt()
            problem = LWE.Parameters(n=spec["n"], q=spec["q"], m=spec["m"],
                Xs=(ND.UniformMod(spec["q"]) if spec["secret"] == "uniform-mod-q" else ND.DiscreteGaussian(sigma)),
                Xe=ND.DiscreteGaussian(sigma), tag=f"{row['family']}-{role}-n{row['n']}-q{row['q_bits']}")
            result = row["estimator_results"].setdefault(role, {})
            for mode in ("classical", "quantum"):
                for attack in ("primal_usvp", "dual"):
                    start = time.monotonic()
                    key = f"{attack}-{mode}"
                    try:
                        kw = dict(red_cost_model=ADPS16(mode=mode))
                        if attack == "primal_usvp":
                            kw["red_shape_model"] = "lgsa"
                        cost = getattr(LWE, attack)(problem, **kw)
                        finite = cost["rop"] != oo
                        result[key] = dict(status="finite_estimate" if finite else "no_finite_estimate",
                            rop_log2=float(log(cost["rop"], 2)) if finite else None,
                            cost_fields={k: str(v) for k, v in cost.items() if k != "problem"},
                            goal="heuristic_secret_search" if attack == "primal_usvp" else "decisional_distinguisher")
                    except Exception as exc:
                        # An unsupported/failed estimate is unknown, never a large cost.
                        result[key] = dict(status="error", rop_log2=None,
                            exception_type=type(exc).__name__, error=str(exc))
                    result[key]["elapsed_seconds"] = time.monotonic()-start
                    if checkpoint is not None:
                        checkpoint()
            print(json.dumps(dict(family=row["family"], n=row["n"], q_bits=row["q_bits"], role=role,
                costs={key: value["rop_log2"] for key, value in result.items()})), flush=True)
    verify_estimator_checkout(root)
    report["estimator"]["completed"] = True
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--estimator-path", type=Path)
    parser.add_argument("--dimensions", type=int, nargs="+", default=[128, 512, 2048, 8192, 16384])
    args = parser.parse_args(argv)
    # Reserve exclusively before any costly public calculation; never overwrite receipts.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write('{"status":"public-screen-started"}\n')
    report = build_report(tuple(args.dimensions))
    def save():
        args.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    save()
    if args.estimator_path:
        run_estimators(report, args.estimator_path, checkpoint=save)
    save()
    print(f"{len(report['rows'])} public projections; zero key generations; no security admission")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
