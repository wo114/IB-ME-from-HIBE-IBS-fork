"""Independent Sage checks and statistics for the finite SRGG gadget kernel."""

import argparse
from collections import Counter
from dataclasses import asdict
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import platform
import sys

from sage.all import QQ, ZZ, PolynomialRing, RealIntervalField, matrix, vector
from sage.version import version as sage_version

from ibme.core.randomness import DeterministicRandom
from experiments.research.gaussian_reference import (
    build_gaussian_table_squared, interval_record,
)
from .algebra import Params, reconstruct_vector
from .audit import PAPER, PAPER_SHA, example, require
from .sampling import GadgetSampler

ROOT = Path(__file__).resolve().parents[4]


def scalar_statistics(table, *, label, samples):
    rng = DeterministicRandom(b"srgg-sampling-statistics:" + label.encode())
    counts = Counter(table.sample(rng=rng) for _ in range(samples))
    exact_mean = sum(QQ(x*m)/table.total_mass for x,m in zip(table.support,table.masses))
    exact_var = sum(QQ(m)/table.total_mass*(x-exact_mean)**2 for x,m in zip(table.support,table.masses))
    mean = QQ(sum(x*n for x,n in counts.items()))/samples
    variance = sum(QQ(n)/samples*(x-mean)**2 for x,n in counts.items())
    empirical_tv = sum(abs(QQ(counts[x])/samples-table.probability(x)) for x in table.support)/2
    require(empirical_tv < QQ(1)/10, "empirical scalar distribution diagnostic failed")
    field = RealIntervalField(96)
    return {
        "samples": samples, "aborts_observed": 0,
        "mean": interval_record(field(mean)), "variance": interval_record(field(variance)),
        "finite_law_mean": interval_record(field(exact_mean)),
        "finite_law_variance": interval_record(field(exact_var)),
        "empirical_tv_to_integer_law": interval_record(field(empirical_tv)),
        "tail_threshold_absolute": 12,
        "tail_count": sum(n for x,n in counts.items() if abs(x) >= 12),
        "finite_law_tail_probability": interval_record(field(sum(
            QQ(m)/table.total_mass for x,m in zip(table.support,table.masses) if abs(x) >= 12))),
        "scope": "diagnostic only; interval certificates budget unobserved tails and aborts",
    }


def finite_box_comparisons(sampler):
    """Independent joint density versus exact finite recurrence on one small box."""
    p, field = sampler.params, RealIntervalField(256)
    support = sorted(set(x for t in sampler.tables for x in t.support))
    require(len(support)**p.digits <= 100000, "independent box budget exceeded")
    rows = []
    for v in range(p.gadget_modulus):
        law = sampler.finite_scalar_distribution(p.p*v)
        require(sum(law.values(), QQ(0)) == 1, "finite gadget probability normalization")
        weights = {}
        for z in product(support, repeat=p.digits):
            if sum(p.base**i*x for i,x in enumerate(z)) % p.gadget_modulus == v:
                weights[z] = (-field.pi()*field(QQ(sum(x*x for x in z))/QQ(sampler.digit_width_squared))).exp()
        require(set(law).issubset(weights), "finite recurrence left its independent gadget fiber")
        # Recompute each point probability without the recurrence enumerator.
        for z, mass in law.items():
            state, independent = v, QQ(1)
            for value in z:
                require((state-value) % p.base == 0, "independent carry relation")
                table = sampler.tables[state % p.base]
                independent *= table.probability(value)
                state = (state-value)//p.base
            require(independent == mass, "independent finite point probability")
        total = sum(weights.values(), field(0))
        distance = sum((abs(field(law.get(z,0))-w/total) for z,w in weights.items()), field(0))/2
        rows.append({
            "quotient_target": v, "box_states": len(support)**p.digits,
            "fiber_states": len(weights), "recurrence_states": len(law),
            "exact_finite_probability_sum": "1", "finite_box_tv": interval_record(distance),
            "scope": "spherical density conditioned on finite box; not an infinite-tail or full-IBS test",
        })
    return rows


def sampled_extraction(p, *, repetitions):
    sampler = GadgetSampler(p, 36)
    public, r, target, perturbation = example(p, b"sampled-extraction-component")
    source = DeterministicRandom(b"srgg-independent-gadget:" + bytes((p.degree,p.rank,p.digits)))
    polynomials = PolynomialRing(ZZ, "X")
    x = polynomials.gen()
    ring = polynomials.quotient(x**p.degree+1, "a")
    def rp(values): return ring(polynomials(list(values)))
    def rv(values): return vector(ring, [rp(value) for value in values])
    a = matrix(ring, [[rp(value) for value in row] for row in public.a])
    def zero_mod(values):
        return all(all(int(c) % p.modulus == 0 for c in value.lift().list()) for value in values)
    error_counts, scalar_draws = Counter(), 0
    for u in range(p.modulus):
        for _ in range(3):
            z, error = sampler.sample_scalar(u, rng=source)
            require((p.p*sum(p.base**i*value for i,value in enumerate(z))-u+error) % p.modulus == 0,
                    "independent sampled scalar syndrome")
            error_counts[error] += 1
            scalar_draws += p.digits
    require(len(set(error_counts.values())) == 1 and len(error_counts) == p.p,
            "canonical uniform target error counting")
    from .sampling import extract_with_gadget
    for _ in range(repetitions):
        trace = extract_with_gadget(public, r, target, perturbation, sampler, rng=source)
        restored = reconstruct_vector(public, target, trace.tail)
        require(zero_mod(a*rv(trace.raw_vector)-rv(target)+rv(trace.error)),
                "independent sampled approximate extraction")
        require(zero_mod(a*rv(restored)-rv(target)), "independent sampled HNF reconstruction")
        scalar_draws += p.rank*p.degree*p.digits
    return {
        "parameters": asdict(p), "Q": p.modulus, "digit_width_squared": "36",
        "SampleZ_recipe_width_squared": "4", "exhaustive_scalar_targets": p.modulus,
        "samples_per_scalar_target": 3, "extraction_repetitions": repetitions,
        "scalar_draws": scalar_draws, "independent_module_relations_passed": repetitions,
        "independent_HNF_relations_passed": repetitions,
        "canonical_error_counts": dict(sorted(error_counts.items())), "aborts_observed": 0,
        "module_certificate": sampler.certificate(blocks=p.rank*p.degree),
        "perturbation_source": "caller-provided algebra fixture, not Gaussian",
        "key_distribution_claim": "none",
    }


def audit(*, samples=4096, repetitions=128):
    require(sha256((ROOT/PAPER).read_bytes()).hexdigest() == PAPER_SHA, "source PDF version differs")
    profiles = {}
    for name, width in (("algorithm6-literal-r2-4",4), ("table3-recipe-r2-4",36), ("table3-recipe-r2-16",144)):
        sampler = GadgetSampler(Params(), width)
        profiles[name] = {
            "certificate": sampler.certificate(),
            "scalar_statistics": [scalar_statistics(t,label=name+":"+str(t.residue),samples=samples) for t in sampler.tables],
            "finite_box_comparisons": finite_box_comparisons(sampler),
        }
    mapping = []
    recipe = GadgetSampler(Params(), 36)
    literal = GadgetSampler(Params(), 4)
    for residue, table in enumerate(recipe.tables):
        scalar = build_gaussian_table_squared(4, center=QQ(-residue)/3)
        shifted = {3*x+residue: QQ(m)/scalar.total_mass for x,m in zip(scalar.support,scalar.masses)}
        difference = sum(abs(table.probability(x)-shifted.get(x,QQ(0))) for x in set(table.support)|set(shifted))/2
        require(difference <= table.tv_upper+scalar.tv_upper, "affine scalar width mapping")
        literal_difference = sum(abs(table.probability(x)-literal.tables[residue].probability(x))
                                 for x in set(table.support)|set(literal.tables[residue].support))/2
        mapping.append({"residue":residue,"affine_SampleZ_finite_law_tv":str(difference),
                        "combined_scalar_error_upper":str(table.tv_upper+scalar.tv_upper),
                        "recipe_vs_literal_width_finite_law_tv":interval_record(RealIntervalField(96)(literal_difference))})
    paths = (
        "experiments/research/candidates/srgg/sampling.py",
        "experiments/research/candidates/srgg/sampling_audit.py",
        "experiments/research/candidates/srgg/algebra.py",
        "experiments/research/candidates/srgg/audit.py",
        "experiments/research/candidates/srgg/geometry.py",
        "experiments/research/gaussian_reference.py",
        "src/ibme/core/randomness.py",
    )
    extraction = [sampled_extraction(p,repetitions=repetitions) for p in (
        Params(degree=2,digits=1), Params(), Params(rank=2,p=7))]
    return {
        "security_claim":"none","backend_admitted":False,"teaching_parameters":True,
        "gaussian_gadget_kernel_implemented":True,"full_perturbation_sampler_implemented":False,
        "full_IBS_implemented":False,"XOF_identity_hash_sign_verify_implemented":False,
        "base_commit":"ae572cd","paper_source":PAPER,"paper_sha256":PAPER_SHA,
        "source_mapping":"SRGG Table3/PDF6 and SampleZ affine recipe; Algorithms5/6/PDF7; Algorithms2/7 equations",
        "primary_online_source":"https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/ise2/6684889",
        "environment":{"python":sys.version,"sage":sage_version,"platform":platform.platform(),"processor":platform.processor()},
        "identity_message_lengths":"not applicable: public targets only; no instantiated identity or message hash",
        "ROM":"no ROM/QROM claim for this sampling component",
        "randomness":"SecureRandom default; named deterministic streams for reproducible diagnostics",
        "density_convention":"exp(-pi*(x-c)^2/s^2); s is density width, not physical standard deviation",
        "width_recipe_mapping_verified":True,"paper_algorithm6_notation_discrepancy_resolved":False,
        "signature_zeta_width_mapping_resolved":False,
        "statistics_scalar_samples":9*samples,"finite_joint_laws_checked":27,
        "profiles":profiles,"affine_width_mapping":mapping,"sampled_extraction":extraction,
        "source_sha256_lf":{path:sha256((ROOT/path).read_bytes().replace(b"\r\n",b"\n")).hexdigest() for path in paths},
        "limitations":[
            "Output width is explicit; following the sigma=b*r recipe is an interpretation, not an author erratum.",
            "The total gadget-fiber bound includes coset-normalizer bias, scalar tails, quantization and rejection aborts.",
            "Exact finite laws omit abort events, and are not the actual law conditional on surviving every draw.",
            "Finite-box joint comparisons and empirical moments do not prove infinite distribution or cryptographic security.",
            "Perturbations in extraction are supplied algebra fixtures; reconstructed keys have no distribution/norm admission.",
            "No correlated SampleP/SampleF, continuous Gaussian, XOF, actual hash, signing, verification or side-channel guarantee.",
            "Strong-signature conditions and q/Q/gamma mapping, signature zeta scale and old education authentication gaps remain open.",
            "No master/user vectors or private shapes are exported in this report.",
        ],
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    result=audit()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({name:result[name] for name in (
        "statistics_scalar_samples","finite_joint_laws_checked","security_claim")}))


if __name__ == "__main__": main()
