"""Yu finite circuit/parameter evidence, NOT a security admission certificate.

Source: Yu PDF pp.6--7,11--13 (Lemma 7,9, Fig.5); BPR author version
2011-09-29 pp.17--18, Definition 5.1 and Theorem 5.2. See CONDITIONS.md.
All norm bounds below use exact integers/rationals, not floating-point SVD.
Only synthetic, publicly specified algebra fixtures are evaluated/exported;
never pass real private witnesses to these diagnostic functions for publication.
"""

from fractions import Fraction
from hashlib import sha256
from math import isqrt
import json

from . import bpr, evaluation as e
from .circuits import Circuit, MAX_INPUTS, MAX_GATES, MAX_DEPTH, _integer


def _rational(value, name, *, positive=True):
    if type(value) not in (int, Fraction):
        raise ValueError(f"{name} must be an exact int or Fraction")
    value = Fraction(value)
    if (max(abs(value.numerator).bit_length(), value.denominator.bit_length()) > 1024
            or value < 0 or (positive and value == 0)):
        raise ValueError(f"{name} outside exact rational resource bounds")
    return value


def circuit_digest(circuit):
    if type(circuit) is not Circuit:
        raise ValueError("validated Circuit required")
    return sha256(json.dumps([circuit.input_count, circuit.gates, circuit.outputs],
                             separators=(",", ":")).encode()).hexdigest()


def compose_match(circuit, pattern):
    """Append the actual matching circuit without altering NAND topology."""
    if type(circuit) is not Circuit:
        raise ValueError("validated Circuit required")
    pattern = e.bits(pattern, len(circuit.outputs))
    match = e.equality_circuit(pattern)
    wires, gates = list(circuit.outputs), list(circuit.gates)
    for left, right in match.gates:
        gates.append(tuple(wires[w] if w >= 0 else w for w in (left, right)))
        wires.append(circuit.input_count + len(gates) - 1)
    return Circuit(circuit.input_count, tuple(gates), tuple(wires[w] for w in match.outputs))


def circuit_resources(circuit):
    """Measured finite depth/size. Counts are NOT asymptotic NC1 evidence."""
    if type(circuit) is not Circuit:
        raise ValueError("validated Circuit required")
    uses = [0] * (circuit.input_count + len(circuit.gates))
    for pair in circuit.gates:
        for w in pair:
            if w >= 0:
                uses[w] += 1
    for w in circuit.outputs:
        if w >= 0:
            uses[w] += 1
    # Mirror evaluation._release: dead initial inputs / dead gates are retained.
    live = peak = circuit.input_count
    for pair in circuit.gates:
        live += 1
        peak = max(peak, live)
        for w in pair:
            if w >= 0:
                uses[w] -= 1
                if uses[w] == 0:
                    live -= 1
    return dict(input_count=circuit.input_count, output_count=len(circuit.outputs),
                gates=len(circuit.gates), depth=circuit.depth,
                peak_live_wire_slots=peak, final_live_wire_slots=live,
                wire_table_slots=len(uses), sha256=circuit_digest(circuit),
                caps=dict(inputs=MAX_INPUTS, gates=MAX_GATES, depth=MAX_DEPTH),
                nc1_family_verified=False,
                memory_note="wire slots only; NOT Python bytes or process RSS")


def spectral_bounds_squared(rows):
    """L <= s1(R)^2 <= min(||R||F^2, ||R||1*||R||inf), exact integers.

    L is the largest squared row/column norm. No eigensolver rounding or
    hidden big-O constant is used. Input guards precede multiplication.
    """
    if type(rows) not in (tuple, list) or not 1 <= len(rows) <= 192:
        raise ValueError("bounded nonempty matrix required")
    if type(rows[0]) not in (tuple, list) or not 1 <= len(rows[0]) <= 4096:
        raise ValueError("bounded nonempty rows required")
    width = len(rows[0])
    for row in rows:
        if type(row) not in (tuple, list) or len(row) != width:
            raise ValueError("ragged matrix")
        if any(type(x) is not int or abs(x).bit_length() > e.MAX_WITNESS_BITS for x in row):
            raise ValueError("integer witness resource limit")
    row_sq = [sum(x*x for x in row) for row in rows]
    columns = tuple(zip(*rows))
    column_sq = [sum(x*x for x in col) for col in columns]
    frobenius = sum(row_sq)
    product = max(sum(abs(x) for x in row) for row in rows) * max(
        sum(abs(x) for x in col) for col in columns)
    return dict(lower=max(row_sq + column_sq), upper=min(frobenius, product),
                frobenius=frobenius, one_times_infinity=product,
                rows=len(rows), columns=width, arithmetic="exact integers")


def coarse_spectral_squared(circuit, params, initial_coefficient_bound=1):
    """Universal coarse bound, deliberately NOT Yu Lemma 7's sharper bound."""
    if type(circuit) is not Circuit or type(params) is not e.EvalParams:
        raise ValueError("Circuit and EvalParams required")
    _integer(initial_coefficient_bound, "initial coefficient bound", 0, 1 << 1024)
    coefficient = initial_coefficient_bound * (params.w + 1)**circuit.depth
    return params.m * len(circuit.outputs) * params.w * coefficient**2


def finite_width_check(width_squared, gs_squared, dimension, epsilon_bits):
    """Only the existing GPV C1-exec sufficient gate, not full admission.

    gs_squared must be a justified max GS bound for the exact input basis.
    It is basis-dependent if supplied from a secret key: do not export that.
    """
    width_squared = _rational(width_squared, "width_squared")
    gs_squared = _rational(gs_squared, "gs_squared")
    _integer(dimension, "dimension", 1, 192)
    _integer(epsilon_bits, "epsilon_bits", 2, 128)
    factor = (2*dimension*(1 + (1 << epsilon_bits))-1).bit_length()
    required = 4*gs_squared*factor
    return dict(required_squared=str(required), supplied_squared=str(width_squared),
                smoothing_factor=factor, sufficient_gate=width_squared >= required,
                full_sampler_admission=False)


def parameter_conditions(params):
    """Paper mappings, known counterexample, and public-only sufficient checks."""
    from .standalone import Params
    from experiments.research.chkp_genbasis import genbasis_certificate
    if type(params) is not Params:
        raise ValueError("validated raw Yu Params required")
    p, root = params.evaluation, params.root
    root_gs = int(root.gs_squared_bound)
    gamma = finite_width_check(params.gamma_squared, root_gs, p.m+p.w, params.epsilon_bits)
    # RandBasis norm cutoff implies this bound BEFORE optional LLL; it is not
    # a guarantee for a subsequently reduced basis unless separately checked.
    raw_user_gs = params.gamma_squared * (p.m+p.w)
    delta = finite_width_check(params.delta_squared, raw_user_gs, p.m+2*p.w,
                              params.epsilon_bits)
    norm_squared = params.delta_squared * (p.m+2*p.w)
    prf = []
    for name, spec in (("identity", params.identity_prf), ("signing", params.signing_prf)):
        b = spec.params
        # BPR Thm5.2 q >= 2*k*(C*r*sqrt(n))^k*n^omega(1).
        # C=1 and growth=1 are DIAGNOSTIC placeholders, never paper constants.
        rhs_squared = (2*b.input_bits)**2 * b.gaussian_width**(2*b.input_bits) * b.dimension**b.input_bits
        prf.append(dict(name=name, input_bits=b.input_bits, key_bits=b.key_bits,
            dimension=b.dimension, columns=b.columns, output_bits=b.output_bits,
            q=b.modulus, gaussian_width=str(b.gaussian_width),
            c1_growth1_rhs_squared=str(rhs_squared),
            c1_growth1_diagnostic_pass=Fraction(b.modulus**2) >= rhs_squared,
            theorem_status="pending: C, asymptotic family, LWE hardness and key-input NC1 unmapped",
            finite_distribution=spec.certificate()))
    return dict(n=p.n, m=p.m, q=p.q, w=p.w, signature_dimension=p.m+2*p.w,
        identity_bits=params.identity_bits, message_bits=params.message_bits,
        salt_bits=params.salt_bits, gamma_squared=params.gamma_squared,
        delta_squared=params.delta_squared, max_vectors=params.max_vectors,
        epsilon_bits=params.epsilon_bits, postprocess=params.postprocess,
        input_concatenation="checked", gamma_C1_exec=gamma,
        delta_C1_exec_using_raw_randbasis_bound=delta,
        delta_after_LLL="pending actual basis admission" if params.postprocess else "use raw bound",
        ap09=genbasis_certificate(root), prf=prf,
        verifier_norm_squared_limit=norm_squared,
        public_qe1_forgery=dict(norm_squared=p.q**2, accepted_by_equation_for_every_public_matrix=True,
            passes_norm=p.q**2 <= norm_squared,
            status="failed" if p.q**2 <= norm_squared else "this attack excluded only"),
        beta=dict(status="pending", formula="beta >= polynomial(kappa) * delta * sqrt(m+2w)",
                  reason="reduction polynomial/constants and admissible SIS instance not supplied"),
        lemma7=dict(status="pending", paper="s1(R_C) <= O(4^d*m^(3/2))",
                    reason="coarse bound and finitely measured norms do not establish this theorem mapping"),
        overall_formal_status="not_admitted", security_claim="none", backend_admitted=False,
        parameters_are_formal=False)


def algebra_case(spec, x, *, homomorphic=False, evaluation_params=None):
    """Deterministic PUBLIC synthetic fixture; NOT actual Setup or key material."""
    circuit = bpr.compile_key_circuit(spec, x)
    import random
    rng = random.Random(10815)  # Public synthetic vectors, never real key entropy.
    keys = ((0,)*spec.params.key_bits, (1,)*spec.params.key_bits,
            tuple(rng.randrange(2) for _ in range(spec.params.key_bits)))
    report = dict(resources=circuit_resources(circuit), selected_factors=sum(x),
                  semantic_comparisons=0, homomorphism_checks=0, norm_bounds=[])
    p = e.EvalParams(1, 15, 3) if evaluation_params is None else evaluation_params
    if type(p) is not e.EvalParams:
        raise ValueError("EvalParams required")
    a = tuple(tuple(rng.randrange(p.q) for _ in range(p.m)) for _ in range(p.n))
    report["fixture_arithmetic"] = dict(n=p.n, m=p.m, q=p.q, w=p.w)
    witnesses = tuple(tuple(tuple(2*rng.randrange(2)-1 for j in range(p.w))
                            for i in range(p.m)) for h in range(spec.params.key_bits)) if homomorphic else None
    for key in keys:
        direct = bpr.evaluate(spec, key, x)
        if circuit.evaluate(key) != direct:
            raise AssertionError("BPR numeric/circuit semantics mismatch")
        report["semantic_comparisons"] += 1
        if not homomorphic:
            continue
        # One fixed synthetic-key case, both match outcomes; all arithmetic
        # is independent of any sampled master/user trapdoor.
        if key != keys[-1]:
            continue
        encoded = e.encode_inputs(p, a, key, witnesses)
        for target in (direct, tuple(1-b for b in direct)):
            combined = compose_match(circuit, target)
            private = e.eval_private(p, combined, a, key, witnesses)
            public = e.eval_public(p, combined, a, encoded)
            two_stage = e.eval_public(p, e.equality_circuit(target), a,
                                      e.eval_public(p, circuit, a, encoded))
            if (private.output_bits != (int(target == direct),) or public != two_stage
                    or not e.homomorphism_holds(p, a, public, private)):
                raise AssertionError("composed Yu homomorphism mismatch")
            bounds = spectral_bounds_squared(e.join(private.witnesses))
            coarse = coarse_spectral_squared(combined, p)
            if bounds["upper"] > coarse:
                raise AssertionError("coarse norm upper violated")
            report["homomorphism_checks"] += 1
            report["norm_bounds"].append(dict(match=target == direct, **bounds,
                combined_depth=combined.depth, coarse_squared=coarse,
                nonzero_witness=bounds["lower"] > 0,
                lemma7_status="not_established"))
    return report


def run():
    """One redacted evidence batch; failed checks raise, formal gaps stay gaps."""
    from dataclasses import asdict
    from pathlib import Path
    import platform
    from sage.env import SAGE_VERSION
    from .profiles import tiny_profile
    from ibme.ibs.yu.params import YuParams
    from ibme.ibs.yu.codec import input_bits
    byte_config = YuParams()
    byte = byte_config.raw()
    old = tiny_profile()
    rows = []
    for name, spec in (("legacy-identity", old.identity_prf), ("legacy-signing", old.signing_prf),
                       ("byte-identity", byte.identity_prf), ("byte-signing", byte.signing_prf)):
        k = spec.params.input_bits
        patterns = [("raw-zero", (0,)*k), ("raw-one", (1,)*k),
                    ("raw-alternating", tuple(i % 2 for i in range(k)))]
        if name.startswith("byte-"):
            ident = input_bits(b"\xff", byte_config.identity_max_bytes, identity=True)
            x = ident if name == "byte-identity" else ident + input_bits(
                b"\xff", byte_config.message_max_bytes) + (1,)*byte_config.salt_bits
            patterns.append(("valid-byte-ff-max-salt", x))
        for label, x in patterns:
            rows.append(dict(profile=name, input_case=label,
                **algebra_case(spec, x, homomorphic=label in ("raw-alternating", "valid-byte-ff-max-salt"))))
    # q=257 is a public algebra-only diagnostic, NOT a changed IBS profile.
    # The q=3 results can degenerate to zero witnesses; retain rather than hide them.
    extra = algebra_case(byte.identity_prf, input_bits(b"\xff", 1, identity=True),
                         homomorphic=True, evaluation_params=e.EvalParams(1, 15, 257))
    if not all(row["nonzero_witness"] for row in extra["norm_bounds"]):
        raise AssertionError("nonzero auxiliary spectral fixture unexpectedly degenerated")
    rows.append(dict(profile="auxiliary-q257-algebra-only", input_case="valid-byte-ff", **extra))
    repo = Path(__file__).resolve().parents[4]
    files = ["experiments/research/candidates/yu/" + n for n in
             ("qualification.py", "bpr.py", "circuits.py", "evaluation.py", "profiles.py", "standalone.py", "trapdoors.py")]
    files += ["src/ibme/ibs/yu/params.py", "src/ibme/ibs/yu/codec.py", "papers/2026_ibs_ibme_yu.pdf"]
    return dict(schema="yu-circuit-qualification-v1", security_claim="none", backend_admitted=False,
        parameters_are_formal=False, python=platform.python_version(), sage=SAGE_VERSION,
        source_sha256={f: sha256((repo/f).read_bytes()).hexdigest() for f in files},
        input_provenance="deterministic public algebra fixtures, no secret samples or production seeds",
        byte_config=asdict(byte_config), conditions=dict(legacy=parameter_conditions(old),
        byte=parameter_conditions(byte)), cases=rows,
        scope="finite semantics/bounds; not NC1 family, PRF security, full IBS lifecycle or HIBE composition")


def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(cases=len(result["cases"]), formal="not_admitted", security_claim="none")))


if __name__ == "__main__":
    main()
