"""Independent Sage checking of the NAND homomorphism component.

Only public matrices, synthetic truth values, dimensions, norms and digests
are exported. Input/output witnesses and random streams stay in memory.
"""

import argparse
from dataclasses import asdict
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import platform
import sys

from ibme.core.randomness import DeterministicRandom
from .homomorphic_reference import (
    Params, NandCircuit, encode_inputs, eval_public, eval_private, gadget_inverse,
    homomorphism_holds, matching_circuit,
)

ROOT = Path(__file__).resolve().parents[4]
PAPER = "papers/2026_ibs_ibme_yu.pdf"
PAPER_SHA = "f10d8672d952d9923a00c883a7d65feb36a15fb67fbef1c52ee64254f5301948"


def require(condition, label):
    if not condition: raise RuntimeError(label)


def inputs(p, count, label):
    # Explicit deterministic teaching streams; no real user/secret key exists.
    source = DeterministicRandom(b"yu-nand-component:" + label)
    def below(bound):
        width = max(1, ((bound - 1).bit_length() + 7) // 8)
        ceiling = 2**(8 * width)
        limit = ceiling - ceiling % bound
        for _ in range(128):
            value = int.from_bytes(source.read(width), "big")
            if value < limit: return value % bound
        raise RuntimeError("teaching random integer budget exhausted")
    a = tuple(tuple(below(p.q) for _ in range(p.m)) for _ in range(p.n))
    r = tuple(tuple(tuple(1 if below(2) else -1 for _ in range(p.w)) for _ in range(p.m)) for _ in range(count))
    return a, r


def sage_check(p, circuit, values, a, encoded, public, private):
    from sage.all import ZZ, matrix
    g = matrix(ZZ, p.n, p.w, lambda i, j: (2**(j % p.digit_bits)) % p.q if j // p.digit_bits == i else 0)
    awires = [matrix(ZZ, block) for block in encoded]
    truth = list(values)
    inverse_count = 0
    for left, right in circuit.gates:
        # Rebuild all digits independently of the production tuple routine.
        raw = awires[right]
        bitrows = [[int(raw[i, j]) // 2**b % 2 for j in range(p.w)]
                   for i in range(p.n) for b in range(p.digit_bits)]
        decomposition = matrix(ZZ, bitrows)
        require((g * decomposition - raw).apply_map(lambda x: x % p.q).is_zero(), "independent G*digits identity")
        require(tuple(tuple(int(x) for x in row) for row in decomposition.rows()) == gadget_inverse(p, tuple(tuple(int(x) for x in row) for row in raw.rows())),
                "bit decomposition disagrees with Sage oracle")
        awires.append((g - awires[left] * decomposition).apply_map(lambda x: x % p.q))
        truth.append(1 - truth[left] * truth[right])
        inverse_count += 1
    expected = awires[circuit.outputs[0]]
    for node in circuit.outputs[1:]: expected = expected.augment(awires[node])
    require(expected == matrix(ZZ, public), "independent public NAND output differs")
    output_bits = tuple(truth[node] for node in circuit.outputs)
    masks = g * output_bits[0]
    for bit in output_bits[1:]: masks = masks.augment(g * bit)
    relation = matrix(ZZ, a) * matrix(ZZ, private.matrix) + masks - expected
    require(relation.apply_map(lambda x: x % p.q).is_zero(), "independent A*R + output*G identity")
    require(output_bits == private.output_bits, "independent truth values differ")
    require(sum(int(x)**2 for x in matrix(ZZ, private.matrix).list()) <= p.m * len(private.matrix[0]) * private.coefficient_bound**2,
            "coarse Frobenius bound failed")
    return inverse_count


def digest_matrix(value):
    return sha256(json.dumps(value, separators=(",", ":")).encode("ascii")).hexdigest()


def audit():
    from sage.version import version
    require(sha256((ROOT / PAPER).read_bytes()).hexdigest() == PAPER_SHA, "Yu paper version differs")
    cases = (
        ("nand-prime", Params(n=1, m=3, q=17), NandCircuit(2, ((0, 1),), (2,))),
        ("nand-composite", Params(n=1, m=3, q=81), NandCircuit(2, ((0, 1),), (2,))),
        ("shared-multi-output", Params(), NandCircuit(3, ((0, 1), (3, 2)), (4, 3, 0))),
        ("match-1010", Params(), matching_circuit((1, 0, 1, 0))),
    )
    rows, checked, inverses, rejected = [], 0, 0, 0
    for label, p, circuit in cases:
        a, r = inputs(p, circuit.input_count, label.encode())
        traces = []
        for values in product((0, 1), repeat=circuit.input_count):
            encoded = encode_inputs(p, a, values, r)
            public = eval_public(p, circuit, a, encoded)
            private = eval_private(p, circuit, a, values, r)
            require(homomorphism_holds(p, a, public, private), "reference equation failed")
            inverses += sage_check(p, circuit, values, a, encoded, public, private)
            if label.startswith("nand-"): truth = (1 - values[0] * values[1],)
            elif label == "shared-multi-output": truth = (1 - (1 - values[0] * values[1]) * values[2], 1 - values[0] * values[1], values[0])
            else: truth = (int(values == (1, 0, 1, 0)),)
            require(private.output_bits == truth, "truth-table control failed")
            changed = ((public[0][0] + 1) % p.q,) + public[0][1:]
            require(not homomorphism_holds(p, a, (changed, *public[1:]), private), "modified public output accepted")
            rejected += 1
            traces.append(dict(input_bits=values, output_bits=truth, public_output_sha256=digest_matrix(public),
                               private_coefficient_max=max(abs(x) for row in private.matrix for x in row),
                               max_intermediate_abs=private.max_intermediate_abs, coefficient_bound=private.coefficient_bound,
                               frobenius_squared=sum(x * x for row in private.matrix for x in row)))
            checked += 1
        rows.append(dict(name=label, parameters=asdict(p), gadget_columns=p.w, inputs=circuit.input_count,
                         outputs=len(circuit.outputs), gates=len(circuit.gates), output_depth=circuit.depth,
                         public_output_shape=[p.n, len(circuit.outputs) * p.w],
                         private_output_shape=[p.m, len(circuit.outputs) * p.w], circuit_sha256=sha256(circuit.to_bytes()).hexdigest(),
                         rows=traces))
    names = ("experiments/research/candidates/yu/homomorphic_reference.py", "experiments/research/candidates/yu/audit.py")
    return dict(security_claim="none", backend_admitted=False, full_IBS_implemented=False, actual_PRF_implemented=False,
                paper_spectral_norm_bound_verified=False, lemma7_homomorphism_portion_checked=True,
                paper_source=PAPER, paper_sha256=PAPER_SHA, paper_locations="§2.2 Definition2/Lemma7 PDF6; §3.3 Eq.(3.2)/Figure5",
                python=sys.version, sage=version, platform=platform.platform(), processor=platform.processor(),
                repeats_per_input=1, entropy="Deterministic teaching streams only; synthetic +/-1 input witnesses",
                identity_message_lengths="Not applicable: Boolean circuits over 2/3/4 synthetic bits; no IBS identity/message encoding",
                rom="None in this algebra component; no standard-model or QROM security claim follows",
                cases=rows, input_assignments_checked=checked, independent_digit_preimages_checked=inverses,
                altered_public_outputs_rejected=rejected,
                source_sha256_lf={name: sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in names},
                limitations=["Canonical binary preimages give exact equations but not a Gaussian sampler or the paper's O(4^d*m^1.5) singular-value bound.",
                             "Initial +/-1 witnesses and arbitrary integer witnesses used in composition have different norm scopes.",
                             "Full PRF circuit/evaluation, sampling, finite parameters, IBS and protocol integration remain WIP.",
                             "No private matrices, witness digest, random seed or key snapshot is exported."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({name: result[name] for name in ("input_assignments_checked", "altered_public_outputs_rejected", "security_claim")}))


if __name__ == "__main__": main()
