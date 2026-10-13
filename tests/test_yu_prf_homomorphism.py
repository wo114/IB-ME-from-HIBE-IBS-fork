"""End-to-end PRF Boolean/numerical/public/private evaluation agreement."""
from itertools import product

import pytest

pytest.importorskip("sage.all", reason="Use the prescribed WSL Sage Python")

from experiments.research.candidates.yu import bpr, evaluation as e


@pytest.mark.parametrize("input_bits", [1, 2])
def test_real_bpr_circuit_relation_then_match(input_bits):
    spec = bpr.make_spec(bpr.Params(input_bits=input_bits, dimension=1, columns=1,
                                   modulus_bits=4, ticket_bits=8))
    p, a = e.EvalParams(1, 3, 17), ((1, 2, 3),)
    r = tuple(tuple(tuple(1 if (i+j+k) % 2 else -1 for j in range(p.w))
                    for i in range(p.m)) for k in range(spec.params.key_bits))
    # Fixed public algebra vectors, not saved real PRF or IBS secrets.
    for key in ((0,) * spec.params.key_bits, (1,) * spec.params.key_bits,
                tuple(i % 2 for i in range(spec.params.key_bits))):
        public_inputs = e.encode_inputs(p, a, key, r)
        for x in product((0, 1), repeat=input_bits):
            circuit = bpr.compile_key_circuit(spec, x)
            direct = bpr.evaluate(spec, key, x)
            public = e.eval_public(p, circuit, a, public_inputs)
            private = e.eval_private(p, circuit, a, key, r)
            assert direct == circuit.evaluate(key) == private.output_bits
            assert e.homomorphism_holds(p, a, public, private)
            for target in ((0,), (1,)):
                match = e.equality_circuit(target)
                final_public = e.eval_public(p, match, a, public)
                final_private = e.eval_private(p, match, a, direct, private.witnesses)
                assert final_private.output_bits == (int(direct == target),)
                assert e.homomorphism_holds(p, a, final_public, final_private)
