"""Portable exact config and ordered public tape; real sampler test in Sage."""

from dataclasses import asdict, replace
from fractions import Fraction
import json
import pytest

from ibme.core.errors import InvalidParameterError, SerializationError, EncodingError, RandomnessError
from ibme.hibe.abb_rom.params import ABBROMParams, Q160, SCHEMA
from ibme.hibe.abb_rom.identity import matrix_oracle_input, MatrixOracleTape


def test_complete_config_roundtrip_is_portable_and_canonical():
    params = ABBROMParams()
    assert params.dimension == 1280 and params.q == Q160
    assert ABBROMParams.from_bytes(params.to_bytes()) == params
    assert params.to_bytes() == ABBROMParams.from_bytes(params.to_bytes()).to_bytes()
    assert params.security_claim == "none" and params.backend_admitted is False


@pytest.mark.parametrize("change", [{"n": True}, {"q": 2}, {"q": 1.0},
    {"sigma1_squared": 0}, {"sigma2_squared": 2**193}, {"identity_max_bytes": 0},
    {"payload_max_bytes": 33}, {"max_tape_bytes": 2**45}, {"security_claim": "128bit"},
    {"backend_admitted": True}, {"parameters_are_formal": 0}, {"normalization": "auto"}])
def test_config_rejects_type_resource_and_security_substitution(change):
    with pytest.raises(InvalidParameterError):
        replace(ABBROMParams(), **change)


def test_config_decoder_rejects_unknown_missing_duplicate_and_noncanonical():
    base = ABBROMParams().to_bytes()
    record = json.loads(base)
    cases = [base[:-1], base+b"x", b" "+base, b'{"schema":"'+SCHEMA.encode()+b'","schema":"x","params":{}}']
    wrong = dict(record); wrong["schema"] = "unknown"
    cases.append(json.dumps(wrong).encode())
    wrong = {"schema": SCHEMA, "params": {**record["params"], "extra": 0}}
    cases.append(json.dumps(wrong).encode())
    wrong = {"schema": SCHEMA, "params": dict(record["params"])}
    wrong["params"].pop("q")
    cases.append(json.dumps(wrong).encode())
    for raw in cases:
        with pytest.raises(SerializationError):
            ABBROMParams.from_bytes(raw)


def test_ordered_prefix_inputs_are_length_framed_role_separated_and_bound():
    ctx = b"a"*64
    first = matrix_oracle_input(ctx,(b"rcv",),identity_max_bytes=86)
    second = matrix_oracle_input(ctx,(b"rcv",b"phi"),identity_max_bytes=86)
    reversed_pair = matrix_oracle_input(ctx,(b"phi",b"rcv"),identity_max_bytes=86)
    assert len({first,second,reversed_pair}) == 3
    assert second != matrix_oracle_input(b"b"*64,(b"rcv",b"phi"),identity_max_bytes=86)
    assert matrix_oracle_input(ctx,(b"ab",b"c"),identity_max_bytes=86) != matrix_oracle_input(ctx,(b"a",b"bc"),identity_max_bytes=86)
    for bad in [(), (b"",), (b"x"*87,), (b"a",b"b",b"c")]:
        with pytest.raises(EncodingError):
            matrix_oracle_input(ctx,bad,identity_max_bytes=86)


def test_public_tape_is_reproducible_across_read_partitions_without_testrng():
    data = matrix_oracle_input(b"a"*64,(b"rcv",b"phi"),identity_max_bytes=86)
    one, split = MatrixOracleTape(data,9000), MatrixOracleTape(data,9000)
    expected = one.read(9000)
    actual = b"".join(split.read(x) for x in [1,4095,1,4096,807])
    assert actual == expected and split.bytes_used == 9000
    assert MatrixOracleTape(data,9000).read(9000) == expected
    with pytest.raises(RandomnessError):
        split.read(1)
    assert split.bytes_used == 9000
    with pytest.raises(RandomnessError):
        split.read(True)


def test_actual_matrix_sampler_consumes_public_engineering_tape_in_sage():
    pytest.importorskip("sage.all",reason="prescribed WSL Sage required")
    from sage.all import GF, matrix
    from ibme.hibe.abb_rom import MatrixSampleR
    from ibme.lattice.matrix_sampling import MatrixFiniteOptions
    # Public primitive fixture; not the 1280-dimensional HIBE parameter preset.
    cfg = replace(ABBROMParams(), name="abb-oracle-public-fixture", q=101,
        random_rows=8,root_m1=8,root_m2=36,hadamard_scale=40,
        matrix_gaussian_squared_width=16,sample_r_max_matrices=5)
    from ibme.hibe.abb_rom.identity import prefix_matrix
    sampler = MatrixSampleR(cfg.q,cfg.dimension,cfg.matrix_gaussian_squared_width,
        max_matrices=cfg.sample_r_max_matrices,options=MatrixFiniteOptions())
    first = prefix_matrix(b"a"*64,(b"rcv",),cfg,sampler=sampler)
    second = prefix_matrix(b"a"*64,(b"rcv",),cfg,sampler=sampler)
    other = prefix_matrix(b"a"*64,(b"rcv",b"phi"),cfg,sampler=sampler)
    assert first == second and first != other
    assert matrix(GF(cfg.q),first).is_invertible()
