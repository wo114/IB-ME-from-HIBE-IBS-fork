import copy
import hashlib

import pytest

from experiments.research.random_batch_acceptance import (
    CHECK_NAMES,
    IDENTITY_BYTES,
    MESSAGE_LENGTHS,
    ROOT_COUNT,
    case_inputs,
    parse_seed,
    public_input_manifest,
    validate_public_report,
)


SEED = bytes(range(32))


def test_public_input_expansion_is_reproducible_distinct_and_bounded():
    first = case_inputs(SEED, 0)
    assert first == case_inputs(SEED, 0)
    assert first != case_inputs(SEED, 1)
    assert len(first["receivers"]) == len(first["senders"]) == 2
    identities = first["receivers"] + first["senders"]
    assert len(set(identities)) == 4
    assert {len(value) for value in identities} == {IDENTITY_BYTES}
    assert [len(case["message"]) for case in first["cases"]] == list(MESSAGE_LENGTHS)
    assert [(case["receiver_slot"], case["sender_slot"]) for case in first["cases"]] == [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
    ]


def test_public_manifest_has_hashes_but_no_raw_inputs():
    manifest = public_input_manifest(SEED, 2)
    assert manifest["root_index"] == 2
    assert len(manifest["cases"]) == 4
    rendered = repr(manifest)
    assert "receiver':" not in rendered
    assert "sender':" not in rendered
    assert "message':" not in rendered
    for case in manifest["cases"]:
        for name in ("receiver_identity_sha256", "sender_identity_sha256", "message_sha256"):
            assert len(case[name]) == 64
            int(case[name], 16)


@pytest.mark.parametrize("value", ["", "00", "g" * 64, "00" * 31, "00" * 33, None])
def test_seed_parser_rejects_non_32_byte_hex(value):
    with pytest.raises(ValueError):
        parse_seed(value)


def _valid_report():
    from ibme.assembly import make_suite

    seed = SEED.hex()
    runner_hash = hashlib.sha256(b"runner").hexdigest()
    config = make_suite(
        hibe="latte",
        hibe_params="seed32",
        ibs="cert-ml-dsa",
        ibs_params="ml-dsa-44",
        transport="hybrid",
        protocol="byteauth-v1",
        signature_format="reference",
        allow_mock=False,
    )
    suite = config.to_dict()
    roots = []
    for root_index in range(ROOT_COUNT):
        manifest = public_input_manifest(SEED, root_index)
        cases = []
        for item in manifest["cases"]:
            cases.append(
                dict(
                    **item,
                    ciphertext_bytes=123,
                    ciphertext_sha256=hashlib.sha256(item["case_id"].encode()).hexdigest(),
                    tamper=dict(
                        component="byteauth.inner_bytes",
                        byte_offset=7,
                        xor_mask=2,
                        wire_length_unchanged=True,
                        canonical_loader_accepted=True,
                    ),
                    checks={name: True for name in sorted(CHECK_NAMES)},
                )
            )
        roots.append(
            dict(
                schema="IBME-A09-RANDOM-BATCH-ROOT/1",
                status="passed",
                source_commit="a" * 40,
                root_index=root_index,
                process={
                    "returncode": 0,
                    "timed_out": False,
                    "fresh_process_wall_seconds": 1.0,
                },
                completed_checks=20,
                failed_checks=0,
                suite=suite,
                suite_digest=config.digest,
                security_claim="none",
                backend_admitted=False,
                parameters_are_formal=False,
                input_manifest=manifest,
                cryptographic_randomness=dict(
                    source="SecureRandom / operating-system CSPRNG",
                    deterministic_test_seed_injected=False,
                    reads=10,
                    bytes=100,
                ),
                native_operation_counts={
                    "latte:setup": 1,
                    "latte:delegate": 2,
                    "latte:extract": 4,
                    "latte:encrypt": 4,
                    "latte:decrypt": 16,
                    "mldsa:keypair": 3,
                    "mldsa:sign": 6,
                },
                source_providers={
                    "experiments/research/random_batch_acceptance.py": runner_hash
                },
                cases=cases,
            )
        )
    return dict(
        schema="IBME-A09-RANDOM-BATCH/1",
        status="passed",
        source_commit="a" * 40,
        suite_name="latte3-hybrid-cert-ml-dsa-ml-dsa-44-reference-byteauth-v1",
        suite=suite,
        suite_digest=config.digest,
        identity_bytes=64,
        message_lengths=list(MESSAGE_LENGTHS),
        input_seed_hex=seed,
        input_generation=dict(
            algorithm="SHAKE256",
            domain="IBME:A09:RANDOM-BATCH:INPUTS:v1",
            public_reproducible_seed=True,
            cryptographic_rng_separation=True,
        ),
        execution=dict(
            fresh_process_per_root=True,
            failed_samples_retried=False,
            failed_samples_discarded=False,
            roots_planned=3,
            roots_completed=3,
            pairs_planned=12,
            cases_recorded=12,
        ),
        totals={name: 12 for name in CHECK_NAMES},
        total_checks_passed=60,
        total_checks_planned=60,
        roots=roots,
        security=dict(
            security_claim="none",
            backend_admitted=False,
            parameters_are_formal=False,
            functional_tests_are_security_proof=False,
        ),
    )


def test_public_report_validator_accepts_exact_scope():
    assert validate_public_report(_valid_report(), expected_commit="a" * 40) == 60


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report["roots"][0]["cases"][0]["checks"].__setitem__(
            "honest_roundtrip", False
        ),
        lambda report: report["suite"].__setitem__("allow_mock", True),
        lambda report: report["execution"].__setitem__("failed_samples_retried", True),
        lambda report: report["roots"][1]["cryptographic_randomness"].__setitem__("bytes", 0),
        lambda report: report["roots"][2]["cases"][0].__setitem__("message_hex", "00"),
    ],
)
def test_public_report_validator_rejects_scope_or_evidence_tampering(mutation):
    report = copy.deepcopy(_valid_report())
    mutation(report)
    with pytest.raises(AssertionError):
        validate_public_report(report)
