"""Extension contracts: registry-driven planning and explicitly selected runs.

Renamed real IBS implementations exercise public interfaces through a test-only
HIBE. They establish driver reuse, not a newly implemented cryptographic scheme.
"""

from dataclasses import replace
import itertools
import json

import pytest

from ibme.assembly import BackendRegistry, BackendSpec, default_registry
import experiments.run_combination_matrix as runner


@pytest.fixture
def registry():
    builtins = default_registry()
    hibe = replace(builtins.get("hibe", "mock"), id="arbitrary-hibe")
    ibs = builtins.get("ibs", "luo-module")
    # No Luo ID/default-preset conventions are available to the driver.
    ibs = replace(ibs, id="brand-new-ibs", presets={"explicit-parameters": ibs.presets["research"]},
                  default_preset=lambda transport: "explicit-parameters",security_claim="none",
                  backend_admitted=False,formal_parameter_presets=(),admission_basis="")
    return BackendRegistry([hibe, ibs])


def selection(transport="direct", protocol="byteauth-v1", fmt="reference"):
    return dict(hibe="arbitrary-hibe", ibs="brand-new-ibs", allow_mock=True,
                hibe_params="hybrid-research" if transport == "hybrid" else "education",
                ibs_params="explicit-parameters", transport=transport, protocol=protocol,
                signature_format=fmt)


def test_explicit_saved_instance_hook_keeps_all_common_checks_and_classification():
    called=[]
    def setup(runtime,source):
        called.append(True)
        pk,master=runtime.proto.setup(runtime.hibe_params,ibs_params=runtime.ibs_params,rng=source)
        return pk,master,{"test_only_fixture":True}
    receipt=runner.run_case("explicit-fixture",runner.case_definitions()["mock-direct-mock-byteauth"],
        setup_callback=setup,identities=(b"Alice",b"Bob",b"Carol",b"Charlie"))
    assert called==[True] and receipt["status"]=="pass"
    assert receipt["setup_source"]=="explicit research harness"
    assert receipt["classification"]=="test_only" and receipt["security_proof_count"]==0
    assert {"honest_roundtrip","wrong_sender","wrong_receiver","both_wrong","restored_decrypt"} <= {
        row["name"] for row in receipt["checks"] if row["status"]=="pass"}


@pytest.mark.parametrize("transport,protocol,fmt", tuple(itertools.product(
    runner.TRANSPORTS, runner.PROTOCOLS, ("reference", "compact"))))
def test_arbitrary_id_runs_every_transport_protocol_and_format(registry, transport, protocol, fmt):
    receipt = runner.run_case("new-ibs-" + "-".join((transport, protocol, fmt)),
                              selection(transport, protocol, fmt), registry=registry)
    assert receipt["status"] == "pass", receipt
    assert receipt["classification"] == "test_only"  # HIBE is a mock despite its arbitrary ID.
    assert receipt["execution"] == "executed"
    names = {item["name"] for item in receipt["checks"] if item["status"] == "pass"}
    assert {"honest_roundtrip", "wrong_sender", "wrong_receiver", "both_wrong",
            "public_restore", "master_restore", "sender_restore", "receiver_restore",
            "restored_decrypt", "fixed_identity_repeated_extract", "fixed_identity_after_restore",
            "truncated_loader", "appended_loader", "duplicate_loader", "wrong_version_loader",
            "ibs_honest", "ibs_wrong_message", "ibs_wrong_identity",
            "inner_authentication_rejects", "inner_rejection_reached_ibs", "empty_roundtrip"} <= names
    assert any(name.startswith("changed_signature_") for name in names)
    assert any(name.startswith("random_signature_") for name in names)
    assert ("forged_outer_ots_valid" in names) == (protocol == "byteauth-v1")
    report = runner.summarize([receipt])
    assert report["evidence_counts"]["test_only"]["checks"] == receipt["executed_checks"]
    assert report["evidence_counts"]["research"]["checks"] == report["security_proof_count"] == 0


def test_generator_covers_registry_product_without_executing(registry, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("planning must not build runtime or generate keys")

    specs = [replace(registry.get(role, name), factory=forbidden)
             for role, name in (("hibe", "arbitrary-hibe"), ("ibs", "brand-new-ibs"))]
    specs.append(BackendSpec("future-route", "ibs", "pending", available=False,
                             reason="primitive not delivered"))
    registry = BackendRegistry(specs)
    monkeypatch.setattr(runner, "build_runtime", forbidden)
    cases = runner.generate_cases(registry=registry, allow_mock=True)
    # Two HIBE presets, both protocols/transports, two IBS formats + one pending.
    assert len(cases) == 2 * 2 * 2 * (2 + 1)
    assert {opt["signature_format"] for opt in cases.values()} == {"reference", "compact"}
    rows = [runner.plan_case(name, options, registry=registry) for name, options in cases.items()]
    assert {row["status"] for row in rows} == {"planned", "preflight_failed", "unavailable"}
    assert all(row["execution"] == "not_executed" and not row["checks"] for row in rows)
    assert all(row["status"] == "unavailable" for row in rows if row["selection"]["ibs"] == "future-route")
    report = runner.summarize(rows)
    assert report["status"] == "incomplete"
    assert report["executed_cases"] == report["executed_checks"] == report["security_proof_count"] == 0


def test_default_and_explicit_plan_never_run_cases(registry, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("plan called an executor")

    monkeypatch.setattr(runner, "run_case", forbidden)
    monkeypatch.setattr(runner, "build_runtime", forbidden)
    for args in ([], ["--plan", "--allow-mock"]):
        assert runner.main(args, registry=registry) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["mode"] == "plan"
        assert report["status"] == "preflight_only"
        assert report["executed_checks"] == report["security_proof_count"] == 0
        assert len(report["results"]) == 16
        if not args:
            assert all(row["status"] == "preflight_failed" for row in report["results"])


def test_dependency_blockers_and_unknown_ids_do_not_reach_setup(registry, monkeypatch):
    spec = registry.get("ibs", "brand-new-ibs")

    def unavailable():
        raise ImportError("dependency absent")

    registry = BackendRegistry([registry.get("hibe", "arbitrary-hibe"),
                               replace(spec, validate_environment=unavailable)])
    monkeypatch.setattr(runner, "build_runtime", lambda *a, **k: pytest.fail("unavailable execution"))
    plan = runner.plan_case("dependency", selection(), registry=registry)
    assert plan["status"] == "unavailable"
    assert "dependency absent" in str(plan["preflight"])
    receipt = runner.run_case("dependency", selection(), registry=registry)
    assert receipt["status"] == "blocked" and receipt["executed_checks"] == 0
    unknown = runner.plan_case("unknown", dict(selection(), ibs="not-registered"), registry=registry)
    assert unknown["status"] == "preflight_failed"
    assert "no fallback" in unknown["error"]


@pytest.mark.parametrize("break_after_restore", (False, True))
def test_arbitrary_cache_capability_detects_reextraction_and_restore_failures(break_after_restore):
    builtins = default_registry()
    spec = builtins.get("ibs", "luo-matrix")
    created = []

    def factory(rng, fmt):
        backend = spec.factory(rng, fmt)
        extract = backend.key_extract
        calls = []

        def broken_extract(master, identity):
            calls.append(identity)
            if ((break_after_restore and len(created) > 1)
                    or (not break_after_restore and len(calls) > 1)):
                # Model a cache failure entirely through public Setup/Extract.
                _, master = backend.setup(spec.presets["test-small"])
            return extract(master, identity)

        backend.key_extract = broken_extract
        created.append(backend)
        return backend

    registry = BackendRegistry([builtins.get("hibe", "mock"),
        replace(spec, id="unrelated-identity-cache", factory=factory)])
    receipt = runner.run_case("broken-cache", dict(hibe="mock", ibs="unrelated-identity-cache",
        ibs_params="test-small", allow_mock=True), registry=registry)
    assert receipt["status"] == "fail", receipt
    expected = "fixed_identity_after_restore" if break_after_restore else "fixed_identity_repeated_extract"
    assert receipt["checks"][-1] == {"name": expected, "status": "fail"}
    assert runner.summarize([receipt])["status"] == "incomplete"


def test_cache_requirement_comes_from_metadata_not_name():
    builtins = default_registry()
    registry = BackendRegistry([builtins.get("hibe", "mock"),
                                replace(builtins.get("ibs", "mock"), id="luo-matrix")])
    receipt = runner.run_case("not-cache-capable", dict(hibe="mock", ibs="luo-matrix",
                              ibs_params="education", allow_mock=True), registry=registry)
    assert receipt["status"] == "pass", receipt
    assert not any(item["name"].startswith("fixed_identity_") for item in receipt["checks"])


def test_real_descriptor_classification_does_not_follow_allow_mock():
    options = dict(hibe="abb10", ibs="luo-matrix", transport="hybrid", allow_mock=True)
    plan = runner.plan_case("real", options)
    assert plan["status"] == "planned"
    assert plan["classification"] == "research"


def test_immutable_ibs_needs_no_method_monkeypatching():
    builtins = default_registry()
    spec = builtins.get("ibs", "luo-matrix")

    class ReadOnlyBackend:
        __slots__ = ("backend",)

        def __init__(self, backend):
            self.backend = backend

        def __getattr__(self, name):
            return getattr(self.backend, name)

    registry = BackendRegistry([builtins.get("hibe", "mock"), replace(spec,
        id="immutable-ibs", factory=lambda rng, fmt: ReadOnlyBackend(spec.factory(rng, fmt)))])
    receipt = runner.run_case("immutable", dict(hibe="mock", ibs="immutable-ibs",
                              ibs_params="research", allow_mock=True), registry=registry)
    assert receipt["status"] == "pass", receipt
    assert {"name": "inner_rejection_reached_ibs", "status": "pass"} in receipt["checks"]


def test_selected_json_reuses_driver_and_can_be_planned(registry, tmp_path, monkeypatch, capsys):
    path = tmp_path / "selected.json"
    path.write_text(json.dumps([dict(name="only-this", selection=selection(fmt="compact"))]), encoding="utf-8")
    original = runner.run_case
    calls = []

    def observed(name, options, *, registry):
        calls.append((name, options))
        return original(name, options, registry=registry)

    monkeypatch.setattr(runner, "run_case", observed)
    assert runner.main(["--plan", "--suite-file", str(path)], registry=registry) == 0
    assert not calls
    assert json.loads(capsys.readouterr().out)["executed_checks"] == 0
    assert runner.main(["--suite-file", str(path)], registry=registry) == 0
    assert calls == [("only-this", selection(fmt="compact"))]
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "pass" and report["executed_cases"] == 1
    assert report["evidence_counts"]["research"]["cases"] == 0


@pytest.mark.parametrize("raw", [
    '[]', '{}', '[{"name":"a","selection":{"hibe":"mock","ibs":"mock","module":"os"}}]',
    '[{"name":"a","name":"b","selection":{"hibe":"mock","ibs":"mock"}}]',
    '[{"name":"a","selection":{"hibe":"mock","ibs":"mock","ibs_params":{"n":1,"n":2}}}]',
    '[{"name":"a","selection":{"hibe":"mock","ibs":"mock","ibs_params":{"n":NaN}}}]',
    '[{"name":"a","selection":{},"factory":"os.system"}]',
])
def test_json_is_strict_data_and_cannot_load_code(raw, tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_text(raw, encoding="utf-8")
    monkeypatch.setattr(runner, "run_case", lambda *a, **k: pytest.fail("malformed JSON executed"))
    with pytest.raises(SystemExit) as error:
        runner.main(["--suite-file", str(path)])
    assert error.value.code == 2


def test_duplicate_suite_aliases_are_rejected_before_execution(registry, tmp_path, monkeypatch):
    path = tmp_path / "duplicates.json"
    path.write_text(json.dumps([dict(name=name, selection=selection()) for name in ("one", "two")]), encoding="utf-8")
    monkeypatch.setattr(runner, "run_case", lambda *a, **k: pytest.fail("duplicate executed"))
    with pytest.raises(SystemExit) as error:
        runner.main(["--suite-file", str(path)], registry=registry)
    assert error.value.code == 2


def test_nonexecution_evidence_cannot_inflate_acceptance_counts():
    rows = [dict(status=status, executed_checks=999, execution="not_executed")
            for status in ("planned", "unavailable", "preflight_failed", "pass")]
    report = runner.summarize(rows)
    assert report["status"] == "incomplete"
    assert report["executed_checks"] == report["executed_cases"] == report["security_proof_count"] == 0


def test_legacy_named_cases_and_defaults_remain_compatible(capsys):
    expected = {}
    for ibs, fmt in (("sis", "reference"), ("luo-matrix", "reference"),
                     ("luo-module", "reference"), ("luo-module", "compact")):
        for protocol in ("baseline-v1", "byteauth-v1"):
            expected[f"abb10-hybrid-{ibs}-{fmt}-{protocol}"] = dict(
                hibe="abb10", ibs=ibs, transport="hybrid", protocol=protocol, signature_format=fmt)
    default_names = tuple(expected) + ("abb10-direct-sis-byteauth",)
    expected.update({
        "abb10-direct-sis-byteauth": dict(hibe="abb10", ibs="sis"),
        "mock-direct-mock-byteauth": dict(hibe="mock", ibs="mock", allow_mock=True),
        "mock-hybrid-luo-matrix-byteauth": dict(hibe="mock", ibs="luo-matrix", transport="hybrid", allow_mock=True),
        "abb10-hybrid-mock-byteauth": dict(hibe="abb10", ibs="mock", transport="hybrid", allow_mock=True),
        "latte-pending": dict(hibe="latte", ibs="luo-module", transport="hybrid"),
    })
    assert runner.case_definitions() == expected
    assert runner.DEFAULT_CASES == default_names
    assert runner.main(["--list"]) == 0
    assert json.loads(capsys.readouterr().out)["cases"] == expected
    assert runner.main(["--case", "mock-direct-mock-byteauth"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "pass"
