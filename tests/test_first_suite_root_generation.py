"""Private root API, finite entropy/regularity and independent basis checks."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import json
import subprocess
import traceback
from types import SimpleNamespace

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage; skip is not pass")
from sage.all import QQ

from ibme.core.errors import InvalidParameterError, RandomnessError
from ibme.core.randomness import DeterministicRandom
from experiments.research.first_suite.root_generation import (
    MP12RootParams, MP12RootGenerator, regularity_upper, unique_fields, validate_output,
)
from experiments.research.first_suite.root_probe import chain_plan, scope_for, public_n1_seed_attack, public_attack_fixture, attack_only


def binary():
    p=Path(__file__).resolve().parents[1]/"test-results/qfall-target/release/ibme-qfall-private-root"
    if not p.exists(): pytest.skip("explicit private root build required; skip is not pass")
    return p


def test_actual_private_root_defining_relation_complete_kernel_and_entropy_mode():
    p=MP12RootParams(1,35184372088891,37,1024)
    g=MP12RootGenerator(p,binary())
    a=g.generate(rng=DeterministicRandom(b"private-root-explicit-test"))
    b=g.generate(rng=DeterministicRandom(b"private-root-explicit-test"))
    assert a.basis.basis_rows == b.basis.basis_rows and a.basis.public==b.basis.public
    c=a.public_generation_certificate
    assert c["entropy_source"]=="deterministic-test"
    assert c["complete_kernel_and_defining_relation_checked"]
    assert QQ(c["root_regular_distance_upper_conditional"])<=QQ(1)/2**64
    assert c["actual_entropy_bytes"]<=c["worst_entropy_bytes"]
    assert "basis_rows" not in repr(a)
    actual=g.generate()
    assert actual.public_generation_certificate["entropy_source"]=="system"
    assert actual.basis.public!=a.basis.public


def test_regular_distance_bound_uses_actual_finite_entropy_and_upward_rounding():
    p=MP12RootParams(1,35184372088891,37,1024)
    delta=regularity_upper(p,32)
    assert delta*delta >= p.k*p.k*QQ(p.q)/QQ(32)**p.m_bar
    assert regularity_upper(p,16)>delta
    assert regularity_upper(p,1)==1


def test_stronger_regularity_target_recomputes_precision_and_reports_joint_dimension_failure():
    p=MP12RootParams(1,35184372088891,63,1024,regularity_bits=128)
    g=MP12RootGenerator(p,binary())
    assert g.regularity<=QQ(1)/2**128
    assert g.regularity*g.regularity >= QQ(p.k*p.k*p.q)/g.scalar.acceptance_mass_lower**p.m_bar
    plan=chain_plan(g)
    assert plan["dimensions"]==[109,218,327]
    assert not plan["resource_dimensions"]["parent_tobasis"]
    assert not plan["resource_dimensions"]["leaf_finite_gpv"]


@pytest.mark.parametrize("params", [
    (True,17,8,16),(1,15,8,16),(1,17,0,16),(1,17,8,0),(64,2**61-1,100,16),
])
def test_invalid_parameters_reject_before_entropy(params):
    with pytest.raises(InvalidParameterError): MP12RootParams(*params)


def test_root_regularity_support_and_tape_rejections_are_pre_entropy():
    with pytest.raises(InvalidParameterError,match="regularity"):
        MP12RootGenerator(MP12RootParams(1,35184372088891,8,1024),binary())
    with pytest.raises(InvalidParameterError,match="injective"):
        MP12RootGenerator(MP12RootParams(1,17,8,1024,regularity_bits=None),binary())
    with pytest.raises(InvalidParameterError,match="entropy"):
        MP12RootGenerator(MP12RootParams(1,35184372088891,37,1024,max_entropy_bytes=1),binary())
    g=MP12RootGenerator(MP12RootParams(1,35184372088891,37,1024),binary())
    class Bad:
        def read(self,count): return b""
    with pytest.raises(RandomnessError): g.generate(rng=Bad())


@pytest.mark.parametrize("change", ["version","unknown","public-fixture","dimension","residue","R-range"])
def test_private_engine_rejects_bad_inputs_without_echoing_secret_values(change):
    req=dict(schema="IBME/MP12-SECRET-ROOT/1",entropy_source="deterministic-test",n=1,q=17,m_bar=1,a_bar=[[1]],r=[[0]*5])
    if change=="version": req["schema"]="wrong"
    elif change=="unknown": req["unexpected_secret"]="DO-NOT-ECHO-ROOT-SECRET"
    elif change=="public-fixture": req={"public_test_fixture":True,"n":1,"q":17,"m_bar":1,"a_bar":[[1]],"r":[[0]*5]}
    elif change=="dimension": req["m_bar"]=2049
    elif change=="residue": req["a_bar"]=[[17]]
    else: req["r"][0][0]=2**49
    r=subprocess.run([str(binary())],input=json.dumps(req).encode(),capture_output=True,timeout=30)
    assert r.returncode!=0 and not r.stdout
    assert b"DO-NOT-ECHO-ROOT-SECRET" not in r.stderr


def test_public_fixture_frontend_is_not_silently_repurposed():
    old=Path(__file__).resolve().parents[1]/"test-results/qfall-target/release/ibme-qfall-public-fixture"
    if not old.exists(): pytest.skip("public fixture comparison build required")
    req=dict(schema="IBME/MP12-SECRET-ROOT/1",entropy_source="system",n=1,q=17,m_bar=1,a_bar=[[1]],r=[[0]*5])
    r=subprocess.run([str(old)],input=json.dumps(req).encode(),capture_output=True,timeout=30)
    assert r.returncode!=0


@pytest.fixture
def valid_private_output():
    request=dict(schema="IBME/MP12-SECRET-ROOT/1",entropy_source="deterministic-test",n=1,q=17,m_bar=1,a_bar=[[1]],r=[[0]*5])
    raw=subprocess.run([str(binary())],input=json.dumps(request).encode(),capture_output=True,check=True,timeout=30).stdout
    return request,json.loads(raw)


@pytest.mark.parametrize("change", ["unknown","dimension-bool","A-equation","A-residue","B-kernel","B-sublattice","B-shape","integer-leading-zero","integer-float","integer-bool"])
def test_independent_private_output_validation_rejects_bad_encodings_and_relations(valid_private_output,change):
    req,out=valid_private_output
    out=deepcopy(out)
    if change=="unknown": out["unused"]=1
    elif change=="dimension-bool": out["n"]=True
    elif change=="A-equation": out["a"][0][0]="2"
    elif change=="A-residue": out["a"][0][0]="17"
    elif change=="B-kernel": out["basis"][0][0]=str(int(out["basis"][0][0])+1)
    elif change=="B-sublattice":
        for row in out["basis"]: row[0]=str(2*int(row[0]))
    elif change=="B-shape": out["basis"].pop()
    elif change=="integer-leading-zero": out["basis"][0][0]="00"
    elif change=="integer-float": out["basis"][0][0]=0.0
    else: out["basis"][0][0]=False
    with pytest.raises(ValueError): validate_output(req,out)


def test_duplicate_fields_rejected_at_both_private_boundaries(valid_private_output):
    req,out=valid_private_output
    with pytest.raises(ValueError,match="duplicate"):
        json.loads('{"basis":[],"basis":[]}',object_pairs_hook=unique_fields)
    raw=json.dumps(req).replace('"n": 1','"n": 1, "n": 1')
    r=subprocess.run([str(binary())],input=raw.encode(),capture_output=True,timeout=30)
    assert r.returncode and not r.stdout


def test_private_json_errors_do_not_include_cause_or_secret_in_traceback(monkeypatch):
    generator=MP12RootGenerator(MP12RootParams(1,35184372088891,37,1024),binary())
    raw=b'{"basis":"DO-NOT-ECHO-SECRET","basis":[]}'
    monkeypatch.setattr(subprocess,"run",lambda *args,**kwargs: SimpleNamespace(returncode=0,stdout=raw))
    with pytest.raises(InvalidParameterError) as caught:
        generator.generate(rng=DeterministicRandom(b"malformed-private-output-test"))
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert "DO-NOT-ECHO-SECRET" not in "".join(traceback.format_exception(caught.value))


def test_public_chain_recalculates_widths_and_persists_epsilon128_scope():
    from experiments.research.first_suite.identity import ROHIBEContext
    from experiments.research.first_suite.delegation_state import MasterTreeState
    generator=MP12RootGenerator(MP12RootParams(1,35184372088891,37,1024),binary())
    plan=chain_plan(generator)
    assert plan["dimensions"]==[83,166,249]
    assert plan["parent_width_squared"]==272729642840
    assert plan["leaf_width_squared"]==24809670149869120
    assert plan["selected_modulus_sufficient"] and plan["conditional_noise"]["conditional_noise_sufficient"]
    assert not plan["actual_parent_leaf_profiles_checked"] and not plan["backend_admitted"]
    assert plan["capacity_obstruction"]["max_n_from_gadget_before_random_columns"]==1
    root=generator.generate(rng=DeterministicRandom(b"epsilon128-private-root-test"))
    o=ROHIBEContext(1,83,generator.params.q,root.basis.public.rows,b"TEST-ONLY/root-plan")
    scope=scope_for(o,plan)
    tree=MasterTreeState(scope,root.basis)
    restored=MasterTreeState.from_bytes(tree.to_bytes(),expected_scope=scope)
    assert restored.scope.epsilon_bits==128 and restored.to_bytes()==tree.to_bytes()
    with pytest.raises(InvalidParameterError,match="epsilon bits"):
        replace(scope,epsilon_bits=129)


def test_public_n1_attack_recovers_actual_rounded_noise_seed_without_private_key():
    from fractions import Fraction
    from experiments.research.first_suite.identity import ROHIBEContext
    from experiments.research.first_suite.seed_kem import encapsulate_seed
    from experiments.research.ibme_noise_budget import RoundedNoiseParams
    from experiments.research.ibme_rounded_noise import build_rounded_noise
    q=35184372088891
    o=ROHIBEContext(1,20,q,(tuple(range(1,21)),),b"TEST-ONLY/public-LWE-attack",identity_bytes=64)
    noise=build_rounded_noise(RoundedNoiseParams(q,Fraction(4,q),tail_bits=64,mass_bits=96,precision_bits=160))
    seed=bytes(range(32))
    capsule=encapsulate_seed(o,b"Bob",b"Alice",seed,noise,rng=DeterministicRandom(b"n1-public-only-control"))
    count,candidates,seeds=public_n1_seed_attack(o,b"Bob",b"Alice",capsule,noise)
    assert count==2*noise.radius+1 and len(candidates)==1 and seeds==[seed]
    fixture=public_attack_fixture(o,b"Bob",b"Alice",capsule,noise,seed)
    result=attack_only(json.loads(json.dumps(fixture)))
    assert result["unique_seed_hash_matches"] and not result["private_state_loaded"]
    changed=deepcopy(fixture);changed["expected_seed_sha256"]="0"*64
    assert not attack_only(changed)["unique_seed_hash_matches"]


@pytest.mark.parametrize("kind",["private-alias","existing","outside"])
def test_probe_refuses_public_output_key_alias_or_overwrite_before_generation(tmp_path,monkeypatch,kind):
    from experiments.research.first_suite import root_probe
    monkeypatch.setattr(root_probe,"ROOT",tmp_path)
    def forbidden(*args,**kwargs): pytest.fail("bad output path reached private generation")
    monkeypatch.setattr(root_probe,"one_probe",forbidden)
    private=tmp_path/"test-results/new-private"
    if kind=="private-alias": output=private/"master-tree.bin"
    elif kind=="outside": output=tmp_path/"tracked.json"
    else:
        output=tmp_path/"test-results/old-result.json"
        output.parent.mkdir(parents=True);output.write_bytes(b"keep-this-result")
    with pytest.raises(ValueError,match="public output"):
        root_probe.main(["--private-directory",str(private),"--output",str(output)])
    assert not private.exists()
    if kind=="existing": assert output.read_bytes()==b"keep-this-result"
