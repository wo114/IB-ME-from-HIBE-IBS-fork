"""Finite MP12 DelTrap equations, private scope/wire and whole-call ABORT."""

from copy import deepcopy
from fractions import Fraction
import json
from pathlib import Path

import pytest
pytest.importorskip("sage.all",reason="Use prescribed WSL Sage; skip is not pass")

from ibme.core.errors import InvalidParameterError,RandomnessError,SerializationError
from ibme.core.randomness import DeterministicRandom
from experiments.research.chkp_basis import ModMatrixReference,complete_kernel_basis
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.first_suite.finite_gpv import FirstFiniteGPV
from experiments.research.first_suite.compact_delegation import CompactGTrapdoor,FiniteDelTrap,split_extension


def oracle(p=8):
    public=ModMatrixReference(((1,)+(0,)*(p-1),),17)
    return FirstFiniteGPV(complete_kernel_basis(public),2**20,epsilon_bits=128)


@pytest.fixture
def actual_key():
    sampler=oracle()
    tail=ModMatrixReference(((3,4,5,6,7),),17)
    engine=FiniteDelTrap(sampler,tail)
    key=engine.sample(rng=DeterministicRandom(b"finite-MP12-deltrap-test"))
    return engine,key


def test_actual_gaussian_cosets_compact_relation_wire_and_source_independent_bound(actual_key):
    engine,key=actual_key
    cert=engine.certificate()
    assert not cert["tobasis_required"] and not cert["rank_detection_required"]
    assert not cert["old_trapdoor_padded_and_returned"] and cert["hibe_model_mapping_pending"]
    assert cert["security_claim"]=="none" and not cert["backend_admitted"]
    assert len(key.r_rows)==8 and len(key.r_rows[0])==5
    restored=CompactGTrapdoor.from_bytes(key.to_bytes(),expected_public=key.public,expected_width_squared=key.source_width_squared)
    assert restored.r_rows==key.r_rows and restored.to_bytes()==key.to_bytes()
    assert "r_rows" not in repr(key) and engine.last_entropy_bytes>0
    assert key.public_gs_squared_bound==10*(1+5*8*2**20)


def test_system_byte_source_is_the_default_and_real_read_occurs():
    engine=FiniteDelTrap(oracle(64),ModMatrixReference(((3,4,5,6,7),),17))
    key=engine.sample()
    assert key.public.ncols==69 and 0<engine.last_entropy_bytes<=engine.worst_entropy


def test_native_complete_basis_conversion_is_only_arithmetic_reuse(actual_key):
    engine,key=actual_key
    binary=Path(__file__).resolve().parents[1]/"test-results/qfall-target/release/ibme-qfall-private-root"
    if not binary.exists():pytest.skip("explicit private native build required")
    basis=key.to_basis(binary)
    assert basis.public==key.public and basis.public.ncols==13


@pytest.mark.parametrize("change",["context","width","leading-zero","negative-zero","equation","appended","duplicate","unknown"])
def test_private_formats_reject_malformed_or_foreign_binding(actual_key,change):
    engine,key=actual_key
    raw=key.to_bytes();obj=json.loads(raw)
    if change=="context":obj["public_binding"]="0"*64
    elif change=="width":obj["source_width_squared"]="2"
    elif change=="leading-zero":obj["r"][0][0]="00"
    elif change=="negative-zero":obj["r"][0][0]="-0"
    elif change=="equation":obj["r"][0][0]=str(int(obj["r"][0][0])+1)
    elif change=="unknown":obj["unused_secret"]="DO-NOT-ECHO"
    elif change=="appended":raw+=b"junk"
    else:raw=raw.replace(b'"schema":',b'"schema":"bad","schema":')
    if change not in ("appended","duplicate"):
        raw=json.dumps(obj,sort_keys=True,separators=(",", ":")).encode()
    with pytest.raises(SerializationError) as caught:
        CompactGTrapdoor.from_bytes(raw,expected_public=key.public,expected_width_squared=key.source_width_squared)
    assert "DO-NOT-ECHO" not in str(caught.value) and caught.value.__suppress_context__


def test_norm_failure_aborts_once_without_second_column_or_fallback(monkeypatch):
    sampler=oracle();calls=[]
    def bad(target,**kwargs):calls.append(target);return (2**30,)+(0,)*7
    monkeypatch.setattr(sampler,"sample",bad)
    engine=FiniteDelTrap(sampler,ModMatrixReference(((3,4,5,6,7),),17))
    with pytest.raises(SamplingAbort):engine.sample(rng=DeterministicRandom(b"bad-norm"))
    assert len(calls)==1 and engine.last_entropy_bytes==0


def test_resource_and_shape_rejections_precede_entropy():
    sampler=oracle();tail=ModMatrixReference(((3,4,5,6,7),),17)
    with pytest.raises(InvalidParameterError,match="entropy"):
        FiniteDelTrap(sampler,tail,max_entropy_bytes=1)
    with pytest.raises(InvalidParameterError,match="nk"):
        FiniteDelTrap(sampler,ModMatrixReference(((1,2),),17))
    class Bad:
        def read(self,count):return b""
    with pytest.raises(RandomnessError):FiniteDelTrap(sampler,tail).sample(rng=Bad())


def test_extension_prefix_uses_all_extra_columns_and_final_gadget_width():
    root=oracle().basis
    block=ModMatrixReference((tuple(range(7)),),17)
    prefix,tail=split_extension(root,block)
    assert prefix.public.ncols==10 and tail.rows==((2,3,4,5,6),)
    assert prefix.public.append(tail)==root.public.append(block)
    with pytest.raises(InvalidParameterError):split_extension(root,ModMatrixReference(((1,2),),17))


def test_master_exports_immutable_primitive_input_without_issuing_or_changing_addresses():
    from experiments.research.first_suite.identity import ROHIBEContext
    from experiments.research.first_suite.delegation_state import DelegationScope,MasterTreeState,ReceiverState
    root=oracle().basis
    o=ROHIBEContext(1,8,17,root.public.rows,b"TEST-ONLY/master-export",identity_bytes=64)
    scope=DelegationScope(o,Fraction(289),Fraction(2**20),Fraction(2**40),b"TEST-ONLY/p",b"TEST-ONLY/l",epsilon_bits=128)
    tree=MasterTreeState(scope,root);before=tree.to_bytes()
    assert tree.root_basis_for_research()==root and tree.to_bytes()==before
    assert not hasattr(ReceiverState,"root_basis_for_research")


def test_public_entropy_planning_is_minimal_and_never_admits_execution():
    from experiments.research.first_suite.parameter_resource_probe import minimum_entropy_columns,public_projection
    n,q,k,bits=2,353,9,8
    mass=Fraction(319,10);count=minimum_entropy_columns(n,q,k,bits=bits)
    target=(n*k)**2*q**n*2**(2*bits)
    assert mass**count>=target and mass**(count-1)<target
    with pytest.raises(ValueError):minimum_entropy_columns(True,q,k)
    with pytest.raises(ValueError):minimum_entropy_columns(n,q,k,mass=32.0)
    with pytest.raises(ValueError):public_projection(n,17)
    row=public_projection(128,2**61-1)
    assert row["root_dimension"]==9428
    assert not row["actual_key_generation_or_sampling"] and not row["execution_gates"]["compact_source"]
    assert not row["backend_admitted"] and not row["parameters_are_formal"]


def test_private_bridge_and_scope_reject_bad_types_without_secret_diagnostics(actual_key,monkeypatch):
    import subprocess
    from types import SimpleNamespace
    from experiments.research.first_suite.private_basis_bridge import convert_private_input
    engine,key=actual_key
    with pytest.raises(SerializationError):
        CompactGTrapdoor.from_bytes(key.to_bytes(),expected_public=key.public,expected_width_squared=float(key.source_width_squared))
    binary=Path(__file__).resolve().parents[1]/"test-results/qfall-target/release/ibme-qfall-private-root"
    if not binary.exists():pytest.skip("explicit private native build required")
    monkeypatch.setattr(subprocess,"run",lambda *a,**k:SimpleNamespace(returncode=0,stdout=b'{"basis":"DO-NOT-ECHO","basis":[]}'))
    with pytest.raises(InvalidParameterError) as caught:convert_private_input({},binary)
    assert caught.value.__suppress_context__ and "DO-NOT-ECHO" not in str(caught.value)
