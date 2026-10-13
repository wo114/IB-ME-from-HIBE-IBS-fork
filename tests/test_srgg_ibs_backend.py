"""End-to-end real SRGG research IBS; no formal security claim."""
from dataclasses import replace
import importlib
import json
import os
import subprocess
import sys

import pytest
from ibme.core.errors import EncodingError, SerializationError
from ibme.core.randomness import DeterministicRandom


def api():
    try: return importlib.import_module("experiments.research.candidates.srgg.backend")
    except ModuleNotFoundError: pytest.fail("complete SRGG IBS backend is missing")


def test_complete_backend_available():
    assert all(callable(getattr(api().Backend, method, None)) for method in
               ("setup", "key_extract", "sign", "verify", "load_signature"))


@pytest.fixture(scope="module")
def lifecycle():
    pytest.importorskip("sage.all", reason="real SRGG sampling uses prescribed Sage")
    a = api()
    b = a.Backend(rng=DeterministicRandom(b"SRGG-full-master"))
    pk, master = b.setup(a.Config())
    key = b.key_extract(master, b"Alice")
    sig = b.sign(key, b"hello")
    return a, b, pk, master, key, sig


def test_nontrivial_norm_profile_and_parameter_gates():
    c = api().Config()
    assert c.algebra.modulus == 7656287
    assert c.signature_bound_squared == 6597069766656
    assert c.algebra.modulus**2 > 4*c.signature_bound_squared
    assert c.signature_noise_factor == 2
    assert c.security_claim == "none" and c.backend_admitted is False
    for fields in ({"degree": True}, {"signature_noise_factor": 1}, {"max_users": 0},
                   {"sign_max_attempts": 0}, {"signature_first_squared": 1},
                   {"precision_bits":128},{"ticket_bits":256},{"scalar_mass_bits":256}):
        with pytest.raises(ValueError): api().Config(**fields)


def test_real_setup_extract_sign_verify_and_independent_commitment(lifecycle):
    from sage.all import PolynomialRing, ZZ, matrix, vector
    from experiments.research.candidates.srgg.algebra import signing_matrix, zeta_star
    a, b, pk, master, key, sig = lifecycle
    assert b.verify(pk, b"Alice", b"hello", sig) is True
    h = importlib.import_module("experiments.research.candidates.srgg.hashing")
    target = h.identity_target(pk, b"Alice")
    n, Q = pk.config.degree, pk.config.algebra.modulus
    ring0 = PolynomialRing(ZZ, "X"); X = ring0.gen(); ring = ring0.quotient(X**n+1, "x")
    def pol(c): return ring(ring0(list(c)))
    A = matrix(ring, [[pol(v) for v in row] for row in signing_matrix(pk.public, target)])
    recovered = A*vector(ring, [pol(v) for v in sig.z])
    recovered[0] -= Q*pol(zeta_star(pk.config.algebra))*pol(sig.challenge)
    w = tuple(tuple(int(poly.lift()[i]) % (2*Q) for i in range(n)) for poly in recovered)
    assert h.message_challenge(pk, w, b"hello") == sig.challenge
    assert sum(x*x for poly in sig.z for x in poly) <= pk.config.signature_bound_squared
    assert len(sig.z) == pk.config.algebra.columns+1
    assert len(sig.challenge) == n
    assert key.identity == b"Alice"
    assert b.verify(pk, b"Bob", b"hello", sig) is False
    assert b.verify(pk, b"Alice", b"different", sig) is False


def test_fixed_identity_cache_and_repeated_signing(lifecycle):
    a, b, pk, master, key, sig = lifecycle
    class NoRead:
        def read(self, _): raise AssertionError("cached extraction consumed entropy")
    assert a.Backend(rng=NoRead()).key_extract(master, b"Alice").to_bytes() == key.to_bytes()
    second = b.sign(key, b"hello")
    third = b.sign(key, b"")
    assert second.to_bytes() != sig.to_bytes()
    assert b.verify(pk, b"Alice", b"hello", second)
    assert b.verify(pk, b"Alice", b"", third)


def test_strict_objects_and_cross_process_resume(lifecycle):
    a, b, pk, master, key, sig = lifecycle
    o = importlib.import_module("experiments.research.candidates.srgg.objects")
    for value, cls in ((pk,o.PublicKey),(master,o.MasterSecret),(key,o.SigningKey),(sig,o.Signature)):
        raw=value.to_bytes()
        assert cls.from_bytes(raw).to_bytes()==raw
        for corrupt in (raw[:-1],raw+b"x",raw+raw):
            with pytest.raises(SerializationError): cls.from_bytes(corrupt)
    restored = o.MasterSecret.from_bytes(master.to_bytes())
    class NoRead:
        def read(self,_): raise AssertionError("restored issued key was resampled")
    assert a.Backend(rng=NoRead()).key_extract(restored,b"Alice").to_bytes()==key.to_bytes()
    code="from experiments.research.candidates.srgg.backend import Backend; from experiments.research.candidates.srgg.objects import SigningKey; import sys; k=SigningKey.from_bytes(bytes.fromhex(sys.stdin.read())); b=Backend(); s=b.sign(k,b'restarted'); assert b.verify(k.public_key,k.identity,b'restarted',s); print('ok')"
    run=subprocess.run([sys.executable,"-c",code],input=key.to_bytes().hex(),text=True,capture_output=True,env=os.environ.copy(),timeout=90)
    assert run.returncode==0,run.stderr
    assert run.stdout.strip()=="ok"


def test_input_context_and_wire_rejection(lifecycle):
    a,b,pk,master,key,sig=lifecycle
    for pos,bad in ((0,None),(1,b""),(1,"Alice"),(2,None),(3,None)):
        args=[pk,b"Alice",b"hello",sig]; args[pos]=bad
        assert b.verify(*args) is False
    with pytest.raises(EncodingError): b.sign(key,"bad")
    with pytest.raises(EncodingError): b.key_extract(master,b"")
    other_pk=replace(pk,config=replace(pk.config,message_max_bytes=pk.config.message_max_bytes+1))
    assert b.verify(other_pk,b"Alice",b"hello",sig) is False
    with pytest.raises(SerializationError): b.load_signature(other_pk,sig.to_bytes())
    assert b.load_signature(pk,sig.to_bytes())==sig
    too_big=replace(sig,z=tuple(tuple(pk.config.algebra.modulus for _ in poly) for poly in sig.z))
    assert b.verify(pk,b"Alice",b"hello",too_big) is False


def test_sampling_abort_marks_failed_identity_and_never_rerolls(lifecycle,monkeypatch):
    a,b,pk,master,key,sig=lifecycle
    from experiments.research.gaussian_reference import SamplingAbort
    runtime=importlib.import_module("experiments.research.candidates.srgg.runtime")
    calls=[]
    def fail(*args,**kwargs): calls.append(1); raise SamplingAbort("deliberate exhaustion")
    monkeypatch.setattr(runtime,"extract_tail",fail)
    with pytest.raises(SamplingAbort): b.key_extract(master,b"Failed")
    with pytest.raises(SamplingAbort): b.key_extract(master,b"Failed")
    assert len(calls)==1
    monkeypatch.setattr(runtime,"sign_attempt",fail)
    with pytest.raises(SamplingAbort): b.sign(key,b"abort")
    assert len(calls)==2


def test_shared_protocol_four_matching_cases(lifecycle):
    from ibme.hibe.mock import MockHIBE
    from ibme.lattice.params import EDUCATION_PARAMS
    from ibme.protocol.baseline import BaselineIBME,BOTTOM
    a,b,_,_,_,_=lifecycle
    protocol=BaselineIBME(MockHIBE(),b)
    pk,master=protocol.setup(replace(EDUCATION_PARAMS,max_message_bytes=8192),ibs_params=a.Config())
    sender=protocol.skgen(master,b"Alice"); receiver=protocol.rkgen(master,b"Bob")
    ct=protocol.encrypt(pk,sender,b"Bob",b"message")
    assert protocol.decrypt(pk,receiver,b"Alice",ct)==b"message"
    assert protocol.decrypt(pk,receiver,b"Eve",ct) is BOTTOM
    wrong=protocol.rkgen(master,b"Carol")
    assert protocol.decrypt(pk,wrong,b"Alice",ct) is BOTTOM
    assert protocol.decrypt(pk,wrong,b"Eve",ct) is BOTTOM


def test_full_audit_contains_actual_signatures_and_whitelist(lifecycle):
    try: audit=importlib.import_module("experiments.research.candidates.srgg.full_audit")
    except ModuleNotFoundError: pytest.fail("complete SRGG lifecycle audit is missing")
    from ibme.core.randomness import DeterministicRandom
    report=audit.audit_report(repetitions=2,rng=DeterministicRandom(b"srgg-full-audit"))
    assert report["honest_verified"]==2
    assert report["restored_key_verified"] is True
    assert report["restored_cache_same_key"] is True
    assert report["Q_gt_2gamma_exact"] is True
    assert report["full_IBS_implemented"] is True
    assert report["backend_admitted"] is False
    assert set(report)=={"schema","parameters","implementation","environment","samples","wire_bytes",
                         "timings_seconds","honest_verified","restored_key_verified","restored_cache_same_key",
                         "Q_gt_2gamma_exact","full_IBS_implemented","security_claim","backend_admitted","limitations"}
    assert "private_covariance" not in json.dumps(report)


def test_only_norm_rejection_retries_not_shape_errors(lifecycle,monkeypatch):
    a,b,pk,master,key,sig=lifecycle
    runtime=importlib.import_module("experiments.research.candidates.srgg.runtime")
    calls=[]
    def malformed(*args,**kwargs):
        calls.append(1)
        return ((0,)*pk.config.degree,),(0,)*pk.config.degree
    monkeypatch.setattr(runtime,"sign_attempt",malformed)
    with pytest.raises(RuntimeError): b.sign(key,b"malformed")
    assert len(calls)==1


def test_zero_response_fixed_point_is_public_negative_control(lifecycle):
    from itertools import product
    from experiments.research.candidates.srgg.algebra import recover_commitment
    from experiments.research.candidates.srgg.hashing import identity_target,message_challenge
    from experiments.research.candidates.srgg.objects import Signature
    a,b,pk,master,key,sig=lifecycle
    p=pk.config.algebra; zero=((0,)*p.degree,)*(p.columns+1)
    target=identity_target(pk,b"Unissued")
    forged=None
    for counter in range(16):
        msg=b"public-fixed-point:"+counter.to_bytes(2,"big")
        for c in product((0,1),repeat=p.degree):
            w=recover_commitment(pk.public,target,zero,c)
            if message_challenge(pk,w,msg)==c:
                forged=(msg,Signature(pk.context,zero,c)); break
        if forged: break
    assert forged is not None
    assert b"Unissued" not in master.states
    assert b.verify(pk,b"Unissued",forged[0],forged[1]) is True


def test_duplicate_fields_noncanonical_encoding_and_byte_view_budget(lifecycle):
    a,b,pk,master,key,sig=lifecycle
    o=importlib.import_module("experiments.research.candidates.srgg.objects")
    for obj,kind in ((pk,o.PublicKey),(master,o.MasterSecret),(key,o.SigningKey),(sig,o.Signature)):
        raw=obj.to_bytes(); header,payload=raw.split(b"\0",1); record=json.loads(payload)
        first=next(iter(record))
        duplicate=payload[:-1]+b',"'+first.encode()+b'":'+json.dumps(record[first]).encode()+b'}'
        for invalid in (header+b"\0"+duplicate,header+b"\0 "+payload):
            with pytest.raises(SerializationError): kind.from_bytes(invalid)
    data=o.PREFIX+b"SIG\0"+b" "*(o.MAX_WIRE+128)
    data+=b" "*((-len(data))%4)
    with pytest.raises(SerializationError): o.Signature.from_bytes(memoryview(data).cast("I"))
    view=memoryview(b"invalid"); view.release()
    with pytest.raises(SerializationError): o.Signature.from_bytes(view)


def test_algorithm7_norm_rejection_restarts_whole_attempt(lifecycle,monkeypatch):
    a,b,pk,master,key,sig=lifecycle
    runtime=importlib.import_module("experiments.research.candidates.srgg.runtime")
    real=runtime.sign_attempt; calls=[]
    def first_too_large(*args,**kwargs):
        calls.append(1)
        if len(calls)==1:
            return tuple((pk.config.algebra.modulus,)*pk.config.degree for _ in sig.z),sig.challenge
        return real(*args,**kwargs)
    monkeypatch.setattr(runtime,"sign_attempt",first_too_large)
    result=b.sign(key,b"norm-restart")
    assert len(calls)==2
    assert b.verify(pk,b"Alice",b"norm-restart",result)
