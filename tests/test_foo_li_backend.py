"""Actual Foo--Li primitive, exact reference differential, and boundary evidence."""
from dataclasses import asdict, replace
import json
from pathlib import Path
import subprocess
import sys

import pytest
pytest.importorskip("sage.all", reason="Use WSL ~/miniconda3/envs/sage")

from ibme.core.errors import EncodingError, RandomnessError, SerializationError
from ibme.core.hashing import hash_identity
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.api import IBSBackend, IBSPublicKey, IBSMasterSecret, IBSSigningKey, IBSSignature, IBSError
from ibme.ibs.foo_li import (FooLiIBS, FooLiParams, PublicKey, MasterSecret, SigningKey,
                             Signature, FooLiSamplingAbort, IssuancePending)
from ibme.ibs.foo_li import codec
from ibme.ibs.foo_li.registration import backend_spec, signature_size
from experiments.research.foo_li_runtime_reference import ResearchSession, DOMAINS
from experiments.research.gaussian_reference import SamplingAbort


class NoEntropy:
    def read(self, count):
        raise AssertionError("unexpected fresh entropy")


@pytest.fixture(scope="module")
def root():
    backend = FooLiIBS(DeterministicRandom(b"runtime-master-0"), epoch=b"test-epoch")
    return backend.setup(FooLiParams())[1].to_bytes()


@pytest.fixture(scope="module")
def issued(root):
    master = MasterSecret.from_bytes(root)
    key = FooLiIBS(DeterministicRandom(b"runtime-user-Alice")).key_extract(master, b"Alice")
    return master.to_bytes(), key.to_bytes()


@pytest.fixture
def master(root): return MasterSecret.from_bytes(root)


@pytest.fixture(scope="module")
def key(issued): return SigningKey.from_bytes(issued[1])


def test_five_methods_and_four_base_objects(master, key):
    b = FooLiIBS(NoEntropy())
    sig = b.sign(key, b"hello")
    assert isinstance(b, IBSBackend)
    assert isinstance(master, IBSMasterSecret) and isinstance(master.public_key, IBSPublicKey)
    assert isinstance(key, IBSSigningKey) and isinstance(sig, IBSSignature)
    assert key.identity_digest == hash_identity(b"Alice", 32)
    assert b.load_signature(key.public_key, sig.to_bytes()) == sig
    assert b.verify(PublicKey.from_bytes(key.public_key.to_bytes()), b"Alice", b"hello", sig)
    assert b.security_claim == "none" and not b.backend_admitted and not b.parameters_are_formal


@pytest.mark.parametrize("message", [b"", b"hello", b"second", b"a\0b", bytes(range(256)), b"m"*4096])
def test_exact_reference_differential_and_repeated_signatures(issued, key, message):
    _, reference, _ = codec.decode(issued[0], codec.MSK_MAGIC, 3)
    session = ResearchSession.restore(reference)
    expected = session.sign_raw(key.identity, message)
    assert expected.status == "ok"
    b = FooLiIBS(NoEntropy())
    first, second = b.sign(key, message), b.sign(SigningKey.from_bytes(key.to_bytes()), message)
    assert first.raw == expected.value == second.raw
    assert b.verify(key.public_key, key.identity, message, first)


def test_extraction_differential_and_cached_no_entropy(master):
    reference = ResearchSession.restore(master._session.dump_secret_state())
    expected = reference.extract(b"Alice", seed_rng=DeterministicRandom(b"runtime-user-Alice"))
    actual = FooLiIBS(DeterministicRandom(b"runtime-user-Alice")).key_extract(master, b"Alice")
    assert expected.status == "ok"
    assert actual.trapdoor == tuple(int(x) for x in expected.value.trapdoor.list())
    assert actual.bit == expected.value.bit and actual.seed == expected.value.seed
    recovered = MasterSecret.from_bytes(master.to_bytes())
    assert FooLiIBS(NoEntropy()).key_extract(master, b"Alice") == actual
    assert FooLiIBS(NoEntropy()).key_extract(recovered, b"Alice") == actual


@pytest.mark.parametrize("kind", ["pk", "msk", "sk", "sig"])
@pytest.mark.parametrize("mutation", ["truncate", "append", "repeat", "version", "length", "wrongtype"])
def test_strict_objects_reject_bad_framing(issued, key, kind, mutation):
    values = {"pk": (key.public_key.to_bytes(), PublicKey.from_bytes, codec.PK_MAGIC),
              "msk": (issued[0], MasterSecret.from_bytes, codec.MSK_MAGIC),
              "sk": (key.to_bytes(), SigningKey.from_bytes, codec.SK_MAGIC),
              "sig": (Signature(key.public_key.context, (0,)*5, 0).to_bytes(), Signature.from_bytes, codec.SIG_MAGIC)}
    raw, load, magic = values[kind]
    invalid = {"truncate": raw[:-1], "append": raw+b"x", "repeat": raw+raw[len(magic):],
               "version": b"X"+raw[1:], "length": raw[:len(magic)+1]+b"\xff"*4+raw[len(magic)+5:],
               "wrongtype": "not bytes"}[mutation]
    with pytest.raises(SerializationError): load(invalid)


@pytest.mark.parametrize("mutation", ["extra", "missing", "bool", "float", "epsilon", "nested"])
def test_public_snapshot_parameter_validation(key, mutation):
    config, epoch, values = codec.decode(key.public_key.to_bytes(), codec.PK_MAGIC, 3)
    record = json.loads(config)
    if mutation == "extra": record["unknown"] = 1
    if mutation == "missing": record.pop("max_users")
    if mutation == "bool": record["n"] = True
    if mutation == "float": record["q"] = 3.0
    if mutation == "epsilon": record["epsilon0"] = "2/131072"
    if mutation == "nested": record["q"] = []
    with pytest.raises(SerializationError):
        PublicKey.from_bytes(codec.encode(codec.PK_MAGIC, codec.canonical(record), epoch, values))


@pytest.mark.parametrize("mutation", ["unknown", "duplicate", "no-issued", "pending-with-key", "public"])
def test_master_state_consistency(issued, mutation):
    public, secret, states = codec.decode(issued[0], codec.MSK_MAGIC, 3)
    values = json.loads(states)
    if mutation == "unknown": values[0][1] = "automatic-retry"
    if mutation == "duplicate": values += values
    if mutation == "no-issued": values = []
    if mutation == "pending-with-key": values[0][1] = "pending"
    if mutation == "public":
        pk = PublicKey.from_bytes(public)
        public = replace(pk, epoch=b"another").to_bytes()
    with pytest.raises(SerializationError):
        MasterSecret.from_bytes(codec.encode(codec.MSK_MAGIC, public, secret, codec.canonical(values)))


def test_secret_repr_and_signing_key_has_no_master_secrets(master, key):
    assert key.seed.hex() not in repr(key) and master._session.k1.hex() not in repr(master)
    assert not hasattr(key, "k1") and not hasattr(key, "k2") and not hasattr(key, "_session")
    assert not hasattr(key.public_key, "seed")


@pytest.mark.parametrize("mutation", ["identity", "branch", "trapdoor", "seed", "public"])
def test_signing_key_checks(key, mutation):
    public, identity, bit, trapdoor, seed = codec.decode(key.to_bytes(), codec.SK_MAGIC, 5)
    if mutation == "identity": identity = b""
    if mutation == "branch": bit = b"\x02"
    if mutation == "trapdoor": trapdoor = (2**62).to_bytes(8, "big", signed=True)+trapdoor[8:]
    if mutation == "seed": seed = seed[:-1]
    if mutation == "public":
        p = PublicKey.from_bytes(public)
        public = replace(p, params=replace(p.params, max_users=17)).to_bytes()
    with pytest.raises(SerializationError):
        SigningKey.from_bytes(codec.encode(codec.SK_MAGIC, public, identity, bit, trapdoor, seed))


@pytest.mark.parametrize("bad", [b"", "Alice", 3, None, b"x"*257])
def test_invalid_id_inputs(master, key, bad):
    b = FooLiIBS(NoEntropy())
    with pytest.raises(EncodingError): b.key_extract(master, bad)
    assert not b.verify(key.public_key, bad, b"", b.sign(key, b""))


@pytest.mark.parametrize("bad", ["message", None, 3, b"x"*4097])
def test_invalid_message_inputs(key, bad):
    b = FooLiIBS(NoEntropy())
    with pytest.raises(EncodingError): b.sign(key, bad)
    assert not b.verify(key.public_key, key.identity, bad, b.sign(key, b""))


def test_signature_norm_context_dimensions_and_no_zero_filter(key, monkeypatch):
    b, pk = FooLiIBS(NoEntropy()), key.public_key
    for sig in [Signature(bytes(32), (0,)*5, 0), Signature(pk.context, (0,)*4, 0),
                Signature(pk.context, (10**8, 0, 0, 0, 0), 0)]:
        assert not b.verify(pk, key.identity, b"", sig)
        with pytest.raises(SerializationError): b.load_signature(pk, sig.to_bytes())
    # Raw zero is allowed by the paper whenever the syndrome is zero.
    message = next(str(i).encode() for i in range(30) if pk._verifier.syndrome(key.identity, str(i).encode()) == (0,))
    monkeypatch.setattr(key._sampler, "sample_from_tape", lambda *_: (0,)*5)
    assert b.sign(key, message).vector == (0,)*5


def test_norm_failure_is_one_shot_abort(key, monkeypatch):
    calls = []
    def too_large(*_): calls.append(1); return (10**8, 0, 0, 0, 0)
    monkeypatch.setattr(key._sampler, "sample_from_tape", too_large)
    with pytest.raises(FooLiSamplingAbort, match="norm_rejected"):
        FooLiIBS(NoEntropy()).sign(key, b"sample")
    assert calls == [1]


def test_sampling_abort_and_programmer_error_not_swallowed(key, monkeypatch):
    def abort(*_): raise SamplingAbort("test")
    monkeypatch.setattr(key._sampler, "sample_from_tape", abort)
    with pytest.raises(FooLiSamplingAbort): FooLiIBS(NoEntropy()).sign(key, b"sample")
    def broken(*_): raise RuntimeError("software fault")
    monkeypatch.setattr(key._sampler, "sample_from_tape", broken)
    with pytest.raises(RuntimeError, match="software fault"):
        FooLiIBS(NoEntropy()).sign(key, b"sample")


@pytest.mark.parametrize("stage", ["before", "after", "entropy", "interrupt"])
def test_issuance_failure_tombstone_survives_recovery(master, stage):
    snapshots = []
    def save(msk):
        snapshots.append(msk.to_bytes())
        if stage == "before" and len(snapshots) == 1: raise OSError("save failure")
        if stage == "after" and len(snapshots) == 2: raise OSError("save failure")
        if stage == "interrupt": raise KeyboardInterrupt()
    class Broken:
        def read(self, n): return b""  # must be an entropy error, not a default key
    master.persist_callback = save
    rng = Broken() if stage == "entropy" else DeterministicRandom(b"runtime-user-Alice")
    with pytest.raises((OSError, RandomnessError, KeyboardInterrupt)):
        FooLiIBS(rng).key_extract(master, b"Alice")
    for recovered in [master, MasterSecret.from_bytes(master.to_bytes()), MasterSecret.from_bytes(snapshots[0])]:
        with pytest.raises(IssuancePending): FooLiIBS(NoEntropy()).key_extract(recovered, b"Alice")


def test_public_toy_forgery_and_wrong_message_counterexample_are_retained(key):
    b, pk = FooLiIBS(NoEntropy()), key.public_key
    # q=3: public column inversion yields a tiny signature without any key.
    identity, message, bit = b"Unissued", b"forged", 0
    f = pk._verifier.public.augment(pk._verifier.identity_matrix(identity, bit))
    target = pk._verifier.syndrome(identity, message)[0]
    column = next(i for i in range(pk.params.dimension) if int(f[0, i]) % 3)
    z = [0]*pk.params.dimension
    z[column] = target*pow(int(f[0, column]), -1, 3) % 3
    assert b.verify(pk, identity, message, Signature(pk.context, tuple(z), bit))
    original = b.sign(key, b"known")
    collision = next(str(i).encode() for i in range(60)
                     if b.verify(pk, key.identity, str(i).encode(), original))
    assert collision != b"known"  # functional toy weakness, never hidden as a skip


def test_descriptor_snapshot_and_sizes(key):
    from ibme.assembly.registry import BackendRegistry
    spec = backend_spec()
    assert BackendRegistry([spec]).get("ibs", "foo-li") is spec
    assert spec.parse_params(asdict(key.params)) == key.params
    assert signature_size(key.params, "reference") == len(FooLiIBS(NoEntropy()).sign(key, b"size").to_bytes()) == 104
    spec.check_object(key, key.params)
    with pytest.raises(SerializationError): spec.check_object(key, replace(key.params, max_users=17))


def test_second_dimension_profile_and_capacity():
    params = FooLiParams(n=2, user_quality=11340, max_users=1)
    backend = FooLiIBS(DeterministicRandom(b"FooLi-n2"), epoch=b"dimension-check")
    pk, master = backend.setup(params)
    key = backend.key_extract(master, b"A")
    sig = backend.sign(key, b"two rows")
    assert len(sig.vector) == 9 and backend.verify(pk, b"A", b"two rows", sig)
    assert PublicKey.from_bytes(pk.to_bytes()) == pk
    assert SigningKey.from_bytes(key.to_bytes()) == key
    assert MasterSecret.from_bytes(master.to_bytes()) == master
    with pytest.raises(EncodingError, match="capacity"):
        FooLiIBS(NoEntropy()).key_extract(master, b"B")
    assert FooLiIBS(NoEntropy()).key_extract(master, b"A") == key


def test_wrong_sampler_equation_is_a_software_error(key, monkeypatch):
    message = next(str(i).encode() for i in range(60)
                   if key.public_key._verifier.syndrome(key.identity, str(i).encode()) != (0,))
    monkeypatch.setattr(key._sampler, "sample_from_tape", lambda *_: (0,)*5)
    with pytest.raises(IBSError, match="equation"):
        FooLiIBS(NoEntropy()).sign(key, message)


def test_setup_failure_never_retries_and_checks_before_entropy():
    class AllFF:
        def __init__(self): self.calls = 0
        def read(self, n): self.calls += 1; return b"\xff"*n
    random = AllFF()
    with pytest.raises(FooLiSamplingAbort, match="setup_sampling_abort"):
        FooLiIBS(random, epoch=b"fixed").setup(FooLiParams())
    assert random.calls == 1
    with pytest.raises(ValueError):
        FooLiIBS(NoEntropy()).setup(FooLiParams(max_tape_bytes=1))


@pytest.mark.parametrize("text", ["1e-1000000000", "0.1", "1_0/40", "01/4", "-1/4", "1/0", "1/"+"9"*3000])
def test_rational_lexical_budget_precedes_fraction_construction(text, monkeypatch):
    from ibme.ibs.foo_li import params as module
    def forbidden(*args): raise AssertionError("unbounded input reached Fraction")
    monkeypatch.setattr(module, "Fraction", forbidden)
    with pytest.raises(ValueError): FooLiParams(epsilon0=text)


@pytest.mark.parametrize("mutation", ["wide-root", "root-range", "root-bool", "user-shape", "user-count", "duplicate-user", "ledger", "epoch"])
def test_bad_snapshot_rejected_before_research_matrix_restore(issued, mutation, monkeypatch):
    public, secret, states = codec.decode(issued[0], codec.MSK_MAGIC, 3)
    record, ledger = json.loads(secret), json.loads(states)
    if mutation == "wide-root":
        record["base"] = [[0]*64]
        record["R0"] = [[0, 0] for _ in range(64)]
    if mutation == "root-range": record["R0"][0][0] = 10**100
    if mutation == "root-bool": record["R0"][0][0] = True
    if mutation == "user-shape": record["users"][0]["T"] *= 20
    if mutation == "user-count": record["users"] *= 17
    if mutation == "duplicate-user": record["users"] *= 2
    if mutation == "ledger": ledger = []
    if mutation == "epoch": record["epoch"] = "00"*257
    def forbidden(*args, **kwargs): raise AssertionError("bad snapshot reached matrix engine")
    monkeypatch.setattr(ResearchSession, "restore", forbidden)
    with pytest.raises(SerializationError):
        MasterSecret.from_bytes(codec.encode(codec.MSK_MAGIC, public, codec.canonical(record), codec.canonical(ledger)))


def test_public_verification_and_signing_in_fresh_process(issued, key, tmp_path):
    message = b"fresh-process"
    sig = FooLiIBS(NoEntropy()).sign(key, message)
    for name, value in [("pk", key.public_key.to_bytes()), ("sk", key.to_bytes()), ("sig", sig.to_bytes())]:
        (tmp_path/name).write_bytes(value)
    code = '''
from pathlib import Path
import sys
from ibme.ibs.foo_li import FooLiIBS, PublicKey, SigningKey
class NoEntropy:
    def read(self, n): raise AssertionError("fresh entropy forbidden")
p=Path(sys.argv[1]); b=FooLiIBS(NoEntropy())
pk=PublicKey.from_bytes((p/"pk").read_bytes())
sig=b.load_signature(pk,(p/"sig").read_bytes())
assert b.verify(pk,b"Alice",b"fresh-process",sig)
sk=SigningKey.from_bytes((p/"sk").read_bytes())
assert b.sign(sk,b"fresh-process")==sig
print("public verify and independent restored signing passed")
'''
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path)], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr
    assert "passed" in result.stdout
