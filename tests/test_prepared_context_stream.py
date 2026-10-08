"""Prepared real-SHAKE candidate agrees with the frozen reference lifecycle."""

import pytest
pytest.importorskip("sage.all", reason="Use prescribed WSL Sage environment")
from ibme.core.randomness import DeterministicRandom
from experiments.research.foo_li_runtime_reference import (
    AddressStream, DOMAINS, ResearchConfig, ResearchSession, ShakeOracleCandidate, framed,
)
from experiments.research.online_gaussian_reference import OnlineOptions
from experiments.research.gaussian_reference import SamplingAbort
from experiments.research.prepared_context_stream import (
    PreparedAddressStream, PreparedShakeOracleCandidate,
)


@pytest.mark.parametrize("context_bytes",[0,17,65537,1024*1024])
def test_blocks_and_arbitrary_reads_agree(context_bytes):
    address=framed(b"v",b"hibe-public"+b"h"*context_bytes,b"ibs-public",b"sender",b"message")
    total=3*AddressStream.BLOCK+9
    a,b=AddressStream(address,total),PreparedAddressStream(address,total)
    for count in [0,1,AddressStream.BLOCK-1,7,AddressStream.BLOCK+3,total-(2*AddressStream.BLOCK+10)]:
        assert a.read(count)==b.read(count)
    assert a.remaining==b.remaining==0
    with pytest.raises(SamplingAbort):b.read(1)


def test_every_domain_and_both_public_contexts_are_bound():
    old,new=ShakeOracleCandidate(),PreparedShakeOracleCandidate()
    context=framed(b"HIBE-PK",b"IBS-PK")
    values=[]
    for domain in DOMAINS:
        a=old.stream(domain,context,(b"user",b"message"),33).read(33)
        assert a==new.stream(domain,context,(b"user",b"message"),33).read(33)
        assert a!=new.stream(domain,framed(b"HIBE-PK2",b"IBS-PK"),(b"user",b"message"),33).read(33)
        assert a!=new.stream(domain,framed(b"HIBE-PK",b"IBS-PK2"),(b"user",b"message"),33).read(33)
        values.append(a)
    assert len(set(values))==len(DOMAINS)


def test_real_lifecycle_and_restore_unchanged():
    cfg=ResearchConfig(options=OnlineOptions(tail_bits=24,mass_bits=64,
        precision_bits=128,gaussian_abort_bits=24,max_uniform_trials=64))
    a=ResearchSession.setup(cfg,b"epoch",rng=DeterministicRandom(b"prepared-master"))
    b=ResearchSession.setup(cfg,b"epoch",rng=DeterministicRandom(b"prepared-master"),oracle=PreparedShakeOracleCandidate())
    assert a.status==b.status=="ok"
    a,b=a.value,b.value
    for session in [a,b]:
        assert session.extract(b"Alice",seed_rng=DeterministicRandom(b"prepared-user")).status=="ok"
    assert a.dump_secret_state()==b.dump_secret_state()
    for message in [b"",b"message",b"message"]:
        sa,sb=a.sign_raw(b"Alice",message),b.sign_raw(b"Alice",message)
        assert sa.status==sb.status=="ok" and sa.value==sb.value
        assert b.verify(b"Alice",message,sb.value)
    restored=ResearchSession.restore(b.dump_secret_state(),oracle=PreparedShakeOracleCandidate())
    assert restored.sign_raw(b"Alice",b"message").value==a.sign_raw(b"Alice",b"message").value


def test_public_budget_failure_and_immutable_address():
    with pytest.raises(ValueError):PreparedAddressStream(bytearray(b"x"),1)
    with pytest.raises(ValueError):PreparedAddressStream(b"x",True)
    with pytest.raises(ValueError):PreparedShakeOracleCandidate().stream(b"unknown",b"",(),1)
    a=PreparedAddressStream(b"x",0)
    assert a.read(0)==b""
    with pytest.raises(SamplingAbort):a.read(1)
