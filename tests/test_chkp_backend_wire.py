"""CHKP codec/state tests on explicit algebra fixtures, not sampler evidence.

Private fixtures use publicly solvable bases and deterministic particular
solutions solely to test canonical object wire and state. Real GenTrap,
RandBasis, Gaussian sampling, and combination evidence use separate probes.
"""

from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.hibe.chkp import (CHKPParams, CHKPHIBE, CHKPPublicKey, CHKPMasterSecret,
    CHKPLevel1SecretKey, CHKPLevel2SecretKey, CHKPCiphertext, check_object, research_params)
from ibme.hibe.chkp.objects import _scope
from ibme.lattice.chkp.identity import ROHIBEContext
from ibme.lattice.chkp.seed_kem import SeedCapsule


def _public(p=None, offset=0):
    p = research_params() if p is None else p
    rows = tuple(tuple((int(i == j)+offset) % p.q for j in range(p.m)) for i in range(p.n))
    return CHKPPublicKey(p, ROHIBEContext(p.n, p.m, p.q, rows, p.to_bytes(), identity_bytes=p.identity_bytes))


def test_public_and_ciphertext_wire_are_self_contained_and_identity_free():
    public = _public()
    loaded = CHKPPublicKey.from_bytes(public.to_bytes())
    assert loaded.params == public.params and loaded.oracle.root_rows == public.oracle.root_rows
    assert loaded.context == public.context
    capsule = SeedCapsule(public.context, public.params.q, (0,)*381, (1,)*256)
    ct = CHKPCiphertext(capsule)
    assert CHKPHIBE().load_ciphertext(ct.to_bytes()).to_bytes() == ct.to_bytes()
    assert len(ct.to_bytes()) == 3919
    assert b"receiver" not in ct.to_bytes() and b"sender" not in ct.to_bytes()


@pytest.mark.parametrize("kind", ["public", "ciphertext"])
def test_public_wire_rejects_truncation_append_duplicate_and_unknown_version(kind):
    public = _public()
    obj = public if kind == "public" else CHKPCiphertext(SeedCapsule(public.context, public.params.q, (0,)*381, (1,)*256))
    raw = obj.to_bytes()
    bads = [raw[:i] for i in (0, 1, 15, len(raw)//2, len(raw)-1)]
    bads += [raw+b"\0", raw+raw, b"X"+raw[1:]]
    for bad in bads:
        with pytest.raises(SerializationError):
            type(obj).from_bytes(bad)


def test_same_parameter_different_A0_and_different_profile_are_distinct():
    a, b = _public(), _public(offset=1)
    assert a.params == b.params and a.context != b.context
    with pytest.raises(InvalidParameterError):
        CHKPPublicKey(replace(a.params, message_mode="framed32"), a.oracle)
    with pytest.raises(SerializationError):
        check_object(a, replace(a.params, lll_policy="none"))


def _algebra_private_fixture(mode="seed32"):
    pytest.importorskip("sage.all", reason="Sage algebra fixture; skip is not real sampling")
    from ibme.lattice.chkp.basis import ModMatrixReference, complete_kernel_basis
    from ibme.lattice.chkp.delegation_state import MasterTreeState
    p = CHKPParams(n=1, q=17, m_bar=1, r_width_squared=1,
        root_gs_squared_bound=1024, parent_width_squared=131072,
        leaf_width_squared=201326592, alpha_numerator=1, alpha_denominator=17,
        message_mode=mode, epsilon_bits=16, parent_max_vectors=44, lll_policy="none")
    public = _public(p)
    tree = MasterTreeState(_scope(public), complete_kernel_basis(ModMatrixReference(public.oracle.root_rows, p.q)))
    state = tree.issue(b"receiver", lambda plan: complete_kernel_basis(
        ModMatrixReference(public.oracle.parent_rows(plan.receiver), p.q)))
    def particular(plan):
        return tuple((target[0],)+(0,)*(p.leaf_dimension-1) for target in plan.seed_plan.targets)
    leaf = state.derive(b"sender", particular)
    return public, CHKPMasterSecret(public, tree), CHKPLevel1SecretKey(public, state), CHKPLevel2SecretKey(public, leaf)


@pytest.mark.parametrize("mode", ["seed32", "framed32"])
def test_private_objects_restore_without_sampling_and_preserve_full_integers(mode):
    public, master, parent, child = _algebra_private_fixture(mode)
    backend = CHKPHIBE()
    for obj in (master, parent, child):
        raw = obj.to_bytes()
        loaded = type(obj).from_bytes(raw)
        assert loaded.to_bytes() == raw
        assert backend.validate_key_binding(public, loaded) is True
        assert backend.validate_key_binding(_public(public.params, offset=1), loaded) is False
        assert "private" in repr(obj) and "basis_rows" not in repr(obj)
    restored = CHKPMasterSecret.from_bytes(master.to_bytes())
    p2 = backend.extract(restored, b"receiver", rng=object())
    k2 = backend.derive(p2, b"sender", rng=object())
    assert k2.to_bytes() == child.to_bytes()
    # q, which would become zero after accidental mod-q basis serialization,
    # is a real complete-kernel integer in this explicit public algebra fixture.
    assert any(abs(x) == public.params.q for row in restored.state.root_basis_for_research().basis_rows for x in row)


def test_private_wire_rejects_wrong_kind_truncation_duplicate_and_corruption():
    _, master, parent, child = _algebra_private_fixture()
    for obj in (master, parent, child):
        raw = obj.to_bytes()
        for bad in (raw[:-1], raw[:len(raw)//2], raw+b"\0", raw+raw, b"X"+raw[1:]):
            with pytest.raises(SerializationError):
                type(obj).from_bytes(bad)
    with pytest.raises(SerializationError):
        CHKPLevel1SecretKey.from_bytes(master.to_bytes())
    raw = child.to_bytes().replace(b"receiver", b"Receiver", 1)
    with pytest.raises(SerializationError):
        CHKPLevel2SecretKey.from_bytes(raw)


def test_failed_master_and_leaf_addresses_survive_private_wire():
    from ibme.lattice.chkp.leaf_state import SeedAddressBlocked
    public, master, parent, child = _algebra_private_fixture()
    from ibme.lattice.chkp.delegation_state import ParentAddressBlocked
    def fail(plan):
        raise RuntimeError("explicit fault injection")
    with pytest.raises(RuntimeError):
        master.state.issue(b"failed-parent", fail)
    with pytest.raises(RuntimeError):
        parent.state.derive(b"failed-child", fail)
    restored = CHKPMasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(ParentAddressBlocked):
        CHKPHIBE().extract(restored, b"failed-parent")
    reused = CHKPHIBE().extract(restored, b"receiver", rng=object())
    with pytest.raises(SeedAddressBlocked):
        CHKPHIBE().derive(reused, b"failed-child")


def test_backend_sampling_faults_block_addresses_before_any_retry():
    from ibme.core.errors import RandomnessError
    from ibme.lattice.chkp.leaf_state import SeedAddressBlocked
    _, master, parent, _ = _algebra_private_fixture()
    from ibme.lattice.chkp.delegation_state import ParentAddressBlocked
    class BrokenEntropy:
        def read(self, count):
            return b""
    backend = CHKPHIBE()
    with pytest.raises(RandomnessError):
        backend.extract(master, b"broken-parent", rng=BrokenEntropy())
    with pytest.raises(RandomnessError):
        backend.derive(parent, b"broken-child", rng=BrokenEntropy())
    restored = CHKPMasterSecret.from_bytes(master.to_bytes())
    with pytest.raises(ParentAddressBlocked):
        backend.extract(restored, b"broken-parent", rng=BrokenEntropy())
    reused = backend.extract(restored, b"receiver", rng=object())
    with pytest.raises(SeedAddressBlocked):
        backend.derive(reused, b"broken-child", rng=BrokenEntropy())


@pytest.mark.parametrize("payload", [b"", b"abc", bytes(range(28))])
def test_framed_route_encrypts_length_and_padding_with_raw_math_fixture(payload):
    public, _, _, child = _algebra_private_fixture("framed32")
    encoded = len(payload).to_bytes(4, "big")+payload+bytes(28-len(payload))
    bits = tuple((byte >> shift)&1 for byte in encoded for shift in range(7, -1, -1))
    ct = CHKPCiphertext(SeedCapsule(public.context, public.params.q,
        (0,)*public.params.leaf_dimension, tuple(bit*(public.params.q//2) for bit in bits)))
    assert CHKPHIBE().decrypt(child, ct) == payload
    other = replace(ct.capsule, context=bytes(64))
    assert CHKPHIBE().decrypt(child, CHKPCiphertext(other)) is None


def test_framed_raw_decode_rejects_invalid_length_and_padding():
    public, _, _, child = _algebra_private_fixture("framed32")
    for encoded in ((29).to_bytes(4, "big")+bytes(28), bytes(31)+b"\1"):
        bits = tuple((byte >> shift)&1 for byte in encoded for shift in range(7, -1, -1))
        ct = CHKPCiphertext(SeedCapsule(public.context, public.params.q,
            (0,)*public.params.leaf_dimension, tuple(bit*(public.params.q//2) for bit in bits)))
        assert CHKPHIBE().decrypt(child, ct) is None


def test_private_fresh_process_recovery_loads_no_generator_or_sampler(tmp_path):
    _, master, _, child = _algebra_private_fixture()
    snapshot = tmp_path/"private-master.bin"
    snapshot.write_bytes(master.to_bytes())
    expected = tmp_path/"private-leaf.bin"
    expected.write_bytes(child.to_bytes())
    code = """
from pathlib import Path
import sys
from ibme.hibe.chkp import CHKPHIBE, CHKPMasterSecret
key=CHKPMasterSecret.from_bytes(Path(sys.argv[1]).read_bytes())
backend=CHKPHIBE()
parent=backend.extract(key,b'receiver',rng=object())
child=backend.derive(parent,b'sender',rng=object())
assert child.to_bytes()==Path(sys.argv[2]).read_bytes()
assert 'ibme.lattice.chkp.root_generation' not in sys.modules
assert 'ibme.lattice.chkp.finite_gpv' not in sys.modules
print('fresh private restore, zero generation')
"""
    result = subprocess.run([sys.executable, "-c", code, str(snapshot), str(expected)],
                            capture_output=True, text=True, timeout=60, env=os.environ.copy())
    assert result.returncode == 0, result.stderr
    assert "zero generation" in result.stdout
