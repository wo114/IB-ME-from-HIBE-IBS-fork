"""Independent boundary review with tiny publicly computable algebra fixtures.

No GenTrap/RandBasis/GPV sample or security parameter is claimed by these keys.
The private-object checks require prescribed Sage for exact complete bases.
"""

from dataclasses import replace

import pytest

from ibme.core.encoding import encode_bytes
from ibme.core.errors import InvalidParameterError, SerializationError
from ibme.hibe.chkp import (CHKPParams, CHKPHIBE, CHKPPublicKey, CHKPMasterSecret,
    CHKPLevel1SecretKey, CHKPLevel2SecretKey, CHKPCiphertext, research_params)
from ibme.hibe.chkp.objects import MAGIC, _scope
from ibme.lattice.chkp.identity import ROHIBEContext
from ibme.lattice.chkp.seed_kem import SeedCapsule


def test_public_object_rejects_parameter_mode_and_root_relabeling():
    p = research_params()
    rows = tuple(tuple(int(i == j) for j in range(p.m)) for i in range(p.n))
    oracle = ROHIBEContext(p.n, p.m, p.q, rows, p.to_bytes())
    public = CHKPPublicKey(p, oracle)
    assert CHKPPublicKey.from_bytes(public.to_bytes()).to_bytes() == public.to_bytes()
    with pytest.raises(InvalidParameterError):
        CHKPPublicKey(replace(p, message_mode="framed32"), oracle)
    foreign = replace(oracle, root_rows=(tuple([2] + list(rows[0][1:])), rows[1]))
    assert CHKPPublicKey(p, foreign).context != public.context
    for data in (public.to_bytes()[:-1], public.to_bytes() + b"\0", public.to_bytes() * 2):
        with pytest.raises(SerializationError):
            CHKPPublicKey.from_bytes(data)


@pytest.fixture
def algebra():
    pytest.importorskip("sage.all", reason="Exact tiny private basis checks require prescribed WSL Sage")
    from ibme.lattice.chkp.basis import ModMatrixReference, complete_kernel_basis
    from ibme.lattice.chkp.delegation_state import MasterTreeState

    def create(mode="seed32"):
        p = CHKPParams(n=1, q=17, m_bar=1, r_width_squared=1,
            root_gs_squared_bound=289, parent_width_squared=2**20,
            leaf_width_squared=2**36, alpha_numerator=1, alpha_denominator=17,
            message_mode=mode, epsilon_bits=16, regularity_bits=8,
            parent_max_vectors=20, max_dimension=32)
        o = ROHIBEContext(p.n, p.m, p.q, ((1,) + (0,)*(p.m-1),), p.to_bytes())
        public = CHKPPublicKey(p, o)
        scope = _scope(public)
        tree = MasterTreeState(scope, complete_kernel_basis(ModMatrixReference(o.root_rows, p.q)))
        def parent(plan):
            return complete_kernel_basis(ModMatrixReference(o.parent_rows(plan.receiver), p.q))
        receiver = tree.issue(b"Bob", parent)
        def leaf(plan):
            seed = plan.seed_plan
            return tuple((target[0],) + (0,)*(seed.dimension-1) for target in seed.targets)
        key = receiver.derive(b"Alice", leaf)
        return (public, CHKPMasterSecret(public, tree), CHKPLevel1SecretKey(public, receiver),
                CHKPLevel2SecretKey(public, key), parent, leaf)
    return create


def capsule_for(leaf, encoded):
    """Explicit zero-noise algebra control, not encapsulate_seed or Gaussian."""
    oracle, plan = leaf.public_key.oracle, leaf.key.plan
    bits = [(byte >> shift) & 1 for byte in encoded for shift in range(7, -1, -1)]
    r = 3
    preamble = tuple(a * r % oracle.q for a in plan.public_rows[0])
    terminals = tuple((target[0] * r + bit * (oracle.q // 2)) % oracle.q
                      for target, bit in zip(plan.targets, bits))
    return CHKPCiphertext(SeedCapsule(oracle.context, oracle.q, preamble, terminals))


def test_all_private_objects_restore_reuse_and_bind_without_entropy(algebra):
    public, master, parent, leaf, _, _ = algebra()
    backend = CHKPHIBE()
    def forbidden(*args, **kwargs):
        pytest.fail("restored fixed address tried to sample")
    class NoEntropy:
        read = forbidden
    restored = []
    for obj in (master, parent, leaf):
        raw = obj.to_bytes()
        value = type(obj).from_bytes(raw)
        assert value.to_bytes() == raw
        assert backend.validate_key_binding(public, value) is True
        restored.append(value)
        for invalid in (raw[:-1], raw + b"\0", raw + raw):
            with pytest.raises(SerializationError):
                type(obj).from_bytes(invalid)
    assert backend.extract(restored[0], b"Bob", rng=NoEntropy()).to_bytes() == parent.to_bytes()
    assert backend.derive(restored[1], b"Alice", rng=NoEntropy()).to_bytes() == leaf.to_bytes()
    seed = bytes(range(32))
    assert backend.decrypt(restored[2], CHKPCiphertext.from_bytes(capsule_for(leaf, seed).to_bytes()),
                           rng=NoEntropy()) == seed


def test_leaf_outer_identity_replacement_and_foreign_public_are_rejected(algebra):
    public, _, _, leaf, _, _ = algebra()
    from ibme.hibe.chkp.objects import _single_leaf_snapshot
    def frame(parent, child):
        return MAGIC + encode_bytes(b"LEVEL2") + b"".join(encode_bytes(value) for value in
            (public.to_bytes(), parent, child, _single_leaf_snapshot(leaf.key)))
    for parent, child in ((b"Carol", b"Alice"), (b"Bob", b"Mallory")):
        with pytest.raises(SerializationError):
            CHKPLevel2SecretKey.from_bytes(frame(parent, child))
    foreign_oracle = replace(public.oracle, root_rows=((2,) + (0,)*(public.params.m-1),))
    foreign = CHKPPublicKey(public.params, foreign_oracle)
    assert CHKPHIBE().validate_key_binding(foreign, leaf) is False
    with pytest.raises(InvalidParameterError):
        CHKPLevel2SecretKey(foreign, leaf.key)


def test_failed_parent_and_leaf_remain_blocked_after_backend_object_reload(algebra):
    from ibme.lattice.chkp.delegation_state import ParentAddressBlocked
    from ibme.lattice.chkp.leaf_state import SeedAddressBlocked
    _, master, parent, _, _, _ = algebra()
    def fail(plan):
        raise RuntimeError("controlled failure")
    with pytest.raises(RuntimeError):
        master.state.issue(b"Carol", fail)
    with pytest.raises(RuntimeError):
        parent.state.derive(b"Mallory", fail)
    restored_master = CHKPMasterSecret.from_bytes(master.to_bytes())
    restored_parent = CHKPLevel1SecretKey.from_bytes(parent.to_bytes())
    # An invalid RNG is intentional: lookup must reject a stored failure before
    # considering sampler construction or requiring a functioning RNG.
    with pytest.raises(ParentAddressBlocked):
        CHKPHIBE().extract(restored_master, b"Carol", rng=object())
    with pytest.raises(SeedAddressBlocked):
        CHKPHIBE().derive(restored_parent, b"Mallory", rng=object())


@pytest.mark.parametrize("payload", [b"", bytes(range(28))])
def test_framed32_roundtrip_and_noncanonical_padding_rejection(algebra, payload):
    _, _, _, leaf, _, _ = algebra("framed32")
    encoded = len(payload).to_bytes(4, "big") + payload + bytes(28-len(payload))
    assert CHKPHIBE().decrypt(leaf, capsule_for(leaf, encoded)) == payload
    bad_length = (29).to_bytes(4, "big") + bytes(28)
    assert CHKPHIBE().decrypt(leaf, capsule_for(leaf, bad_length)) is None
    bad_padding = bytes(31) + b"\1"
    assert CHKPHIBE().decrypt(leaf, capsule_for(leaf, bad_padding)) is None
