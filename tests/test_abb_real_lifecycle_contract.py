"""Contracts on a completed real ABB instance; never generate substitute keys.

Select its ignored directory with IBME_ABB_REAL_PRIVATE_DIR. A missing or still
running instance is an explicit skip. Expensive fixed-test-entropy 32 B replay
requires IBME_ABB_REAL_REPLAY=1; it uses saved real keys, not a public basis.
"""

import json
import os
from dataclasses import replace
from pathlib import Path
import pytest

pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from ibme.core.errors import SerializationError
from ibme.core.randomness import DeterministicRandom
from ibme.hibe.abb_rom import (ABBROMHIBE,ABBPublicKey,ABBMasterSecret,ABBLevel1Key,
    ABBLevel2Key,ABBCiphertext)
from ibme.hibe.abb_rom.registration import VERSION
from ibme.protocol.hybrid_hibe import HybridLimits,encoded_identity


class ForbiddenEntropy:
    def __init__(self):self.calls=0
    def read(self,count):
        self.calls+=1
        raise AssertionError('fixed restore/control attempted private sampling')


@pytest.fixture(scope='module')
def completed_real_instance():
    selected=os.environ.get('IBME_ABB_REAL_PRIVATE_DIR')
    if not selected:pytest.skip('explicit completed real ABB private directory required')
    folder=Path(selected)
    if not (folder/'completed').is_file() or not (folder/'receipt.json').is_file():
        pytest.skip('actual ABB run has not completed; no synthetic fallback')
    receipt=json.loads((folder/'receipt.json').read_text())
    assert receipt['status']=='passed' and receipt['full_HIBE_lifecycle'] is True
    assert receipt['source_unchanged_during_execution'] is True
    assert receipt['root_generations']==1 and receipt['payload_bytes']==32
    assert receipt['parent_identity_bytes']==receipt['child_identity_bytes']==86
    assert receipt['private_entropy_bytes']>0
    files=[('public.bin',ABBPublicKey),('master.bin',ABBMasterSecret),
        ('parent.bin',ABBLevel1Key),('leaf.bin',ABBLevel2Key),('ciphertext.bin',ABBCiphertext)]
    loaded=[]
    for name,decoder in files:
        raw=(folder/name).read_bytes()
        value=decoder.from_bytes(raw)
        assert value.to_bytes()==raw
        loaded.append(value)
    return tuple(loaded)+(receipt,)


def test_real_five_codecs_binding_and_fixed_tree_reuse(completed_real_instance):
    public,master,parent,leaf,ct,receipt=completed_real_instance
    backend=ABBROMHIBE();guard=ForbiddenEntropy()
    limits=HybridLimits(backend_id=VERSION.encode())
    rcv=encoded_identity(b'Bob',limits,b'P')
    phi=encoded_identity(b'Alice',limits,b'C')
    assert parent.identity==rcv and (leaf.parent_identity,leaf.child_identity)==(rcv,phi)
    for key in (master,parent,leaf):assert backend.validate_key_binding(public,key) is True
    reused=backend.extract(master,rcv,rng=guard)
    reused_leaf=backend.derive(reused,phi,rng=guard)
    assert reused.to_bytes()==parent.to_bytes() and reused_leaf.to_bytes()==leaf.to_bytes()
    assert guard.calls==0
    assert ct.payload_bytes==32 and ct.params==public.params and ct.context==public.context


def test_real_context_and_wire_controls_reject_before_private_entropy(completed_real_instance):
    public,master,parent,leaf,ct,receipt=completed_real_instance
    backend=ABBROMHIBE();guard=ForbiddenEntropy()
    changed=bytes([ct.context[0]^1])+ct.context[1:]
    assert backend.decrypt(leaf,replace(ct,context=changed),rng=guard) is None
    assert backend.decrypt(leaf,object(),rng=guard) is None
    assert guard.calls==0
    raw=ct.to_bytes()
    for invalid in (raw[:-1],raw+b'x',raw+raw,bytes([raw[0]^1])+raw[1:]):
        with pytest.raises(SerializationError):backend.load_ciphertext(invalid)
    # Different advertised public key is rejected, without creating any key.
    altered=tuple(tuple((x+1)%public.params.q if i==j==0 else x for j,x in enumerate(row))
        for i,row in enumerate(public.a))
    other=ABBPublicKey(public.params,altered,public.u0)
    assert backend.validate_key_binding(other,leaf) is False
    # Raw CPA coefficient tolerance is tested separately; these are framing/
    # context controls, not a claim that every raw byte change is rejected.


def test_saved_real_keys_fixed_test_entropy_32B_encrypt_and_fresh_decrypt(completed_real_instance):
    if os.environ.get('IBME_ABB_REAL_REPLAY')!='1':
        pytest.skip('explicit expensive full32B fixed-test-entropy replay required')
    public,master,parent,leaf,ct,receipt=completed_real_instance
    backend=ABBROMHIBE()
    payload=bytes([0,255,128,1])*8
    first=backend.encrypt(public,parent.identity,leaf.child_identity,payload,
        rng=DeterministicRandom(b'ABB-real-saved-key-encrypt-fixed32'))
    repeated=backend.encrypt(public,parent.identity,leaf.child_identity,payload,
        rng=DeterministicRandom(b'ABB-real-saved-key-encrypt-fixed32'))
    assert first.to_bytes()==repeated.to_bytes()
    assert backend.decrypt(leaf,first,rng=DeterministicRandom(b'ABB-real-saved-key-decrypt-fixed32'))==payload
    # Both operations use explicitly marked test entropy; original true-system
    # 32 B lifecycle evidence belongs to the completed probe receipt.
