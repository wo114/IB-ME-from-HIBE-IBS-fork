"""Actual saved positive Setup and failed parent state, never regenerated.

Missing local private witnesses are explicit skips, not successful tests.
"""

import os
from pathlib import Path
import pytest

pytest.importorskip("sage.all",reason="prescribed WSL Sage required")
from ibme.hibe.abb_rom import ABBROMHIBE, ABBMasterSecret, ABBPublicKey, ABBSamplingAbort


def test_real_positive_master_failed_parent_is_restorable_without_reissue():
    folder=Path(os.environ.get("IBME_ABB_FAILED_PRIVATE_DIR",
        str(Path(__file__).resolve().parents[1]/"test-results/abb-hibe-positive-parent")))
    path=folder/"master-failed-private.bin"
    if not path.is_file():pytest.skip("actual positive-profile failed-parent master witness required")
    raw=path.read_bytes()
    master=ABBMasterSecret.from_bytes(raw)
    assert master.to_bytes()==raw
    assert master.public_key.params.dimension==1280
    assert master.public_key.params.q.bit_length()==160
    assert master.parents[b"Bob"] is None
    assert ABBPublicKey.from_bytes(master.public_key.to_bytes())==master.public_key

    class ForbiddenPrivateEntropy:
        calls=0
        def read(self,count):
            self.calls+=1
            raise AssertionError("actual failed address used private entropy")
    guard=ForbiddenPrivateEntropy()
    with pytest.raises(ABBSamplingAbort,match="already failed"):
        ABBROMHIBE().extract(master,b"Bob",rng=guard)
    assert guard.calls==0 and master.to_bytes()==raw
