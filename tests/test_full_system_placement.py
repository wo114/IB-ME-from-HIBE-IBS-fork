"""Receipt validation handles the repository's compatibility import aliases."""
import copy

import pytest

from experiments.research.full_system_placement import verify_generation_providers


def test_alias_checks_actual_provider_and_rejects_changed_code():
    expected = {"ibme/lattice/chkp/basis.py": "abc"}
    generation = dict(status="passed", repetitions=3, identity_bytes=64, message_bytes=32,
        records=[dict(generation=dict(status="passed", source_providers={
            "experiments.research.chkp_basis": dict(path="/cache/runtime/ibme/lattice/chkp/basis.py", sha256="abc")}),
            restore=dict(status="passed"))])
    generation["records"] = [copy.deepcopy(generation["records"][0]) for _ in range(3)]
    verify_generation_providers(generation, expected)
    changed = copy.deepcopy(generation)
    changed["records"][0]["generation"]["source_providers"]["experiments.research.chkp_basis"]["sha256"] = "different"
    with pytest.raises(ValueError, match="provider differs"):
        verify_generation_providers(changed, expected)
    changed = copy.deepcopy(generation)
    changed["records"][0]["restore"]["status"] = "failed"
    with pytest.raises(ValueError, match="failed/partial"):
        verify_generation_providers(changed, expected)
