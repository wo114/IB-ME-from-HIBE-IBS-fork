"""No actual combination is admitted from missing or partial ABB evidence."""
import json
import pytest
pytest.importorskip('sage.all',reason='prescribed WSL Sage required')
from experiments.research.abb_rom.saved_combo_probe import require_completed


def test_missing_instance_is_an_error_not_a_substitute(tmp_path):
    with pytest.raises(ValueError,match='completed actual'):
        require_completed(tmp_path)


@pytest.mark.parametrize('field,value',[
    ('status','failed'),('full_HIBE_lifecycle',False),('source_unchanged_during_execution',False),
    ('root_generations',2),('payload_bytes',1),('parent_identity_bytes',5),('child_identity_bytes',5)])
def test_partial_or_changed_evidence_cannot_authorize_combination(tmp_path,field,value):
    (tmp_path/'completed').touch()
    record=dict(status='passed',full_HIBE_lifecycle=True,source_unchanged_during_execution=True,
                root_generations=1,payload_bytes=32,parent_identity_bytes=86,child_identity_bytes=86)
    record[field]=value
    (tmp_path/'receipt.json').write_text(json.dumps(record))
    with pytest.raises(ValueError,match='acceptance precondition'):
        require_completed(tmp_path)
