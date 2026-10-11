"""Independent private qFALL basis conversion; supplies no entropy/grade.

Uses the existing private engine schema and independent mathematical parser.
No change to GenTrap's distribution certificate or the public test frontend.
"""

import json
from pathlib import Path
import subprocess

from ibme.core.errors import InvalidParameterError
from .root_generation import MAX_INPUT_BYTES,MAX_OUTPUT_BYTES,unique_fields,validate_output


def convert_private_input(request,binary):
    binary=Path(binary)
    if not binary.is_file():
        raise InvalidParameterError("private basis engine not built; no public-fixture fallback")
    raw=json.dumps(request,separators=(",", ":")).encode()
    if len(raw)>MAX_INPUT_BYTES:
        raise InvalidParameterError("private basis request exceeds byte budget")
    result=subprocess.run([str(binary)],input=raw,capture_output=True,timeout=60)
    if result.returncode or len(result.stdout)>MAX_OUTPUT_BYTES:
        raise InvalidParameterError("private basis conversion failed; diagnostics withheld")
    try:
        return validate_output(request,json.loads(result.stdout,object_pairs_hook=unique_fields))
    except (ValueError,TypeError,KeyError):
        raise InvalidParameterError("private basis output failed validation; diagnostics withheld") from None
