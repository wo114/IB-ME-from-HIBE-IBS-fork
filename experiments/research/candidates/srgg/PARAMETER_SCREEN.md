# SRGG component parameter screen

`parameter_screen.py` records a HIBE-independent candidate profile for the
SRGG IBS research backend.  It reuses the checked `Config` object and the
source-table arithmetic in `experiments.research.primitive_spec_audit`.

Run it from the repository root with:

```text
$env:PYTHONPATH='src'
python -m experiments.research.candidates.srgg.parameter_screen --output srgg-parameter-screen.json
```

The report contains:

- the complete `Config` snapshot and derived module/gadget dimensions;
- canonical JSON shape wire references plus local identity, message and
  issuer capacities;
- component algebra/resource gates, including the exact `Q > 2*gamma` gate
  used by the current research profile;
- sampler draw counts, finite resource knobs and explicit unknown TV/abort
  terms; and
- a source-table hardness placeholder with no estimated security bits.

The report is intentionally marked:

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
```

The JSON wire references use zero-valued shape fixtures only to make the
canonical layout measurable.  They are not keys, signatures or evidence of a
production encoding.  Selecting an HIBE later may change the shared identity
and message capacities, composition wire costs, total error budget and final
hardness estimate; this component report does not freeze those choices.
