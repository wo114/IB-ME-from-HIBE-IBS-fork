# SRGG complete issuer/signature/fault-history audit (WIP)

This package audits the original Table 4 standalone IBS implementation only.
It does not alter the paper backend, persistent issuer, parameters, or any
HIBE component.  The frozen Jia–Liu–Tang–Wang PDF is
`papers/2025_efficient_ibs_jia.pdf` (SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`).
The paper does not define this local persistent issuer or an external storage
fault game, so [the proof](proof.md) is an implementation-law audit, not an
attribution to the source theorem.

An exact complete-state coupling formula is available only when every
adaptive microtransition, including faults interleaved with sampling, has a
uniform conditional full-state TV bound; the bad-key mass after random issue
and reload must also be bounded.  These premises are currently missing.  Two
finite counterexamples demonstrate why identical issuance plus fixture-key
signing laws, or identical fault-free behavior, do not imply a useful full
history bound.  An original-parameter wire-valid signing-key object has an
exact negative shifted-Schur Rayleigh value; the object is deliberately
constructed and is not claimed to be sampled by Extract.

The [receipt](fault-history-law.json) keeps all six original profile/readings'
full random-issuance/signature/fault TV fields null.  See the
[Chinese overview](README_zh-CN.md) for scope and the [validation record](validation.json)
for commands.  This remains `security_claim=none`, `backend_admitted=false`,
`parameters_are_formal=false`, `nist_security_category=null`; no NIST level or
security reduction is asserted.

Run from repository root in the prescribed WSL Sage environment:

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_fault_history_law.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-fault-history-law/verify_delivery.py
```

The manifest covers selected sources and evidence, not the full import graph.
