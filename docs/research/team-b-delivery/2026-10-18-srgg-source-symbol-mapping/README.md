# SRGG source symbol and game mapping (WIP)

This package compares the frozen Jia et al. PDF (SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`) against the unchanged original Table 4 SRGG IBS backend. It establishes exact necessary-premise and game-predicate discrepancies; it does not claim a fresh-message forgery or a complete reduction.

Theorem 1's verifier modulus `2q` can directly match Algorithm 8's `2Q` only with `q=Q=15744063`; all three published acceptance bounds violate its required `q>2γ`. The paper's formal smoothing definition also does not yield printed `r≈1.16`; [the exact report](source-symbol-mapping.json) tests all three Table 3 dimensions. Theorem 1 concludes EUF-CMA, whereas Theorem 2 assumes sEUF-CMA and labels its IBS conclusion strong even though its G0 uses fresh `(id,message)` pairs. Two conditional finite traces expose the displayed G1 `qS`/extraction-count mismatch and a permitted target signing query on which the printed p.9 simulator aborts. See [the detailed evidence](proof.md).

Run under the repository's prescribed WSL Sage environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_source_symbol_mapping.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-source-symbol-mapping/verify_delivery.py
```

No HIBE work, source parameter changes, sampled key/signature experiments, security admission, or NIST category is included. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
