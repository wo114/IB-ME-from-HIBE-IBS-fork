# Constructing Efficient Identity-Based Signatures on Lattices — structural-cost audit

**Authors:** Huiwen Jia, Ying Liu, Chunming Tang, Lin Wang. **Source:** *IET Information Security* (2025), DOI [10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889), frozen local PDF `papers/2025_efficient_ibs_jia.pdf`, SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.

This package audits one concrete attack-cost boundary in the original Table 4 SRGG IBS. It is an independent public-algebra audit, not a security-level reproduction. The paper's §§5.2.1–5.2.3 and Table 5 report generic LWE/SIS BKZ/Core-SVP estimates; this package does not rerun their estimator or infer a NIST category.

For each original row, `Q=15,744,063 < 2γ`. Any integer vector with a single `Q` coefficient in an identity-block column is therefore a nonzero, norm-`Q` solution to the **unrestricted integer Q-MSIS short-kernel search with bound `2γ`**. Its sparse description uses one nonzero coefficient, reads no public matrix, and invokes no BKZ. The same vector is in the kernel of the actual verification matrix's `2A` block modulo `2Q`, for every public matrix and every accepted Setup root. This is a concrete cost upper bound for this precisely stated kernel task, not master-secret recovery or a new-message IBS forgery.

If a valid signature is already known, an attacker can scan the first `4dn` response coefficients and try a single `±Q` change. The commitment and message challenge remain the same. If the original response squared norm is `S` and its largest absolute coefficient in those columns is `M`, the best one-coordinate replacement has squared norm `S+Q²−2QM`; it verifies under the unchanged paper norm cap exactly when this value is at most `floor(γ²)`. The audit computes this **conditional** test and no success probability. Existing real-run same-message replacement receipts are separate evidence; this package performs zero such trials.

| Row | `d` | `γ` | Eligible response coefficients | `Q < γ` | Author Table 5 classical key / forgery bits |
|---|---:|---:|---:|---|---|
| PARAM-I | 2 | 42,086,491.7 | 4,096 | yes | 105 / 103 |
| PARAM-II | 3 | 63,653,172.0 | 6,144 | yes | 178 / 171 |
| PARAM-III | 4 | 86,573,930.5 | 8,192 | yes | 255 / 242 |

The one-coordinate witness is zero in all coefficient-CRT components `3`, `31²`, `43`, `127`. Their ring factor degrees remain `256`, `32`, `256`, `8`, respectively; these degrees alone are not attack costs. A separate exact counterexample shows that keeping every 64th coefficient to obtain the degree-eight subring is **not a ring homomorphism**: the projections of `X` and `X^63` are zero, whereas the projection of their product is `Y=X^64`. True quotient-field CRT projections are homomorphisms, but a short full-ring lift, accepted-root law, and concrete CRT/subfield CVP cost are not established here.

The [proof and boundary](proof.md), [machine receipt](structural-cost.json), [validation](validation.json), and [Chinese README](README_zh-CN.md) are the review entry points. Recreate the receipt in prescribed WSL Sage:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_structural_cost --output /tmp/srgg-structural-cost-fresh.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_structural_cost.py
```

Original Table 4 values, the two existing Gaussian-notation interpretations, and the backend are unchanged. No HIBE is involved. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, and `nist_security_category=null`. Functional algebra does not replace a security reduction. The paper's Theorem 1 condition `q>2γ` fails if its `q` is mapped to this original `Q`; the source's `q/Q/2Q` mapping and native-strong game correspondence remain unresolved.
