# Scope correction: the first-issuance bound is gate-uniform

Added 2026-10-18. This is an addendum. It does **not** modify any file listed in
`MANIFEST.json`; the frozen byte receipts remain the evidence of what was
actually executed.

The frozen receipt keeps `all_accepted_setup_roots_tv: null`. That field is
correct for the *global* accepted-root comparison, but the per-issuance bound is
not tied to the six replayed roots. Its perturbation term is the gate-floor
joint bound; its gadget scalar, digit-normalizer and completed-square terms are
root-independent. Therefore, for every root that passes `SchurNumericalAudit`
and `_source_gates`, the same first-issuance TV bound holds.

What remains null is the mass of the gate set relative to the paper's
mathematical positivity event `A` and to the backend accept set `B`:
`P(A\B)`, `P(B\G)` and the accepted-root distribution. The original backend does
not execute the audit gates; `GuardedSourceSchurBackend` in
[`../2026-10-18-srgg-distribution-guard-deepseek/`](../2026-10-18-srgg-distribution-guard-deepseek/README_zh-CN.md)
adds them as an explicit accept condition.

Recomputation check: the gate-floor recombination reproduces this frozen
`complete_law_tv_upper_including_abort` exactly for PARAM-I and the guarded
six-row report reproduces all table-standard-deviation rows.

中文：首次发钥界对每个通过审计门控的根都成立；`all_accepted_setup_roots_tv=null`
说的是门控集质量，不是这个数值界只对六条根有效。
