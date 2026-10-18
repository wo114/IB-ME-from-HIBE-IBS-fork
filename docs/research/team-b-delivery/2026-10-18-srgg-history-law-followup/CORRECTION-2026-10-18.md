# Scope correction: the per-root history bound is gate-uniform

Added 2026-10-18. This is an addendum. It does **not** modify any file listed in
`MANIFEST.json`; the frozen byte receipts remain the evidence of what was
actually executed.

The frozen proof says the issuance-only result "is a same-root result and cannot
be averaged over all accepted Setup roots without a bound for roots that fail
the required gates". The second clause is still true: the gate-set mass is not
bounded. The first clause should not be read as "the numerical inequality is
only valid on the six replayed roots". The finite / convolution / normalizer /
issuance / sign terms depend only on the audit gate floor `64`, the gate errors
`2^-128` / `2^-96`, the factor and center envelopes, the scalar-batch
certificates and fixed degree / leaf / parameter values; the actual pivots and
gains enter only through the gate booleans. Hence the same per-root bound holds
for every root and key that passes the gates.

So the history statement is:

```
TV(full history | guarded root/key) <= min(1, delta_issue + beta_bad + s*epsilon_good)
```

with `delta_issue` and `epsilon_good` gate-uniform and numeric for the
table-standard-deviation rows (see the guarded report), while `alpha_root` (the
root-gate mass), `beta_bad` and the faulty-history terms remain `null`.

See [`../2026-10-18-srgg-distribution-guard-deepseek/`](../2026-10-18-srgg-distribution-guard-deepseek/README_zh-CN.md).

中文：同根历史界本身对每个通过门控的根都成立；"不能跨根平均"说的是门控集质量，
不是数值不等式只对六条根有效。`beta_bad`、`P(A\B)`、故障历史仍为 null。
