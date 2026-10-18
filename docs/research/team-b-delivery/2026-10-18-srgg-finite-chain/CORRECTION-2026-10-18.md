# Scope correction: `fixed_root_only` is a receipt label, not the theorem domain

Added 2026-10-18. This is an addendum. It does **not** modify any file listed in
`MANIFEST.json`; the frozen byte receipts remain the evidence of what was
actually executed.

The frozen certificate records `fixed_root_only: true` and
`all_accepted_setup_roots_covered: false`. That is correct as a statement about
the *stored receipt* (six deterministic roots were replayed), but it has been
read as a statement about the theorem. It is not one.

Every numerical term of the finite / convolution / normalizer chain is one of:
the audit gate floor `64`, the gate errors `2^-128` / `2^-96`, the factor and
center envelopes, the scalar-batch certificates, and fixed degree / leaf /
parameter values. The actual pivots, gains and adaptive centers enter only
through the gate booleans checked by `SchurNumericalAudit` and `_source_gates`.
Replacing a real pivot by the gate floor gives a uniform bound over every plan
that passes the same gates; the six roots are witnesses that the gate set is
nonempty.

The remaining distributional gap is therefore **not** the finite-sampler law
bridge but (a) the original backend does not execute the audit gates and (b) the
gate-set masses `P(A\B)`, `P(B\G)` and `beta_bad` are not bounded. See the
independent audit
[`../2026-10-18-srgg-distribution-guard-deepseek/`](../2026-10-18-srgg-distribution-guard-deepseek/README_zh-CN.md)
and its `GuardedSourceSchurBackend`.

Recomputation check: the gate-floor evaluation reproduces the frozen joint,
source-issuance and history values exactly for the table-standard-deviation
rows; a second accepted root gives an identical master joint bound.

中文：`fixed_root_only` 是回执范围标签，不是定理范围；界对每个通过同一审计门控
的根/密钥都成立。剩余缺口是后端没有执行门控以及门控事件质量，不是采样器分布。

v2 re-freeze: [`../2026-10-18-srgg-gate-uniform-v2/`](../2026-10-18-srgg-gate-uniform-v2/README_zh-CN.md).
The complete gate set includes the issuance `C > 64 I` gate and the finite-key
object/service envelope; the guard proves the protected accept set, not the
original unguarded algorithm.
