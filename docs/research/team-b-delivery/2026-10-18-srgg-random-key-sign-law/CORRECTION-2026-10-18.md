# Scope correction: good-key bound is gate-uniform; the impossibility is unchanged

Added 2026-10-18. This is an addendum. It does **not** modify any file listed in
`MANIFEST.json`; the frozen byte receipts remain the evidence of what was
actually executed.

Two statements must be kept apart.

1. **The all-reference-key uniform signature certificate is impossible.** The
   frozen canonical-tail obstruction remains valid. A key with a large constant
   tail coefficient lies in the mathematical reference's support, survives the
   key codec, and makes a Fourier diagonal of the signing Schur form strictly
   negative. This note does not weaken that result.

2. **The good-key signing bound is gate-uniform.** The one-fixture-key bound is
   not a pointwise fact about the fixture. Its finite / convolution /
   normalizer terms use the audit gate floor `64` and root-independent
   constants. Therefore every issued key whose signature plan passes
   `SchurNumericalAudit` and `_source_gates` gets the same bound (for the
   table-standard-deviation rows: `2^-19`, `2^-18`, `2^-18` per call; literal
   rows remain `1`).

What remains `null` is `beta_bad = Q_K(G_sign^c)`: the mass of keys that fail
the signing gate under the ideal centered-HNF issuance reference. The
conditional tail law needs a target-uniform lower bound for `P_D(S_h)` and an
HNF-wrapping numerator; at the paper's widths the Gaussian modulo
`Q = 15744063` is not smoothing. The canonical obstruction proves
`beta_bad > 0`, not a numeric bound.

See [`../2026-10-18-srgg-distribution-guard-deepseek/`](../2026-10-18-srgg-distribution-guard-deepseek/README_zh-CN.md)
and its `GuardedSourceSchurBackend` (signing aborts on `G_sign^c`).

中文：全参考密钥一致证书仍不可能（大尾反例有效）；被修正的是"好密钥的签名界只
对单条固定密钥有效"这一范围标签。`beta_bad` 仍为 null，只证明了严格为正。
