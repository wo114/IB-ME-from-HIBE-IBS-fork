# Gate-uniform scope, complete guard, and the v2 re-freeze

Date: 2026-10-18. This is a **scope-label v2**. It does not rewrite the v1
numeric receipts; their bytes and manifests stay frozen. It freezes:

1. the corrected domain of the finite/convolution/normalizer/issuance/sign
   conditional bounds;
2. the complete gate set that the guard executes;
3. the protected-accept-set semantics and its limits;
4. the list of quantities that remain `null`.

Primary source: Jia–Liu–Tang–Wang, *Constructing Efficient Identity-Based
Signatures on Lattices*, IET Information Security (2025), DOI
[10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889); frozen
`papers/2025_efficient_ibs_jia.pdf`, SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.
Original Table 4 inputs are unchanged.

## 1. What v1 got right and what it under-stated

**Right.** The six deterministic roots are witnesses; no bound on the
Setup-root distribution, gate-set mass, random-key bad mass, fault history or
native-strong game follows from them. The all-reference-key uniform signature
certificate is impossible (canonical tail obstruction). These remain true.

**Under-stated.** The `fixed_root_only` / `all_accepted_setup_roots_covered:
false` labels describe how the receipt was produced, not the inequality's
domain. Every numerical term in the chain is one of:

- the audit gate floor `64`;
- the gate errors `2^-128` (gain / stored-factor covariance) and `2^-96`
  (adaptive-center recurrence);
- the factor envelope `2 < factor < 2^32` and center envelope `< 2^240`;
- the scalar-batch certificates and the fixed `B=512` / `P=768` / dyadic
  windows;
- the original parameters `r^2`, degree and upper-leaf count.

Actual pivots, gains and adaptive centers enter only through the gate booleans.
Therefore, for **any** plan passing the complete gate set, the same bound holds.
The six roots are witnesses that the gate set is nonempty.

## 2. Complete gate set

The guard must execute every item below; the pivot floor alone is insufficient:

| # | gate | where checked |
|---:|---|---|
| 1 | all ideal Schur pivots ≥ `64` | `SchurNumericalAudit` |
| 2 | gain coefficient error ≤ `2^-128` | `SchurNumericalAudit` |
| 3 | stored-factor ideal-covariance error ≤ `2^-128` | `SchurNumericalAudit` |
| 4 | adaptive-center recurrence error ≤ `2^-96` on the same successful history | `SchurNumericalAudit` |
| 5 | stored factors in `(2, 2^32)` | `_source_gates` |
| 6 | adaptive centers below `2^240` | `_source_gates` / plan constructor |
| 7 | scalar/aggregate entropy caps and whole-attempt budgets | `_source_gates` / `PaperSchurSampleF` |
| 8 | finite leaf/output 256-bit object guard | `_source_gates` |
| 9 | issuance centered-gadget `C > 64 I` | `fixed_root_c_gate` |
| 10 | successful finite-key object/service byte envelope | `_source_key_guard_envelope` |

Items 1–8 are the Schur/audit layer used by both Setup and signing. Items 9–10
are the root/issuance layer. The guard runs 1–10 at Setup and 1–8 before
signing.

## 3. Protected accept set vs the original algorithm

`GuardedSourceSchurBackend` runs the complete gate set:

- Setup: a gate failure raises `RootGateRejection`, a subclass of the original
  `WitnessGeometryError`; the unchanged Setup loop retries it. The accepted
  root law becomes `mu(· | B ∩ G)`.
- Signing: a gate failure raises `SigningKeyGateRejection`; the fixed key is
  aborted (no redraw).

This is a **service/accept-set change**. It does not modify the paper's
algorithms, parameters or proofs. The conclusion is about the modified
protected accept set:

> On every root/key that passes the complete gate set, the conditional bounds
> hold. The original unguarded backend has not been shown to pass the same gate
> set, so this does not directly certify the original unmodified algorithm.

The gate-set masses remain explicit nulls:

- `P(A \ B)`: mathematical positivity vs finite backend acceptance;
- `P(B \ G)`: backend acceptance but complete-gate failure;
- the mass of roots/keys rejected by the guard, and the accepted-root
  distribution relative to `mu_A`;
- `beta_bad = Q_K(G_sign^c)`, strictly positive but unquantified (the
  conditional HNF denominator lacks a target-uniform lower bound; the master
  widths are far below `Q = 15744063`, so the Gaussian modulo `Q` is not
  smoothing).

## 4. What stays unchanged

- The v1 numeric receipts are byte-identical and remain the evidence of what
  was executed; this v2 only freezes the corrected scope declaration.
- The standard-deviation bounds are unchanged: `2^-26/2^-25/2^-25` (master),
  `2^-25/2^-24/2^-24` (signature), `2^-25/2^-25/2^-24` (first issuance),
  `2^-24` (capacity history), `2^-19/2^-18/2^-18` (one sign call).
- Literal density-width: the mathematical joint bounds are nontrivial but weak
  (master ≈`0.678/0.817/0.896`, signature ≈`0.896/0.967/0.989`); first
  issuance remains `null` (gadget digit-normalizer gate) and one sign call is
  `1`.
- The all-reference-key uniform signature certificate remains impossible; the
  canonical tail obstruction is untouched.
- External-fault histories and native strong security are not solved by the
  guard.

## 5. Verification of the v2 re-freeze

- `v1` packages: unchanged bytes; their manifests are re-checked entry by entry
  by this package's verifier.
- `v1` semantic verifiers: the nine-package driver passed `18/18` checks
  (normal and `-O`); the random-key-sign-law verifier passed separately.
- Guard: `tests/test_srgg_paper_distribution_guard.py` passed; the six-row
  report records the complete gate set, the C gate and the object envelope.
- This package's `MANIFEST.json` binds the v2 files and the four v1 manifests;
  `verify_delivery.py` re-checks both.

All statements remain `security_claim=none`, `backend_admitted=false`,
`parameters_are_formal=false`, `nist_security_category=null`. Functional tests
and finite bounds are not a security proof.
