# Gaussian analysis progress — Task B

Scope: exclusively `FooLiL2/Gaussian.lean` and this record. No repository edits,
Git commits, child agents, dependency updates, or cache downloads.

## Agreed interface

Namespace `FooLiL2`:

```lean
gaussianMass (t c : ℝ) :=
  ∑' z : ℤ, Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c) ^ 2)
```

Target: `gaussianMass t c ≤ gaussianMass t 0` for `0 < t`, together with
summability, nonnegativity, positivity, and `1 ≤ gaussianMass t 0`.
The sums are over all integers.

## Mathlib route and import request

Requested import: `Mathlib.NumberTheory.ModularForms.JacobiTheta.TwoVariable`.
It imports `Mathlib.Analysis.SpecialFunctions.Gaussian.PoissonSummation`.

Relevant pinned-source APIs:

- `summable_jacobiTheta₂_term_iff`, `norm_jacobiTheta₂_term`:
  obtain summability by completing the square.
- `Complex.tsum_exp_neg_quadratic`: use `a = (t²)⁻¹`, `b = -I*c`.
- `norm_tsum_le_tsum_norm`: bound the Fourier series by the centered series.
- `Complex.cpow_ne_zero_iff`: cancel the nonzero Poisson prefactor without
  selecting or approximating a complex square root.

Mathlib source: `D:\Lean\projects\lean-check\.lake\packages\mathlib`;
pin `d13f23b723b8a846827a245b89c10fc7d3f11612`.
Lean reports 4.34.1.

## Final status: full one-dimensional shifted maximum machine checked

The complete `FooLiL2/Gaussian.lean` compiled successfully on 2026-10-06, exit 0,
using the requested toolchain and pinned Mathlib. Final command, run from
`D:\Lean\projects\fooli-l2`:

```powershell
. D:\Lean\Enter-Lean.ps1
lake env lean FooLiL2/Gaussian.lean
```

No additional imports are required beyond `TwoVariable`. The main process
retrieved its selective cache; this task did not download dependencies.

The first attempt stopped at the missing import. After the cache completion
notice, the first actual proof check found one overly broad simplification in
the real-part positivity condition. Restricting it to `Complex.ofReal_re`
resolved the error; the next complete compilation exited 0.

Public interfaces in namespace `FooLiL2` (stable):

```lean
gaussianMass (t c : ℝ) : ℝ

summable_gaussian {t : ℝ} (ht : 0 < t) (c : ℝ) :
  Summable (fun z : ℤ => Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c) ^ 2))

hasSum_gaussian {t : ℝ} (ht : 0 < t) (c : ℝ) :
  HasSum (fun z : ℤ => Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c) ^ 2))
    (gaussianMass t c)

gaussianMass_le_zero {t : ℝ} (ht : 0 < t) (c : ℝ) :
  gaussianMass t c ≤ gaussianMass t 0

one_le_gaussianMass_zero {t : ℝ} (ht : 0 < t) :
  1 ≤ gaussianMass t 0

gaussianMass_nonneg (t c : ℝ) : 0 ≤ gaussianMass t c

gaussianMass_pos {t : ℝ} (ht : 0 < t) (c : ℝ) :
  0 < gaussianMass t c

gaussianMass_antitone {s t : ℝ} (hs : 0 < s) (hst : s ≤ t) (c : ℝ) :
  gaussianMass t c ≤ gaussianMass s c
```

Also provided: `summable_gaussian_coefficient {a : ℝ} (ha : 0 < a) (c : ℝ)`
for `exp (-π * a * (z+c)²)` before substituting `a = t²`.

### Proof and assumption audit

1. Complete the square in the norm of a Jacobi theta summand. Multiply its
   summable norm series by `exp (-π*a*c²)` to prove shifted summability.
2. In `Complex.tsum_exp_neg_quadratic`, put `a = (t²)⁻¹`, `b = -I*c`.
   Its right side is exactly `k * gaussianMass t c` in `ℂ`, with
   `k = 1 / ((a : ℂ) ^ (1/2 : ℂ))`.
3. The Fourier summand has norm `exp (-π*a*z²)` independent of `c`. Absolute
   summability justifies `norm_tsum_le_tsum_norm` on the full integer series.
4. The centered Fourier sum is real and nonnegative. Applying the same Poisson
   identity at `c = 0` bounds `‖k‖ * gaussianMass t c` by
   `‖k‖ * gaussianMass t 0`. Since `a > 0`, `k ≠ 0`, so cancel `‖k‖ > 0`.

There is no remaining mathematical bridge in this one-dimensional theorem.
The main bound's only hypothesis is `0 < t`; the shift is an arbitrary real.
Neither the desired mass inequality nor a Fourier/Poisson identity is supplied
as a theorem parameter. There are no finite truncations or numerical decisions.

Axiom audit output before removing module-local diagnostic commands:

```text
'FooLiL2.summable_gaussian' depends on axioms: [propext, Classical.choice, Quot.sound]
'FooLiL2.one_le_gaussianMass_zero' depends on axioms: [propext, Classical.choice, Quot.sound]
'FooLiL2.gaussianMass_antitone' depends on axioms: [propext, Classical.choice, Quot.sound]
'FooLiL2.gaussianMass_le_zero' depends on axioms: [propext, Classical.choice, Quot.sound]
```

The source scan found no `sorry`, `admit`, custom `axiom`, or `native_decide`.
The transitive axiom audit above contains only the standard Lean axioms.
The four module-local `#print axioms` commands were subsequently removed at
coordinating agent request; the main process owns the centralized `Audit.lean`.
All definitions and theorem statements/proofs are unchanged by this cleanup.

Verified Mathlib source HEAD:
`d13f23b723b8a846827a245b89c10fc7d3f11612`.
Pre-cleanup `Gaussian.lean` SHA-256 (including the four diagnostic commands):
`A6436FE61734CAB1981101D86BF4305A33D6081CC6D37B4F313F24FAF0CE5F6D`.

After cleanup, `lake env lean FooLiL2/Gaussian.lean` was rerun successfully:
exit 0, empty stdout/stderr (no diagnostics). The source scan found no `#print`
commands or prohibited proof placeholders. Final clean-source SHA-256:
`606BDFF24E306CEAFA32A5C113088DBE21969CAE1BF046F420389409519978E8`.

### Integration boundary

The main process owns `MassBounds.lean`, `ProductSum.lean`, finite-dimensional
Gaussian products, coset decomposition, matrix/dual-lattice arguments, and the
final numerical/eta corollaries. This task neither edits nor certifies those
modules. `HasSum`/`Summable` and the one-dimensional inequalities above are ready
for their integration. No `.olean` was explicitly exported by this source-check
command; the main process can use its normal module build for imports.

Reference scope: `docs/research/2026-10-06-correctness/FooLi-条件式正确性定理与参数账本.md`,
§§2–4, specifically L2's shifted-integer-Gaussian mass inequality. This file does
not certify the matrix/dual-lattice decomposition or the complete L2 theorem.
