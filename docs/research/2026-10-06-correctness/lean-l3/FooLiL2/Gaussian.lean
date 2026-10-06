import Mathlib.NumberTheory.ModularForms.JacobiTheta.TwoVariable

/-!
# One-dimensional Gaussian mass for Foo--Li L2

All sums range over the whole of `ℤ`. The width convention here is
`exp (-π * t² * x²)`, i.e. the lattice Gaussian parameter is `1 / t`.
The only analytic input is Mathlib's Jacobi theta / Poisson summation theory.
-/

noncomputable section

namespace FooLiL2

/-- The full shifted integer Gaussian mass (not a finite truncation). -/
def gaussianMass (t c : ℝ) : ℝ :=
  ∑' z : ℤ, Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c) ^ 2)

theorem gaussianMass_nonneg (t c : ℝ) : 0 ≤ gaussianMass t c :=
  tsum_nonneg (fun _ => (Real.exp_pos _).le)

/-- Summability with a positive quadratic coefficient, before substituting `a = t²`. -/
theorem summable_gaussian_coefficient {a : ℝ} (ha : 0 < a) (c : ℝ) :
    Summable (fun z : ℤ => Real.exp (-Real.pi * a * ((z : ℝ) + c) ^ 2)) := by
  have h := ((summable_jacobiTheta₂_term_iff
    ((a * c : ℝ) * Complex.I) ((a : ℂ) * Complex.I)).mpr (by simpa using ha)).norm
  convert h.mul_left (Real.exp (-Real.pi * a * c ^ 2)) using 1
  ext z
  rw [norm_jacobiTheta₂_term, ← Real.exp_add]
  congr 1
  simp only [Complex.mul_I_im, Complex.ofReal_re]
  ring

theorem summable_gaussian {t : ℝ} (ht : 0 < t) (c : ℝ) :
    Summable (fun z : ℤ => Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c) ^ 2)) :=
  summable_gaussian_coefficient (sq_pos_of_pos ht) c

/-- `HasSum` interface for subsequent product constructions. -/
theorem hasSum_gaussian {t : ℝ} (ht : 0 < t) (c : ℝ) :
    HasSum (fun z : ℤ => Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c) ^ 2))
      (gaussianMass t c) :=
  (summable_gaussian ht c).hasSum

theorem one_le_gaussianMass_zero {t : ℝ} (ht : 0 < t) :
    1 ≤ gaussianMass t 0 := by
  have h := (summable_gaussian ht 0).le_tsum 0
    (fun z _ => (Real.exp_pos (-Real.pi * t ^ 2 * ((z : ℝ) + 0) ^ 2)).le)
  simpa [gaussianMass] using h

theorem gaussianMass_pos {t : ℝ} (ht : 0 < t) (c : ℝ) :
    0 < gaussianMass t c := by
  exact (Real.exp_pos _).trans_le ((summable_gaussian ht c).le_tsum 0
    (fun z _ => (Real.exp_pos (-Real.pi * t ^ 2 * ((z : ℝ) + c) ^ 2)).le))

/-- Increasing the inverse width decreases every mass, for an arbitrary fixed shift. -/
theorem gaussianMass_antitone {s t : ℝ} (hs : 0 < s) (hst : s ≤ t) (c : ℝ) :
    gaussianMass t c ≤ gaussianMass s c := by
  apply (summable_gaussian (hs.trans_le hst) c).tsum_le_tsum _ (summable_gaussian hs c)
  intro z
  apply Real.exp_le_exp.mpr
  have hsq : s ^ 2 ≤ t ^ 2 := pow_le_pow_left₀ hs.le hst 2
  have hpi : -Real.pi ≤ 0 := neg_nonpos.mpr Real.pi_pos.le
  exact mul_le_mul_of_nonneg_right (mul_le_mul_of_nonpos_left hsq hpi) (sq_nonneg _)

/-- Fourier-side Gaussian with a unit complex phase. -/
private def fourierGaussian (a c : ℝ) (z : ℤ) : ℂ :=
  Complex.exp (-(Real.pi : ℂ) * a * (z : ℂ) ^ 2 +
    2 * Real.pi * (-Complex.I * c) * z)

private theorem norm_fourierGaussian (a c : ℝ) (z : ℤ) :
    ‖fourierGaussian a c z‖ = Real.exp (-Real.pi * a * (z : ℝ) ^ 2) := by
  rw [fourierGaussian, Complex.norm_exp]
  congr 1
  simp [pow_two, Complex.mul_re, Complex.mul_im]

private theorem summable_norm_fourierGaussian {a : ℝ} (ha : 0 < a) (c : ℝ) :
    Summable (fun z : ℤ => ‖fourierGaussian a c z‖) := by
  simpa only [norm_fourierGaussian, add_zero] using summable_gaussian_coefficient ha 0

private theorem fourierGaussian_zero (a : ℝ) (z : ℤ) :
    fourierGaussian a 0 z = (Real.exp (-Real.pi * a * (z : ℝ) ^ 2) : ℂ) := by
  rw [fourierGaussian, Complex.ofReal_exp]
  congr 1
  push_cast
  ring

/-- The Poisson bridge, retaining its complex prefactor to avoid square-root conventions. -/
private theorem poisson_gaussianMass {t : ℝ} (ht : 0 < t) (c : ℝ) :
    (∑' z : ℤ, fourierGaussian ((t ^ 2)⁻¹) c z) =
      (1 / ((((t ^ 2)⁻¹ : ℝ) : ℂ) ^ (1 / 2 : ℂ))) * (gaussianMass t c : ℂ) := by
  have ha : 0 < ((((t ^ 2)⁻¹ : ℝ) : ℂ)).re := by
    simpa only [Complex.ofReal_re] using inv_pos.mpr (sq_pos_of_pos ht)
  have hi : Complex.I * (-Complex.I * (c : ℂ)) = (c : ℂ) := by
    simp [← mul_assoc]
  calc
    _ = (1 / ((((t ^ 2)⁻¹ : ℝ) : ℂ) ^ (1 / 2 : ℂ))) *
        ∑' z : ℤ, Complex.exp (-(Real.pi : ℂ) / (((t ^ 2)⁻¹ : ℝ) : ℂ) *
          ((z : ℂ) + Complex.I * (-Complex.I * c)) ^ 2) :=
      Complex.tsum_exp_neg_quadratic ha (-Complex.I * c)
    _ = _ := by
      congr 1
      rw [gaussianMass, Complex.ofReal_tsum]
      apply tsum_congr
      intro z
      rw [Complex.ofReal_exp, hi]
      congr 1
      push_cast
      rw [div_inv_eq_mul]

/-- Every real shift has at most the mass of the centered integer Gaussian. -/
theorem gaussianMass_le_zero {t : ℝ} (ht : 0 < t) (c : ℝ) :
    gaussianMass t c ≤ gaussianMass t 0 := by
  let a : ℝ := (t ^ 2)⁻¹
  let k : ℂ := 1 / ((a : ℂ) ^ (1 / 2 : ℂ))
  have ha : 0 < a := inv_pos.mpr (sq_pos_of_pos ht)
  have hk : 0 < ‖k‖ := by
    apply norm_pos_iff.mpr
    exact one_div_ne_zero ((Complex.cpow_ne_zero_iff).mpr
      (Or.inl (by exact_mod_cast ha.ne')))
  have hnorm (d : ℝ) :
      ‖∑' z : ℤ, fourierGaussian a d z‖ = ‖k‖ * gaussianMass t d := by
    rw [poisson_gaussianMass ht d, norm_mul]
    rw [Complex.norm_real, Real.norm_of_nonneg (gaussianMass_nonneg t d)]
  have hcenter :
      ‖∑' z : ℤ, fourierGaussian a 0 z‖ =
        ∑' z : ℤ, Real.exp (-Real.pi * a * (z : ℝ) ^ 2) := by
    simp_rw [fourierGaussian_zero]
    rw [← Complex.ofReal_tsum, Complex.norm_real,
      Real.norm_of_nonneg (tsum_nonneg (fun _ => (Real.exp_pos _).le))]
  apply (mul_le_mul_iff_right₀ hk).mp
  rw [← hnorm c, ← hnorm 0, hcenter]
  have h := norm_tsum_le_tsum_norm (summable_norm_fourierGaussian ha c)
  simpa only [norm_fourierGaussian] using h

end FooLiL2
