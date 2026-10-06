import FooLiL2.VectorGaussian
import FooLiL3.GaussianTail

/-!
# The one-dimensional Fourier--Gaussian identity for the L3 analytic bridge

The width is `s > 0`; the phase has the negative sign
`exp (-2 * π * I * b * z)`. Consequently the dual Gaussian is shifted by `+b`,
in the exact convention of `FooLiL2.gaussianMass s b`.
All series range over the whole of `ℤ`, without truncation.
-/

noncomputable section

open scoped BigOperators

namespace FooLiL3

/-- A width-`s` integer Gaussian times a negative Fourier phase. -/
def phaseTerm (s b : ℝ) (z : ℤ) : ℂ :=
  Complex.exp (((-Real.pi * (z : ℝ) ^ 2 / s ^ 2 : ℝ) : ℂ) -
    2 * Real.pi * Complex.I * b * z)

/-- The phase is unit modulus; the remaining factor is the real Gaussian. -/
theorem norm_phaseTerm (s b : ℝ) (z : ℤ) :
    ‖phaseTerm s b z‖ = Real.exp (-Real.pi * (z : ℝ) ^ 2 / s ^ 2) := by
  rw [phaseTerm, Complex.norm_exp]
  congr 1
  simp only [Complex.sub_re, Complex.ofReal_re]
  simp [Complex.mul_re, Complex.mul_im]

/-- Product form for factoring a multidimensional Gaussian and its character. -/
theorem phaseTerm_eq_mul_exp (s b : ℝ) (z : ℤ) :
    phaseTerm s b z = (Real.exp (-Real.pi * (z : ℝ) ^ 2 / s ^ 2) : ℂ) *
      Complex.exp (-2 * Real.pi * Complex.I * b * z) := by
  rw [phaseTerm, sub_eq_add_neg, Complex.exp_add, ← Complex.ofReal_exp]
  congr 2
  ring

/-- The exact `rho` convention already used by L3, with squared length `z²`. -/
theorem phaseTerm_eq_rho_mul_exp (s b : ℝ) (z : ℤ) :
    phaseTerm s b z = (rho s ((z : ℝ) ^ 2) : ℂ) *
      Complex.exp (-2 * Real.pi * Complex.I * b * z) := by
  exact phaseTerm_eq_mul_exp s b z

theorem norm_phaseTerm_eq_rho (s b : ℝ) (z : ℤ) :
    ‖phaseTerm s b z‖ = rho s ((z : ℝ) ^ 2) := by
  exact norm_phaseTerm s b z

/-- Absolute convergence, independently of the real phase parameter `b`. -/
theorem summable_norm_phaseTerm {s : ℝ} (hs : 0 < s) (b : ℝ) :
    Summable (fun z : ℤ => ‖phaseTerm s b z‖) := by
  have h := FooLiL2.summable_gaussian_coefficient
    (inv_pos.mpr (sq_pos_of_pos hs)) 0
  apply h.congr
  intro z
  rw [norm_phaseTerm]
  congr 1
  simp only [add_zero]
  ring

theorem summable_phaseTerm {s : ℝ} (hs : 0 < s) (b : ℝ) :
    Summable (phaseTerm s b) :=
  (summable_norm_phaseTerm hs b).of_norm

/-- Positive real widths remove the principal-complex-power prefactor exactly. -/
theorem gaussian_poisson_prefactor {s : ℝ} (hs : 0 < s) :
    1 / ((((s ^ 2)⁻¹ : ℝ) : ℂ) ^ (1 / 2 : ℂ)) = (s : ℂ) := by
  have hr : ((s ^ 2)⁻¹ : ℝ) ^ (1 / 2 : ℝ) = s⁻¹ := by
    rw [← Real.sqrt_eq_rpow, Real.sqrt_inv, Real.sqrt_sq hs.le]
  have hc : ((((s ^ 2)⁻¹ : ℝ) : ℂ) ^ (1 / 2 : ℂ)) = (s⁻¹ : ℝ) := by
    rw [← hr]
    simpa using (Complex.ofReal_cpow (inv_nonneg.mpr (sq_nonneg s))
      (1 / 2 : ℝ)).symm
  rw [hc]
  simp

/-- Full exact Poisson identity, with the negative phase and positive dual shift. -/
theorem tsum_phaseTerm_eq_gaussianMass {s : ℝ} (hs : 0 < s) (b : ℝ) :
    (∑' z : ℤ, phaseTerm s b z) = (s : ℂ) * (FooLiL2.gaussianMass s b : ℂ) := by
  have ha : 0 < ((((s ^ 2)⁻¹ : ℝ) : ℂ)).re := by
    simpa only [Complex.ofReal_re] using inv_pos.mpr (sq_pos_of_pos hs)
  have hi : Complex.I * (-Complex.I * (b : ℂ)) = (b : ℂ) := by
    simp [← mul_assoc]
  calc
    _ = ∑' z : ℤ, Complex.exp (-(Real.pi : ℂ) * (((s ^ 2)⁻¹ : ℝ) : ℂ) *
        (z : ℂ) ^ 2 + 2 * Real.pi * (-Complex.I * b) * z) := by
      apply tsum_congr
      intro z
      unfold phaseTerm
      congr 1
      push_cast
      ring
    _ = (1 / ((((s ^ 2)⁻¹ : ℝ) : ℂ) ^ (1 / 2 : ℂ))) *
        ∑' z : ℤ, Complex.exp (-(Real.pi : ℂ) / (((s ^ 2)⁻¹ : ℝ) : ℂ) *
          ((z : ℂ) + Complex.I * (-Complex.I * b)) ^ 2) :=
      Complex.tsum_exp_neg_quadratic ha (-Complex.I * b)
    _ = _ := by
      rw [gaussian_poisson_prefactor hs]
      congr 1
      rw [FooLiL2.gaussianMass, Complex.ofReal_tsum]
      apply tsum_congr
      intro z
      rw [Complex.ofReal_exp, hi]
      congr 1
      push_cast
      rw [div_inv_eq_mul]

/-- `HasSum` form so callers can transport products without re-proving convergence. -/
theorem hasSum_phaseTerm {s : ℝ} (hs : 0 < s) (b : ℝ) :
    HasSum (phaseTerm s b) ((s : ℂ) * (FooLiL2.gaussianMass s b : ℂ)) := by
  rw [← tsum_phaseTerm_eq_gaussianMass hs b]
  exact (summable_phaseTerm hs b).hasSum

/-- The transformed complex Gaussian series is also absolutely convergent. -/
theorem summable_norm_dualGaussian {s : ℝ} (hs : 0 < s) (b : ℝ) :
    Summable (fun z : ℤ =>
      ‖(Real.exp (-Real.pi * s ^ 2 * ((z : ℝ) + b) ^ 2) : ℂ)‖) := by
  simpa only [Complex.norm_real, Real.norm_of_nonneg (Real.exp_pos _).le] using
    FooLiL2.summable_gaussian hs b

/-- Unfolded product-of-exponentials version of the one-dimensional identity. -/
theorem tsum_gaussian_mul_phase {s : ℝ} (hs : 0 < s) (b : ℝ) :
    (∑' z : ℤ, (Real.exp (-Real.pi * (z : ℝ) ^ 2 / s ^ 2) : ℂ) *
      Complex.exp (-2 * Real.pi * Complex.I * b * z)) =
        (s : ℂ) * (FooLiL2.gaussianMass s b : ℂ) := by
  simp_rw [← phaseTerm_eq_mul_exp]
  exact tsum_phaseTerm_eq_gaussianMass hs b

/-- Absolute convergence of a finite product of complex integer series. -/
theorem summable_norm_fin_complex_product (d : ℕ) (f : Fin d → ℤ → ℂ)
    (hf : ∀ i, Summable (fun z : ℤ => ‖f i z‖)) :
    Summable (fun z : Fin d → ℤ => ‖∏ i, f i (z i)‖) := by
  simpa only [norm_prod] using FooLiL2.summable_fin_product d
    (fun i z => ‖f i z‖) hf (fun _ _ => norm_nonneg _)

/-- Finite-dimensional Fubini/product identity with explicit absolute convergence. -/
theorem tsum_fin_complex_product (d : ℕ) (f : Fin d → ℤ → ℂ)
    (hf : ∀ i, Summable (fun z : ℤ => ‖f i z‖)) :
    (∑' z : Fin d → ℤ, ∏ i, f i (z i)) = ∏ i, ∑' z : ℤ, f i z := by
  induction d with
  | zero => simp
  | succ d ih =>
    have htail := summable_norm_fin_complex_product d (fun i => f i.succ)
      (fun i => hf i.succ)
    rw [← (Fin.consEquiv (fun _ : Fin (d + 1) => ℤ)).tsum_eq]
    simp only [Fin.prod_univ_succ, Fin.consEquiv_apply, Fin.cons_zero, Fin.cons_succ]
    rw [← tsum_mul_tsum_of_summable_norm (hf 0) htail]
    rw [ih (fun i => f i.succ) (fun i => hf i.succ)]

theorem summable_norm_prod_phaseTerm (m : ℕ) {s : ℝ} (hs : 0 < s)
    (c : Fin m → ℝ) :
    Summable (fun z : Fin m → ℤ => ‖∏ i, phaseTerm s (c i) (z i)‖) :=
  summable_norm_fin_complex_product m (fun i => phaseTerm s (c i))
    (fun i => summable_norm_phaseTerm hs (c i))

theorem summable_prod_phaseTerm (m : ℕ) {s : ℝ} (hs : 0 < s)
    (c : Fin m → ℝ) :
    Summable (fun z : Fin m → ℤ => ∏ i, phaseTerm s (c i) (z i)) :=
  (summable_norm_prod_phaseTerm m hs c).of_norm

/-- Product Poisson identity on the entire integer grid, including dimension zero. -/
theorem tsum_prod_phaseTerm_eq_gridMass (m : ℕ) {s : ℝ} (hs : 0 < s)
    (c : Fin m → ℝ) :
    (∑' z : Fin m → ℤ, ∏ i, phaseTerm s (c i) (z i)) =
      (s : ℂ) ^ m * (FooLiL2.gridMass m s c : ℂ) := by
  rw [tsum_fin_complex_product m (fun i => phaseTerm s (c i))
    (fun i => summable_norm_phaseTerm hs (c i))]
  simp_rw [tsum_phaseTerm_eq_gaussianMass hs]
  simp [FooLiL2.gridMass, Finset.prod_mul_distrib]

theorem hasSum_prod_phaseTerm (m : ℕ) {s : ℝ} (hs : 0 < s)
    (c : Fin m → ℝ) :
    HasSum (fun z : Fin m → ℤ => ∏ i, phaseTerm s (c i) (z i))
      ((s : ℂ) ^ m * (FooLiL2.gridMass m s c : ℂ)) := by
  rw [← tsum_prod_phaseTerm_eq_gridMass m hs c]
  exact (summable_prod_phaseTerm m hs c).hasSum

/-- The modulus of the full product is the original L3 vector Gaussian weight. -/
theorem norm_prod_phaseTerm_eq_rho (m : ℕ) (s : ℝ)
    (c : Fin m → ℝ) (z : Fin m → ℤ) :
    ‖∏ i, phaseTerm s (c i) (z i)‖ = rho s (∑ i, (z i : ℝ) ^ 2) := by
  simp only [norm_prod, norm_phaseTerm, rho]
  rw [Finset.mul_sum, Finset.sum_div, Real.exp_sum]

/-- Pointwise vector form, before any modular character conversion is applied. -/
theorem prod_phaseTerm_eq_rho_mul_exp (m : ℕ) (s : ℝ)
    (c : Fin m → ℝ) (z : Fin m → ℤ) :
    (∏ i, phaseTerm s (c i) (z i)) =
      (rho s (∑ i, (z i : ℝ) ^ 2) : ℂ) *
        Complex.exp (-2 * Real.pi * Complex.I * ∑ i, (c i : ℂ) * (z i : ℂ)) := by
  simp_rw [phaseTerm_eq_mul_exp]
  rw [Finset.prod_mul_distrib, ← Complex.ofReal_prod]
  have hg : (∏ i, Real.exp (-Real.pi * (z i : ℝ) ^ 2 / s ^ 2)) =
      rho s (∑ i, (z i : ℝ) ^ 2) := by
    rw [rho, Finset.mul_sum, Finset.sum_div, Real.exp_sum]
  rw [hg]
  congr 1
  rw [Finset.mul_sum, Complex.exp_sum]
  apply Finset.prod_congr rfl
  intro i _
  congr 1
  ring

end FooLiL3
