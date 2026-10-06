import FooLiL2.Gaussian
import FooLiL2.ProductSum
import FooLiL2.MassBounds

/-! The full Gaussian mass of a shifted integer grid, in finite dimension. -/

noncomputable section
set_option maxHeartbeats 1000000
open scoped BigOperators
namespace FooLiL2

def gridMass (d : ℕ) (t : ℝ) (c : Fin d → ℝ) : ℝ :=
  ∏ i, gaussianMass t (c i)

theorem gridMass_nonneg (d : ℕ) (t : ℝ) (c : Fin d → ℝ) :
    0 ≤ gridMass d t c :=
  Finset.prod_nonneg (fun i _ => gaussianMass_nonneg t (c i))

theorem gridMass_zero (d : ℕ) (t : ℝ) :
    gridMass d t (fun _ => 0) = gaussianMass t 0 ^ d := by
  simp [gridMass]

theorem summable_grid_gaussian (d : ℕ) {t : ℝ} (ht : 0 < t) (c : Fin d → ℝ) :
    Summable (fun z : Fin d → ℤ =>
      ∏ i, Real.exp (-Real.pi * t ^ 2 * ((z i : ℝ) + c i) ^ 2)) :=
  summable_fin_product d (fun i z => Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c i) ^ 2))
    (fun i => summable_gaussian ht (c i))
    (fun _ _ => (Real.exp_pos _).le)

theorem gridMass_eq_tsum (d : ℕ) {t : ℝ} (ht : 0 < t) (c : Fin d → ℝ) :
    gridMass d t c = ∑' z : Fin d → ℤ,
      ∏ i, Real.exp (-Real.pi * t ^ 2 * ((z i : ℝ) + c i) ^ 2) := by
  exact (tsum_fin_product d (fun i z => Real.exp (-Real.pi * t ^ 2 * ((z : ℝ) + c i) ^ 2))
    (fun i => summable_gaussian ht (c i))
    (fun _ _ => (Real.exp_pos _).le)).symm

theorem gaussian_product_eq_exp (d : ℕ) (t : ℝ) (x : Fin d → ℝ) :
    (∏ i, Real.exp (-Real.pi * t ^ 2 * x i ^ 2)) =
      Real.exp (-Real.pi * t ^ 2 * ∑ i, x i ^ 2) := by
  rw [Finset.mul_sum, Real.exp_sum]

theorem gridMass_eq_gaussian_tsum (d : ℕ) {t : ℝ} (ht : 0 < t) (c : Fin d → ℝ) :
    gridMass d t c = ∑' z : Fin d → ℤ,
      Real.exp (-Real.pi * t ^ 2 * ∑ i, ((z i : ℝ) + c i) ^ 2) := by
  rw [gridMass_eq_tsum d ht c]
  apply tsum_congr
  intro z
  exact gaussian_product_eq_exp d t _

theorem summable_grid_gaussian_exp (d : ℕ) {t : ℝ} (ht : 0 < t)
    (c : Fin d → ℝ) : Summable (fun z : Fin d → ℤ =>
      Real.exp (-Real.pi * t ^ 2 * ∑ i, ((z i : ℝ) + c i) ^ 2)) :=
  (summable_grid_gaussian d ht c).congr
    (fun z => gaussian_product_eq_exp d t (fun i => (z i : ℝ) + c i))

theorem gridMass_append {m w : ℕ} (t : ℝ) (c : Fin m → ℝ) (b : Fin w → ℝ) :
    gridMass (m + w) t (Fin.append c b) = gridMass m t c * gridMass w t b := by
  simp only [gridMass, Fin.prod_univ_add, Fin.append_left, Fin.append_right]

theorem gridMass_antitone (d : ℕ) {s t : ℝ} (hs : 0 < s) (hst : s ≤ t)
    (c : Fin d → ℝ) : gridMass d t c ≤ gridMass d s c := by
  exact Finset.prod_le_prod₀ (fun i _ => gaussianMass_nonneg t (c i))
    (fun i _ => gaussianMass_antitone hs hst (c i))

theorem gridMass_le_zero (d : ℕ) {t : ℝ} (ht : 0 < t) (c : Fin d → ℝ) :
    gridMass d t c ≤ gaussianMass t 0 ^ d := by
  rw [← gridMass_zero d t]
  exact Finset.prod_le_prod₀ (fun i _ => gaussianMass_nonneg t (c i))
    (fun i _ => gaussianMass_le_zero ht (c i))

end FooLiL2
