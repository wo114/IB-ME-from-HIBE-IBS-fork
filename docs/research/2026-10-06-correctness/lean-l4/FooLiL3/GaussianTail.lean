import Mathlib.Analysis.SpecialFunctions.Trigonometric.Bounds
import Mathlib.Analysis.SpecialFunctions.Exp
import Mathlib.Analysis.Normed.Group.InfiniteSum
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.Positivity
import Mathlib.Tactic.Ring
import Mathlib.Tactic.FieldSimp
import Mathlib.Tactic.NormNum
import Mathlib.Analysis.Real.Pi.Bounds

/-!
# Analytic tail assembly with an explicit mass-comparison boundary

This file does NOT derive a lattice Poisson formula or MP12 Lemma 2.6 from a
dual smoothing bound. Its `hdouble` hypothesis is the analytic mass comparison
still required for that bridge. Infinite sums are never truncated.
-/

noncomputable section
open scoped BigOperators
namespace FooLiL3

/-- Gaussian parameter `s` (not standard deviation); `a` is squared length. -/
def rho (s a : ℝ) : ℝ := Real.exp (-Real.pi * a / s ^ 2)

def gaussianZ {X : Type*} (sqLength : X → ℝ) (s : ℝ) : ℝ :=
  ∑' x, rho s (sqLength x)

def tailBudget (m : ℕ) (e : ℝ) : ℝ :=
  (1 / 2 : ℝ) ^ m * ((1 + e) / (1 - e))

theorem tailBudget_nonneg (m : ℕ) {e : ℝ} (he : 0 ≤ e) (he1 : e < 1) :
    0 ≤ tailBudget m e := by
  unfold tailBudget
  positivity

/-- A deliberately loose elementary constant, sufficient for the MP12 bound. -/
theorem exp_three_pi_div_four_ge_four : (4 : ℝ) ≤ Real.exp (3 * Real.pi / 4) := by
  have h1 : (2 : ℝ) ≤ Real.exp 1 := by linarith [Real.add_one_le_exp 1]
  have he : 0 ≤ Real.exp 1 := (Real.exp_pos 1).le
  have h2 : (4 : ℝ) ≤ Real.exp 2 := by
    have heq : Real.exp (2 : ℝ) = Real.exp 1 * Real.exp 1 := by
      convert Real.exp_add (1 : ℝ) 1 using 1
      norm_num
    rw [heq]
    nlinarith
  exact h2.trans (Real.exp_le_exp.mpr (by linarith [Real.pi_gt_three]))

theorem tail_constant (m : ℕ) :
    Real.exp (-(3 * Real.pi / 4) * m) * (2 : ℝ) ^ m ≤ (1 / 2 : ℝ) ^ m := by
  have hx : Real.exp (-(3 * Real.pi / 4)) * 2 ≤ (1 / 2 : ℝ) := by
    rw [Real.exp_neg]
    have hp := Real.exp_pos (3 * Real.pi / 4)
    have hb := exp_three_pi_div_four_ge_four
    field_simp
    nlinarith
  have heq : Real.exp (-(3 * Real.pi / 4) * (m : ℝ)) =
      Real.exp (-(3 * Real.pi / 4)) ^ m := by
    rw [mul_comm, Real.exp_nat_mul]
  rw [heq, ← mul_pow]
  exact pow_le_pow_left₀ (by positivity) hx m

/-- Pointwise change of width; equality at the rejection threshold is covered. -/
theorem rho_tail_le (m : ℕ) {s a : ℝ} (hs : 0 < s)
    (ha : (m : ℝ) * s ^ 2 ≤ a) :
    rho s a ≤ Real.exp (-(3 * Real.pi / 4) * m) * rho (2 * s) a := by
  unfold rho
  rw [← Real.exp_add]
  apply Real.exp_le_exp.mpr
  have hs2 := sq_pos_of_pos hs
  have hh : (m : ℝ) ≤ a / s ^ 2 := (le_div_iff₀ hs2).mpr ha
  have hp : 0 < Real.pi := Real.pi_pos
  have hid : -Real.pi * a / (2 * s) ^ 2 = -Real.pi * (a / s ^ 2) / 4 := by
    field_simp
    ring
  rw [hid]
  have hid2 : -Real.pi * a / s ^ 2 = -Real.pi * (a / s ^ 2) := by ring
  rw [hid2]
  nlinarith

/-- Infinite unnormalised tail mass bound, using only convergence and pointwise comparison. -/
theorem gaussian_tail_mass_le {X : Type*} (sqLength : X → ℝ) (m : ℕ)
    {s : ℝ} (hs : 0 < s)
    (hsum : Summable (fun x => rho s (sqLength x)))
    (hsum2 : Summable (fun x => rho (2 * s) (sqLength x))) :
    (∑' x : {x : X // (m : ℝ) * s ^ 2 ≤ sqLength x}, rho s (sqLength x)) ≤
      Real.exp (-(3 * Real.pi / 4) * m) * gaussianZ sqLength (2 * s) := by
  let T := {x : X // (m : ℝ) * s ^ 2 ≤ sqLength x}
  have hsub := hsum.subtype (fun x => (m : ℝ) * s ^ 2 ≤ sqLength x)
  have hsub2 := hsum2.subtype (fun x => (m : ℝ) * s ^ 2 ≤ sqLength x)
  calc
    _ ≤ ∑' x : T, Real.exp (-(3 * Real.pi / 4) * m) * rho (2 * s) (sqLength x) :=
      hsub.tsum_le_tsum (fun x => rho_tail_le m hs x.property) (hsub2.mul_left _)
    _ = Real.exp (-(3 * Real.pi / 4) * m) * ∑' x : T, rho (2 * s) (sqLength x) :=
      tsum_mul_left
    _ ≤ _ := by
      apply mul_le_mul_of_nonneg_left _ (Real.exp_pos _).le
      exact Summable.tsum_subtype_le _ _ (fun _ => (Real.exp_pos _).le) hsum2

/-- A normalized Gaussian tail bound FROM a concrete width-doubling mass certificate.
This extra certificate has not yet been derived from the ledger's C2 in Lean. -/
theorem gaussian_tail_from_mass_comparison {X : Type*} (sqLength : X → ℝ) (m : ℕ)
    {s e : ℝ} (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hsum : Summable (fun x => rho s (sqLength x)))
    (hsum2 : Summable (fun x => rho (2 * s) (sqLength x)))
    (hz : 0 < gaussianZ sqLength s)
    (hdouble : gaussianZ sqLength (2 * s) ≤
      (2 : ℝ) ^ m * ((1 + e) / (1 - e)) * gaussianZ sqLength s) :
    (∑' x : {x : X // (m : ℝ) * s ^ 2 ≤ sqLength x}, rho s (sqLength x)) /
        gaussianZ sqLength s ≤ tailBudget m e := by
  apply (div_le_iff₀ hz).mpr
  have hr : 0 ≤ (1 + e) / (1 - e) := by positivity
  have h := gaussian_tail_mass_le sqLength m hs hsum hsum2
  have hc := mul_le_mul_of_nonneg_left hdouble
    (Real.exp_pos (-(3 * Real.pi / 4) * m)).le
  have ht := mul_le_mul_of_nonneg_right (tail_constant m)
    (mul_nonneg hr hz.le)
  unfold tailBudget
  calc
    _ ≤ Real.exp (-(3 * Real.pi / 4) * m) * gaussianZ sqLength (2 * s) := h
    _ ≤ Real.exp (-(3 * Real.pi / 4) * m) *
        ((2 : ℝ) ^ m * ((1 + e) / (1 - e)) * gaussianZ sqLength s) := hc
    _ ≤ _ := by nlinarith only [ht]

end FooLiL3
