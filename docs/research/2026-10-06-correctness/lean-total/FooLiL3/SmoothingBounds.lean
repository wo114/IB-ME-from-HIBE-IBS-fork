import FooLiL2.DualMass
import Mathlib.Tactic.FieldSimp
import Mathlib.Tactic.Linarith

/-! Algebraic and monotonicity components of the smoothing-to-mass bridge. -/
noncomputable section
open scoped BigOperators
namespace FooLiL3

theorem weighted_mass_deviation {X : Type*} [Fintype X] [DecidableEq X]
    (z : X) (p : X → ℂ) (v : X → ℝ)
    (hp : ∀ a, ‖p a‖ ≤ 1) (hpz : p z = 1)
    (hv : ∀ a, 0 ≤ v a) (hvz : 1 ≤ v z) :
    ‖(∑ a, p a * (v a : ℂ)) - 1‖ ≤ (∑ a, v a) - 1 := by
  have hterm (a : X) :
      ‖p a * (v a : ℂ) - (if a = z then 1 else 0)‖ ≤
        v a - (if a = z then 1 else 0) := by
    by_cases h : a = z
    · subst a
      simp only [hpz, one_mul, ite_true]
      rw [← Complex.ofReal_one, ← Complex.ofReal_sub, Complex.norm_real,
        Real.norm_of_nonneg (sub_nonneg.mpr hvz)]
    · simp only [h, ite_false, sub_zero, norm_mul, Complex.norm_real,
        Real.norm_of_nonneg (hv a)]
      exact mul_le_of_le_one_left (hv a) (hp a)
  calc
    _ = ‖∑ a, (p a * (v a : ℂ) - (if a = z then 1 else 0))‖ := by
      simp [Finset.sum_sub_distrib]
    _ ≤ ∑ a, ‖p a * (v a : ℂ) - (if a = z then 1 else 0)‖ := norm_sum_le _ _
    _ ≤ ∑ a, (v a - (if a = z then 1 else 0)) := Finset.sum_le_sum (fun a _ => hterm a)
    _ = _ := by simp [Finset.sum_sub_distrib]

theorem dualTheta_antitone {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (hC : FooLiL2.Cosets.FullRowRank q C)
    {s t : ℝ} (hs : 0 < s) (hst : s ≤ t) :
    FooLiL2.dualTheta q C t ≤ FooLiL2.dualTheta q C s := by
  unfold FooLiL2.dualTheta
  rw [FooLiL2.dualMass_eq_coset_sum q C hC (hs.trans_le hst),
    FooLiL2.dualMass_eq_coset_sum q C hC hs]
  exact sub_le_sub_right (Finset.sum_le_sum fun a _ =>
    FooLiL2.gridMass_antitone m hs hst (FooLiL2.residueShift q C a)) 1

theorem residueShift_zero {n m : ℕ} (q : ℕ)
    (C : Matrix (Fin n) (Fin m) ℤ) : FooLiL2.residueShift q C 0 = 0 := by
  ext i
  change ((∑ j, C j i * ZMod.cast (0 : ZMod q) : ℤ) : ℝ) / (q : ℝ) = 0
  simp

theorem one_le_gridMass_residue_zero {n m : ℕ} (q : ℕ)
    (C : Matrix (Fin n) (Fin m) ℤ) {s : ℝ} (hs : 0 < s) :
    1 ≤ FooLiL2.gridMass m s (FooLiL2.residueShift q C 0) := by
  rw [residueShift_zero]
  change 1 ≤ FooLiL2.gridMass m s (fun _ => 0)
  rw [FooLiL2.gridMass_zero]
  exact one_le_pow₀ (FooLiL2.one_le_gaussianMass_zero hs)

theorem doubling_comparison_of_normalized_bounds {m : ℕ} {s e d Z Z2 : ℝ}
    (hs : 0 < s) (hd : 0 < d) (he : 0 ≤ e) (he1 : e < 1)
    (hlo : (1 - e) * (s ^ m / d) ≤ Z)
    (hhi : Z2 ≤ (1 + e) * ((2 * s) ^ m / d)) :
    Z2 ≤ 2 ^ m * ((1 + e) / (1 - e)) * Z := by
  have hf : 0 ≤ (2 : ℝ) ^ m * ((1 + e) / (1 - e)) := by positivity
  calc
    Z2 ≤ (1 + e) * ((2 * s) ^ m / d) := hhi
    _ = (2 : ℝ) ^ m * ((1 + e) / (1 - e)) *
        ((1 - e) * (s ^ m / d)) := by
      rw [mul_pow]
      field_simp [ne_of_gt (sub_pos.mpr he1)]
    _ ≤ _ := mul_le_mul_of_nonneg_left hlo hf

end FooLiL3
