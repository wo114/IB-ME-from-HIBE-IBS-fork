import FooLiL3.CosetPoisson
import FooLiL3.SmoothingBounds

/-! C2's actual integral-pairing dual mass implies every coset mass certificate. -/
noncomputable section
open scoped BigOperators
open Matrix FooLiL2 FooLiL2.Cosets
namespace FooLiL3

theorem normalized_coset_mass_deviation {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (hC : FullRowRank q C)
    (u : Fin n → ZMod q) {s : ℝ} (hs : 0 < s) :
    |gaussianZ (fun x : {x // InCoset q (modMatrix q C) u x} => vectorSq x.val) s /
        (s ^ m / (q : ℝ) ^ n) - 1| ≤ dualTheta q C s := by
  let v : (Fin n → ZMod q) → ℝ := fun a => gridMass m s (residueShift q C a)
  let p : (Fin n → ZMod q) → ℂ := fun a => ZMod.stdAddChar (dotProduct u a)
  let Z := gaussianZ (fun x : {x // InCoset q (modMatrix q C) u x} => vectorSq x.val) s
  let f : ℝ := s ^ m / (q : ℝ) ^ n
  have hf : 0 < f := div_pos (pow_pos hs _) (pow_pos (Nat.cast_pos.mpr (NeZero.pos q)) _)
  have hsum := weighted_mass_deviation (0 : Fin n → ZMod q) p v
    (fun a => (norm_stdAddChar q _).le) (by simp [p])
    (fun a => gridMass_nonneg m s _) (one_le_gridMass_residue_zero q C hs)
  have hz : (Z : ℂ) = (f : ℂ) * ∑ a, p a * (v a : ℂ) := by
    simpa only [Z, f, p, v, Complex.ofReal_div, Complex.ofReal_pow,
      Complex.ofReal_natCast] using coset_poisson q C u hs
  have hid : ((Z / f - 1 : ℝ) : ℂ) = (∑ a, p a * (v a : ℂ)) - 1 := by
    rw [Complex.ofReal_sub, Complex.ofReal_div, Complex.ofReal_one, hz]
    have hn : (f : ℂ) ≠ 0 := Complex.ofReal_ne_zero.mpr hf.ne'
    field_simp
  have hm : (∑ a, v a) - 1 = dualTheta q C s := by
    rw [dualTheta, dualMass_eq_coset_sum q C hC hs]
  rw [← hid, Complex.norm_real, Real.norm_eq_abs, hm] at hsum
  exact hsum

theorem coset_mass_bounds_of_smoothing {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (hC : FullRowRank q C)
    (u : Fin n → ZMod q) {s e : ℝ} (hs : 0 < s)
    (hTheta : dualTheta q C s ≤ e) :
    (1 - e) * (s ^ m / (q : ℝ) ^ n) ≤
      gaussianZ (fun x : {x // InCoset q (modMatrix q C) u x} => vectorSq x.val) s ∧
    gaussianZ (fun x : {x // InCoset q (modMatrix q C) u x} => vectorSq x.val) s ≤
      (1 + e) * (s ^ m / (q : ℝ) ^ n) := by
  have h := (normalized_coset_mass_deviation q C hC u hs).trans hTheta
  have hf : 0 < s ^ m / (q : ℝ) ^ n :=
    div_pos (pow_pos hs _) (pow_pos (Nat.cast_pos.mpr (NeZero.pos q)) _)
  obtain ⟨hl, hu⟩ := abs_le.mp h
  constructor
  · apply (le_div_iff₀ hf).mp
    linarith
  · apply (div_le_iff₀ hf).mp
    linarith

/-- C2 supplies a single dual-mass bound for A; every target u follows. -/
theorem cosetMassComparison_of_smoothing {n m : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (hA : Function.Surjective A.mulVec)
    (u : Fin n → ZMod q) {s e : ℝ} (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hTheta : dualTheta q (liftMatrix q A) s ≤ e) :
    CosetMassComparison q A u s e := by
  let C := liftMatrix q A
  have hC : FullRowRank q C := by simpa only [C, FullRowRank, mod_liftMatrix] using hA
  have hs2 : 0 < 2 * s := by positivity
  have ht2 : dualTheta q C (2 * s) ≤ e :=
    (dualTheta_antitone q C hC hs (by linarith)).trans hTheta
  have hlo := (coset_mass_bounds_of_smoothing q C hC u hs hTheta).1
  have hhi := (coset_mass_bounds_of_smoothing q C hC u hs2 ht2).2
  have h := doubling_comparison_of_normalized_bounds hs
    (pow_pos (Nat.cast_pos.mpr (NeZero.pos q)) n) he he1 hlo hhi
  change CosetMassComparison q (modMatrix q C) u s e at h
  have hmod : modMatrix q C = A := mod_liftMatrix q A
  rw [hmod] at h
  exact h

end FooLiL3
