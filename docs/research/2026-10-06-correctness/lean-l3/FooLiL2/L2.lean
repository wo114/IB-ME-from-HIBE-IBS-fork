import FooLiL2.DualMass

/-! The complete mass-extension theorem for the actual dual of a q-ary lattice. -/

noncomputable section
set_option maxHeartbeats 1000000
open scoped BigOperators
namespace FooLiL2
open Cosets

theorem residueShift_zero {n d : ℕ} (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) :
    residueShift q C (0 : Fin n → ZMod q) = fun _ => 0 := by
  have hz : liftVector q (0 : Fin n → ZMod q) = 0 := by
    funext i
    simp [liftVector]
  funext j
  simp [residueShift, hz, shift]

theorem dualTheta_append_eq_extensionTheta {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (hA : FullRowRank q A) {t : ℝ} (ht : 0 < t) :
    dualTheta q (appendMatrix A B) t =
      extensionTheta (residueShift q A) (residueShift q B) t := by
  rw [dualTheta_eq_cosetTheta q _ (fullRowRank_append q A B hA) ht]
  unfold cosetTheta extensionTheta
  congr 1
  apply Finset.sum_congr rfl
  intro a _
  unfold residueShift
  rw [shift_append, gridMass_append]

/--
L2 with all original mathematical conditions explicit. There is no hypothesis
about Gaussian summability, shifted maxima, dual decomposition, or the desired
extension inequality: each is proved in this project's dependency chain.
Here full row rank is modular surjectivity; for prime q it is exactly rank n.
-/
theorem l2_qary_mass_extension {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (hA : FullRowRank q A) {s t e : ℝ}
    (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m)
    (hmass : dualTheta q A s ≤ e) (he : 0 < e) (he' : e ≤ 1 / 4) :
    dualTheta q (appendMatrix A B) t ≤ extensionError e ∧
      0 < extensionError e ∧ extensionError e < 1 ∧
      smoothingInf (dualTheta q (appendMatrix A B)) (extensionError e) ≤ t := by
  have hm : cosetTheta (residueShift q A) s ≤ e := by
    rwa [← dualTheta_eq_cosetTheta q A hA hs]
  have hb := coset_extension_bound (residueShift q A) (residueShift q B) 0
    (residueShift_zero q A) hs hst hw hm
  have hfinal : dualTheta q (appendMatrix A B) t ≤ extensionError e := by
    rwa [dualTheta_append_eq_extensionTheta q A B hA (hs.trans_le hst)]
  exact ⟨hfinal, extensionError_pos he, extensionError_lt_one he.le he',
    smoothingInf_le_of_mass_le _ _ _ (hs.trans_le hst) hfinal⟩

/-- Source-facing prime-modulus/rank formulation of L2. -/
theorem l2_prime_rank {n m w : ℕ} (q : ℕ) [Fact q.Prime]
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (hA : (modMatrix q A).rank = n) {s t e : ℝ}
    (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m)
    (hmass : dualTheta q A s ≤ e) (he : 0 < e) (he' : e ≤ 1 / 4) :
    dualTheta q (appendMatrix A B) t ≤ 2 * e + e ^ 2 ∧
      0 < 2 * e + e ^ 2 ∧ 2 * e + e ^ 2 < 1 ∧
      smoothingInf (dualTheta q (appendMatrix A B)) (2 * e + e ^ 2) ≤ t := by
  exact l2_qary_mass_extension q A B ((fullRowRank_iff_rank q A).mpr hA)
    hs hst hw hmass he he'

/-- A direct smoothing certificate; no infimum-attainment converse is needed later. -/
theorem l2_smoothAt {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (hA : FullRowRank q A) {s t e : ℝ}
    (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m)
    (hmass : dualTheta q A s ≤ e) (he : 0 < e) (he' : e ≤ 1 / 4) :
    SmoothAt q (appendMatrix A B) (extensionError e) t := by
  exact (smoothAt_iff_theta q _ _ _).mpr ⟨hs.trans_le hst,
    (l2_qary_mass_extension q A B hA hs hst hw hmass he he').1⟩

/-- Arbitrary residue-field matrices are covered through a verified integer lift. -/
theorem l2_modular_matrices {n m w : ℕ} (q : ℕ) [Fact q.Prime]
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (B : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : A.rank = n) {s t e : ℝ}
    (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m)
    (hmass : dualTheta q (liftMatrix q A) s ≤ e) (he : 0 < e) (he' : e ≤ 1 / 4) :
    dualTheta q (appendMatrix (liftMatrix q A) (liftMatrix q B)) t ≤ 2 * e + e ^ 2 ∧
      0 < 2 * e + e ^ 2 ∧ 2 * e + e ^ 2 < 1 ∧
      smoothingInf (dualTheta q (appendMatrix (liftMatrix q A) (liftMatrix q B)))
        (2 * e + e ^ 2) ≤ t := by
  apply l2_prime_rank q (liftMatrix q A) (liftMatrix q B) _ hs hst hw hmass he he'
  simpa using hA

end FooLiL2
