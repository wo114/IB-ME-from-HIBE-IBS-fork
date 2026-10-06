import FooLiL2.VectorGaussian

/-!
# L2 for finite families of Gaussian cosets

This is a genuine infinite-Gaussian theorem, not yet the assertion that an
arbitrary finite family is the dual of a q-ary kernel. The matrix bridge is
supplied separately; no dual/coset identity is assumed inside this module.
-/

noncomputable section
open scoped BigOperators
namespace FooLiL2

def cosetTheta {ι : Type*} [Fintype ι] {m : ℕ}
    (u : ι → Fin m → ℝ) (t : ℝ) : ℝ :=
  (∑ a, gridMass m t (u a)) - 1

def extensionTheta {ι : Type*} [Fintype ι] {m w : ℕ}
    (u : ι → Fin m → ℝ) (v : ι → Fin w → ℝ) (t : ℝ) : ℝ :=
  (∑ a, gridMass m t (u a) * gridMass w t (v a)) - 1

theorem cosetTheta_antitone {ι : Type*} [Fintype ι] {m : ℕ}
    (u : ι → Fin m → ℝ) {s t : ℝ} (hs : 0 < s) (hst : s ≤ t) :
    cosetTheta u t ≤ cosetTheta u s := by
  exact sub_le_sub_right
    (Finset.sum_le_sum (fun a _ => gridMass_antitone m hs hst (u a))) 1

/-- All Gaussian analytic steps of the mass-extension argument are proved here. -/
theorem coset_extension_bound {ι : Type*} [Fintype ι] {m w : ℕ}
    (u : ι → Fin m → ℝ) (v : ι → Fin w → ℝ) (zeroCoset : ι)
    (hzero : u zeroCoset = fun _ => 0) {s t e : ℝ}
    (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m) (hA : cosetTheta u s ≤ e) :
    extensionTheta u v t ≤ extensionError e := by
  have ht : 0 < t := hs.trans_le hst
  apply finite_mass_extension_bound
    (fun a => gridMass m t (u a)) (fun a => gridMass w t (v a))
    zeroCoset (gaussianMass t 0) e m w
  · exact fun a => gridMass_nonneg m t (u a)
  · exact one_le_gaussianMass_zero ht
  · exact hw
  · rw [hzero, gridMass_zero]
  · exact fun a => gridMass_le_zero w ht (v a)
  · have h := (cosetTheta_antitone u hs hst).trans hA
    unfold cosetTheta at h
    linarith

/-- Both the explicit nonzero-mass bound and the infimum upper bound. -/
theorem coset_l2 {ι : Type*} [Fintype ι] {m w : ℕ}
    (u : ι → Fin m → ℝ) (v : ι → Fin w → ℝ) (zeroCoset : ι)
    (hzero : u zeroCoset = fun _ => 0) {s t e : ℝ}
    (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m) (hA : cosetTheta u s ≤ e)
    (he : 0 < e) (he' : e ≤ 1 / 4) :
    extensionTheta u v t ≤ extensionError e ∧
      0 < extensionError e ∧ extensionError e < 1 ∧
      smoothingInf (extensionTheta u v) (extensionError e) ≤ t := by
  have h := coset_extension_bound u v zeroCoset hzero hs hst hw hA
  exact ⟨h, extensionError_pos he, extensionError_lt_one he.le he',
    smoothingInf_le_of_mass_le _ _ _ (hs.trans_le hst) h⟩

end FooLiL2
