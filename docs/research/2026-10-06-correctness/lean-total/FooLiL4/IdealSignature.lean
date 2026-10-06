import FooLiL4.Contracts
import FooLiL3.SmoothingBridge
import FooLiL3.SetupRank

/-! The exact untruncated ideal signature law and its tail from actual dual mass. -/
noncomputable section
open MeasureTheory Matrix FooLiL2 FooLiL2.Cosets
namespace FooLiL4
open FooLiL3

/-- The lifted-and-reduced extension is exactly the intended public matrix [A|B]. -/
theorem mod_append_lifts {n m w : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (B : Matrix (Fin n) (Fin w) (ZMod q)) :
    modMatrix q (appendMatrix (liftMatrix q A) (liftMatrix q B)) =
      (fun i => Fin.append (A i) (B i)) := by
  ext i j
  refine Fin.addCases ?_ ?_ j
  · intro a
    simp [modMatrix, appendMatrix, liftMatrix]
  · intro b
    simp [modMatrix, appendMatrix, liftMatrix]

def idealSignaturePMF {n D : ℕ} (q : ℕ) [NeZero q]
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (hF : Function.Surjective F.mulVec)
    (u : Fin n → ZMod q) (t : ℝ) (ht : 0 < t) : PMF (SignatureOutput D) :=
  (cosetGaussian q F u (coset_nonempty_of_surjective q F hF u) t ht).map
    (fun x => some x.val)

def idealSignatureMeasure {n D : ℕ} (q : ℕ) [NeZero q]
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (hF : Function.Surjective F.mulVec)
    (u : Fin n → ZMod q) (t : ℝ) (ht : 0 < t)
    [MeasurableSpace (SignatureOutput D)] : Measure (SignatureOutput D) :=
  (idealSignaturePMF q F hF u t ht).toMeasure

instance idealSignatureMeasure_isProbabilityMeasure {n D : ℕ} (q : ℕ) [NeZero q]
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (hF : Function.Surjective F.mulVec)
    (u : Fin n → ZMod q) (t : ℝ) (ht : 0 < t)
    [MeasurableSpace (SignatureOutput D)] :
    IsProbabilityMeasure (idealSignatureMeasure q F hF u t ht) := by
  unfold idealSignatureMeasure
  infer_instance

theorem idealSignature_event {n D : ℕ} (q : ℕ) [NeZero q]
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (hF : Function.Surjective F.mulVec)
    (u : Fin n → ZMod q) (t : ℝ) (ht : 0 < t)
    [MeasurableSpace (SignatureOutput D)] [MeasurableSingletonClass (SignatureOutput D)]
    (E : Set (SignatureOutput D)) :
    (idealSignatureMeasure q F hF u t ht).real E =
      ((cosetGaussian q F u (coset_nonempty_of_surjective q F hF u) t ht).toOuterMeasure
        {x | some x.val ∈ E}).toReal := by
  rw [Measure.real, idealSignatureMeasure, PMF.toMeasure_apply_eq_toOuterMeasure,
    idealSignaturePMF, PMF.toOuterMeasure_map_apply]
  rfl

theorem idealSignature_invalid_probability_zero {n D : ℕ} (q : ℕ) [NeZero q]
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (hF : Function.Surjective F.mulVec)
    (u : Fin n → ZMod q) (t : ℝ) (ht : 0 < t)
    [MeasurableSpace (SignatureOutput D)] [MeasurableSingletonClass (SignatureOutput D)] :
    (idealSignatureMeasure q F hF u t ht).real (invalidOutput (InCoset q F u)) = 0 := by
  rw [idealSignature_event]
  have hempty : {x : {x // InCoset q F u x} |
      some x.val ∈ invalidOutput (InCoset q F u)} = ∅ := by
    ext x
    simp [invalidOutput, x.property]
  rw [hempty, measure_empty, ENNReal.toReal_zero]

theorem idealSignature_failure_le {n D : ℕ} (q : ℕ) [NeZero q]
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (hF : Function.Surjective F.mulVec)
    (u : Fin n → ZMod q) {t e : ℝ} (ht : 0 < t) (he : 0 ≤ e) (he1 : e < 1)
    [MeasurableSpace (SignatureOutput D)] [MeasurableSingletonClass (SignatureOutput D)]
    (hMass : CosetMassComparison q F u t e) :
    (idealSignatureMeasure q F hF u t ht).real (signatureFailure q F u t) ≤
      tailBudget D e := by
  rw [idealSignature_event]
  let p := cosetGaussian q F u (coset_nonempty_of_surjective q F hF u) t ht
  have hp1 : p.toOuterMeasure Set.univ = 1 :=
    (PMF.toOuterMeasure_apply_eq_one_iff p _).mpr (Set.subset_univ _)
  have hsub : {x : {x // InCoset q F u x} | some x.val ∈ signatureFailure q F u t} ⊆
      {x | (D : ℝ) * t ^ 2 ≤ vectorSq x.val} := by
    intro x hx
    have h := (some_mem_failure_iff q F u t x.val).mp hx
    exact (h.resolve_left (not_not.mpr x.property)).le
  calc
    _ ≤ (p.toOuterMeasure {x | (D : ℝ) * t ^ 2 ≤ vectorSq x.val}).toReal := by
      apply ENNReal.toReal_mono
      · exact ne_top_of_le_ne_top (by rw [hp1]; exact ENNReal.one_ne_top)
          (measure_mono (Set.subset_univ _))
      · exact measure_mono hsub
    _ = _ := gaussianPMF_outer_event _ _ _ _ _
    _ ≤ tailBudget D e := coset_tail_from_mass_comparison q F u
      (coset_nonempty_of_surjective q F hF u) ht he he1 hMass

/-- Integer representative version, avoiding an unproved lift-invariance assumption. -/
theorem massComparison_of_integer_smoothing {n D : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin D) ℤ) (hC : FullRowRank q C) (u : Fin n → ZMod q)
    {t e : ℝ} (ht : 0 < t) (he : 0 ≤ e) (he1 : e < 1)
    (hTheta : dualTheta q C t ≤ e) : CosetMassComparison q (modMatrix q C) u t e := by
  have ht2 : 0 < 2 * t := by positivity
  have h2 : dualTheta q C (2 * t) ≤ e :=
    (dualTheta_antitone q C hC ht (by linarith)).trans hTheta
  exact doubling_comparison_of_normalized_bounds ht
    (pow_pos (Nat.cast_pos.mpr (NeZero.pos q)) n) he he1
    (coset_mass_bounds_of_smoothing q C hC u ht hTheta).1
    (coset_mass_bounds_of_smoothing q C hC u ht2 h2).2

end FooLiL4
