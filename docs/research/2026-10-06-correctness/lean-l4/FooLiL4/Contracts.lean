import FooLiL3.EventBounds
import FooLiL3.IntegerGaussian
import Mathlib.Probability.Distributions.Uniform

/-! Raw signature output semantics. No filtering, retry, or concrete PRG is hidden here. -/
noncomputable section
open MeasureTheory
namespace FooLiL4
open FooLiL3

abbrev SignatureOutput (D : ℕ) := Option (Fin D → ℤ)

def NormGood {D : ℕ} (t : ℝ) (x : Fin D → ℤ) : Prop :=
  vectorSq x ≤ (D : ℝ) * t ^ 2

def signatureFailure {n D : ℕ} (q : ℕ)
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (u : Fin n → ZMod q) (t : ℝ) :
    Set (SignatureOutput D) := badOutput (InCoset q F u) (NormGood t)

def signatureAccepts {n D : ℕ} (q : ℕ)
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (u : Fin n → ZMod q) (t : ℝ)
    (o : SignatureOutput D) : Prop :=
  match o with
  | none => False
  | some x => InCoset q F u x ∧ NormGood t x

theorem failure_iff_not_accepts {n D : ℕ} (q : ℕ)
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (u : Fin n → ZMod q) (t : ℝ)
    (o : SignatureOutput D) :
    o ∈ signatureFailure q F u t ↔ ¬signatureAccepts q F u t o := by
  classical
  cases o with
  | none => simp [signatureFailure, signatureAccepts, badOutput]
  | some x =>
    change (¬InCoset q F u x ∨ ¬NormGood t x) ↔ ¬(InCoset q F u x ∧ NormGood t x)
    exact not_and_or.symm

theorem some_mem_failure_iff {n D : ℕ} (q : ℕ)
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (u : Fin n → ZMod q) (t : ℝ)
    (x : Fin D → ℤ) :
    some x ∈ signatureFailure q F u t ↔
      ¬InCoset q F u x ∨ (D : ℝ) * t ^ 2 < vectorSq x := by
  simp [signatureFailure, badOutput, NormGood]

theorem none_mem_failure {n D : ℕ} (q : ℕ)
    (F : Matrix (Fin n) (Fin D) (ZMod q)) (u : Fin n → ZMod q) (t : ℝ) :
    none ∈ signatureFailure q F u t := by trivial

/-- Finite uniform byte tapes, including the unique length-zero tape. -/
abbrev ByteTape (L : ℕ) := Fin L → Fin 256

def rawTapePMF {L D : ℕ} (program : ByteTape L → SignatureOutput D) :
    PMF (SignatureOutput D) := (PMF.uniformOfFintype (ByteTape L)).map program

/-- A specification-level law. This is NOT a verified translation of Python. -/
def rawTapeMeasure {L D : ℕ} [MeasurableSpace (SignatureOutput D)]
    (program : ByteTape L → SignatureOutput D) : Measure (SignatureOutput D) :=
  (rawTapePMF program).toMeasure

instance rawTapeMeasure_isProbabilityMeasure {L D : ℕ}
    [MeasurableSpace (SignatureOutput D)] (program : ByteTape L → SignatureOutput D) :
    IsProbabilityMeasure (rawTapeMeasure program) := by
  unfold rawTapeMeasure
  infer_instance

/-- All tapes, including aborting tapes, contribute to every event probability. -/
theorem rawTapeMeasure_event {L D : ℕ} [MeasurableSpace (SignatureOutput D)]
    [MeasurableSingletonClass (SignatureOutput D)]
    (program : ByteTape L → SignatureOutput D) (E : Set (SignatureOutput D)) :
    (rawTapeMeasure program).real E =
      ((PMF.uniformOfFintype (ByteTape L)).toOuterMeasure (program ⁻¹' E)).toReal := by
  rw [Measure.real, rawTapeMeasure, PMF.toMeasure_apply_eq_toOuterMeasure,
    rawTapePMF, PMF.toOuterMeasure_map_apply]

end FooLiL4
