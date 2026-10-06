import FooLiL4.L4
import Mathlib.Tactic.NormNum

/-! Exact boundary and probability controls, not cryptographic test parameters. -/
noncomputable section
open MeasureTheory Matrix
namespace FooLiL4.Controls
open FooLiL3 FooLiL4

theorem equality_at_cutoff_accepted :
    signatureAccepts 3 (fun (_ : Fin 1) (_ : Fin 1) => 1) (fun _ => 1) 1
      (some (fun _ => 1)) := by
  norm_num [signatureAccepts, InCoset, mulVec, dotProduct, NormGood, vectorSq,
    Fin.sum_univ_one, funext_iff]

theorem zero_is_not_extra_rejected :
    signatureAccepts 3 (fun (_ : Fin 1) (_ : Fin 1) => 1) (fun _ => 0) 1
      (some (fun _ => 0)) := by
  norm_num [signatureAccepts, InCoset, mulVec, dotProduct, NormGood, vectorSq,
    Fin.sum_univ_one, funext_iff]

theorem zero_wrong_syndrome_rejected :
    ¬signatureAccepts 3 (fun (_ : Fin 1) (_ : Fin 1) => 1) (fun _ => 1) 1
      (some (fun _ => 0)) := by
  norm_num [signatureAccepts, InCoset, mulVec, dotProduct, NormGood, vectorSq,
    Fin.sum_univ_one, funext_iff]

theorem signed_integer_minus_one_accepted :
    signatureAccepts 3 (fun (_ : Fin 1) (_ : Fin 1) => 1) (fun _ => 2) 1
      (some (fun _ => -1)) := by
  norm_num [signatureAccepts, InCoset, mulVec, dotProduct, NormGood, vectorSq,
    Fin.sum_univ_one, funext_iff]
  decide

theorem residue_representative_two_is_too_large :
    ¬NormGood 1 (fun _ : Fin 1 => (2 : ℤ)) := by
  norm_num [NormGood, vectorSq, Fin.sum_univ_one]

theorem full_dimension_required :
    NormGood 1 (fun _ : Fin 2 => (1 : ℤ)) ∧
      ¬(vectorSq (fun _ : Fin 2 => (1 : ℤ)) ≤ (1 : ℝ)) := by
  norm_num [NormGood, vectorSq, Fin.sum_univ_two]

theorem epsilon_extension_at_quarter :
    FooLiL2.extensionError (1 / 4) = (9 / 16 : ℝ) := by
  norm_num [FooLiL2.extensionError]

theorem signature_tail_uses_extended_error : tailBudget 2 (9 / 16) = 25 / 28 := by
  norm_num [tailBudget]

theorem budget_clipped_to_one : min (1 : ℝ) (1 / 2 + tailBudget 2 (9 / 16)) = 1 := by
  norm_num [tailBudget]

theorem invalid_epsilon_one_not_admitted : ¬((1 : ℝ) < 1) := by norm_num

theorem constant_abort_tape_probability :
    letI : MeasurableSpace (SignatureOutput 1) := ⊤
    (rawTapeMeasure (fun _ : ByteTape 1 => (none : SignatureOutput 1))).real
      (signatureFailure 3 (fun (_ : Fin 1) (_ : Fin 1) => 1) (fun _ => 0) 1) = 1 := by
  let : MeasurableSpace (SignatureOutput 1) := ⊤
  rw [rawTapeMeasure_event]
  have hpre : (fun _ : ByteTape 1 => (none : SignatureOutput 1)) ⁻¹'
      signatureFailure 3 (fun (_ : Fin 1) (_ : Fin 1) => 1) (fun _ => 0) 1 = Set.univ := by
    ext b
    simp [signatureFailure, badOutput]
  rw [hpre]
  have h1 : (PMF.uniformOfFintype (ByteTape 1)).toOuterMeasure Set.univ = 1 :=
    (PMF.toOuterMeasure_apply_eq_one_iff _ _).mpr (Set.subset_univ _)
  rw [h1, ENNReal.toReal_one]

theorem abort_cannot_be_ignored :
    letI : MeasurableSpace (Option Unit) := ⊤
    ¬TVWithin (Measure.dirac (none : Option Unit)) (Measure.dirac (some ())) 0 := by
  let : MeasurableSpace (Option Unit) := ⊤
  intro h
  have he := h {none} (by trivial)
  norm_num [Measure.real] at he

end FooLiL4.Controls
