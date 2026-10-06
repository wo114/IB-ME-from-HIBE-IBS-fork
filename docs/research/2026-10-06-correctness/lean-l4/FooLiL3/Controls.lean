import FooLiL3.L3
import Mathlib.Tactic.NormNum

/-! Exact boundary checks. These are not sampling experiments or secure parameters. -/

noncomputable section
open MeasureTheory
namespace FooLiL3.Controls
open FooLiL3

theorem quarter_tail_exact : tailBudget 3 (1 / 4) = 5 / 24 := by
  norm_num [tailBudget]

theorem column_count_cannot_be_dropped :
    frobSq (fun (_ : Fin 1) (_ : Fin 2) => (1 : ℤ)) = 2 := by
  norm_num [frobSq, colSq, Fin.sum_univ_two, Fin.sum_univ_one]

theorem each_column_can_be_small :
    ∀ j : Fin 2, colSq (fun (_ : Fin 1) (_ : Fin 2) => (1 : ℤ)) j ≤ 1 := by
  intro j
  norm_num [colSq, Fin.sum_univ_one]

theorem equality_at_cutoff_is_good :
    QualityGood 2 (fun (_ : Fin 1) (_ : Fin 2) => (1 : ℤ)) := by
  exact (qualityGood_iff_frobSq 2 (fun (_ : Fin 1) (_ : Fin 2) => (1 : ℤ))).mpr
    column_count_cannot_be_dropped.le

theorem negative_quality_cutoff_rejects_zero :
    ¬ QualityGood (-1) (0 : Matrix (Fin 1) (Fin 1) ℤ) := by
  rw [qualityGood_iff_frobSq]
  norm_num [frobSq, colSq]

theorem zero_columns_have_zero_mass (R : Matrix (Fin 3) (Fin 0) ℤ) : frobSq R = 0 := by
  simp [frobSq]

theorem probability_budget_is_clipped : min (1 : ℝ) (1 / 2 + 2 * tailBudget 1 (1 / 4)) = 1 := by
  norm_num [tailBudget]

theorem epsilon_one_makes_formula_invalid : tailBudget 3 1 = 0 := by
  norm_num [tailBudget]

/-- A full actual abort has probability one even if the ideal law succeeds. -/
theorem raw_abort_is_not_success_conditioned :
    letI : MeasurableSpace (Option Unit) := ⊤
    (Measure.dirac (none : Option Unit)).real
      (badOutput (fun _ => True) (fun _ => True)) = 1 ∧
    (Measure.dirac (some () : Option Unit)).real
      (badOutput (fun _ => True) (fun _ => True)) = 0 := by
  let : MeasurableSpace (Option Unit) := ⊤
  have he : badOutput (fun _ : Unit => True) (fun _ => True) = {none} := by
    ext o
    cases o <;> simp [badOutput]
  simp [he, Measure.real]

end FooLiL3.Controls
