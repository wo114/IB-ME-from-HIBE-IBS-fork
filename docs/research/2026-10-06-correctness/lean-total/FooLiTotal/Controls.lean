import FooLiTotal.Pipeline
import FooLiTotal.Initialization

noncomputable section
open MeasureTheory FooLiTotal FooLiL3
namespace FooLiTotal.Controls

theorem factor_ten_at_quality_one :
    5 * (Real.sqrt (1 : ℝ) + 1)^2 = 10*(1+1) := by norm_num

theorem factor_five_is_insufficient :
    ¬ (5 * (Real.sqrt (1 : ℝ) + 1)^2 ≤ 5*(1+1)) := by norm_num

theorem clip_large_budget : min (1 : ℝ) (2+3+4) = 1 := by norm_num

theorem transfer_charges_both_gaps :
    (3/10 : ℝ) ≤ min 1 (1/10 + 1/10 + 1/10) := by
  exact model_transfer (p0 := 1/10) (p1 := 2/10) (by norm_num)
    (by norm_num) (by norm_num) (by norm_num)

theorem setup_abort_probability_one :
    ((PMF.pure ()).bind (fun _ => PMF.pure true)).toMeasure.real {true} = 1 := by
  simp [Measure.real]

theorem bad_delegation_cannot_be_rescued :
    stopOnBad (Set.univ : Set Unit) (fun _ => PMF.pure (some true)) () = PMF.pure none := by
  exact stopOnBad_bad _ _ () (Set.mem_univ _)

theorem replay_event_is_not_two_trials :
    ∀ b : Bool, (b = true ∧ b = true) ↔ b = true := by simp

theorem zero_gap_not_available :
    ¬ |(1 : ℝ) - 0| ≤ 0 := by norm_num

theorem radial_equality_cutoff (d : ℕ) {r : ℝ} (hr : 0 < r) :
    (idealMasterGaussian d r hr).toMeasure.real
      {x | (d : ℝ)*r^2 < vectorSq x} ≤ (1/2 : ℝ)^d :=
  idealMasterGaussian_quality_tail d hr le_rfl

end FooLiTotal.Controls
