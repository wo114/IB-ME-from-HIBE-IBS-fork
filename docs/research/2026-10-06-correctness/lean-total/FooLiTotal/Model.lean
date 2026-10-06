import FooLiL3.EventBounds
import Mathlib.Probability.ProbabilityMassFunction.Monad
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.NormNum

/-! Honest fixed-experiment event transfer; NOT a SHAKE pseudorandomness claim. -/
noncomputable section
open MeasureTheory
namespace FooLiTotal

/-- Each event gap is a premise, not an estimated or proved cryptographic advantage. -/
theorem model_transfer {p0 p1 p2 B α β : ℝ}
    (h0 : p0 ≤ B) (h1 : |p1 - p0| ≤ α) (h2 : |p2 - p1| ≤ β)
    (hp : p2 ≤ 1) : p2 ≤ min 1 (B + α + β) := by
  apply le_min hp
  have h10 := (abs_le.mp h1).2
  have h21 := (abs_le.mp h2).2
  linarith

theorem measure_model_transfer {Ω : Type*} [MeasurableSpace Ω]
    (g0 g1 g2 : Measure Ω) [IsProbabilityMeasure g2] (E : Set Ω)
    {B α β : ℝ} (h0 : g0.real E ≤ B)
    (h1 : |g1.real E - g0.real E| ≤ α)
    (h2 : |g2.real E - g1.real E| ≤ β) :
    g2.real E ≤ min 1 (B + α + β) :=
  model_transfer h0 h1 h2 measureReal_le_one

/-- An event containing all concrete outputs witnesses a TV lower bound.
In a finite-seed expansion use E = range(expand), then count its uniform mass.
This theorem does not assert a seed count for the whole protocol. -/
theorem support_event_lower_bound {p u : ℝ} (hp : p = 1) (hu : u ≤ 1) :
    |p - u| = 1 - u := by rw [hp, abs_of_nonneg (by linarith)]

/-- The lazy-table lookup itself is deterministic once the table is fixed. -/
theorem fixed_table_replay {K V : Type*} (table : K → V) (key : K) :
    table key = table key := rfl

/-- Small instantiation losses do not follow merely from an ideal success bound. -/
theorem ideal_success_does_not_imply_concrete_success :
    ¬ (∀ p0 p1 : ℝ, 0 ≤ p0 → p0 ≤ 1 → 0 ≤ p1 → p1 ≤ 1 → p0 = 0 → p1 = 0) := by
  intro h
  have hf := h 0 1 (by norm_num) (by norm_num) (by norm_num) (by norm_num) rfl
  norm_num at hf

end FooLiTotal
