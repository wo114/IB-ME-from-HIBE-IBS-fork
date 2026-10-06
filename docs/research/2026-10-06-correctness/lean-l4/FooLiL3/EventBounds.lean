import Mathlib.MeasureTheory.Measure.Real
import Mathlib.Tactic.Linarith

/-!
# Finite failure events and total-variation transfer for Foo--Li L3

All probabilities below are `Measure.real` of genuine probability measures.
`TVWithin` is the eventwise total-variation contract on the *same* output space.
That space may include `none` (abort); no conditioning on successful output is
performed.  The union bounds require no independence of the columns.
-/

open MeasureTheory Set
open scoped BigOperators

namespace FooLiL3

variable {Ω : Type*} [MeasurableSpace Ω]

/-- Eventwise total-variation bound.  Use raw laws on one common output space,
including abort, rather than success-conditioned laws. -/
def TVWithin (μ ν : Measure Ω) (ε : ℝ) : Prop :=
  ∀ E : Set Ω, MeasurableSet E → |μ.real E - ν.real E| ≤ ε

theorem tvWithin_nonneg {μ ν : Measure Ω} {ε : ℝ}
    (h : TVWithin μ ν ε) : 0 ≤ ε := by
  simpa using h ∅ MeasurableSet.empty

theorem tvWithin_refl (μ : Measure Ω) : TVWithin μ μ 0 := by
  intro E _
  simp

theorem tvWithin_symm {μ ν : Measure Ω} {ε : ℝ}
    (h : TVWithin μ ν ε) : TVWithin ν μ ε := by
  intro E hE
  rw [abs_sub_comm]
  exact h E hE

/-- The one-sided consequence used for transfer from the ideal law. -/
theorem tv_event_le {μ ν : Measure Ω} {ε : ℝ}
    (h : TVWithin μ ν ε) {E : Set Ω} (hE : MeasurableSet E) :
    μ.real E ≤ ν.real E + ε := by
  have hd := (abs_le.mp (h E hE)).2
  linarith

/-- Transfer any ideal event bound; clipping uses normalization of the actual law. -/
theorem tv_transfer_min {μ ν : Measure Ω} [IsProbabilityMeasure μ]
    {ε b : ℝ} (h : TVWithin μ ν ε) {E : Set Ω}
    (hE : MeasurableSet E) (hIdeal : ν.real E ≤ b) :
    μ.real E ≤ min 1 (ε + b) := by
  apply le_min measureReal_le_one
  have ht := tv_event_le h hE
  linarith

/-- Finite union bound, allowing arbitrary dependence between the events. -/
theorem finite_union_probability_le {ι : Type*} [Fintype ι]
    (ν : Measure Ω) (C : ι → Set Ω) (b : ι → ℝ)
    (hC : ∀ j, ν.real (C j) ≤ b j) :
    ν.real (⋃ j, C j) ≤ ∑ j, b j := by
  exact (measureReal_iUnion_fintype_le C).trans
    (Finset.sum_le_sum (fun j _ => hC j))

/-- Equal per-column bound.  This includes the zero-column case. -/
theorem fin_union_probability_le (ν : Measure Ω) {w : ℕ}
    (C : Fin w → Set Ω) {τ : ℝ} (hC : ∀ j, ν.real (C j) ≤ τ) :
    ν.real (⋃ j, C j) ≤ (w : ℝ) * τ := by
  simpa using finite_union_probability_le ν C (fun _ => τ) hC

/-- Adding an ideal-null invalid/abort event changes no real probability. -/
theorem probability_union_null (ν : Measure Ω) [IsProbabilityMeasure ν]
    {V E : Set Ω} (hV : ν.real V = 0) :
    ν.real (V ∪ E) = ν.real E := by
  apply le_antisymm
  · simpa [hV] using (measureReal_union_le V E (μ := ν))
  · exact measureReal_mono subset_union_right

/-- The bad-output event is covered by ideal-null invalid outputs and bad columns. -/
theorem ideal_bad_probability_le (ν : Measure Ω) [IsProbabilityMeasure ν]
    {w : ℕ} {E V : Set Ω} (C : Fin w → Set Ω) {τ : ℝ}
    (hCover : E ⊆ V ∪ ⋃ j, C j) (hV : ν.real V = 0)
    (hC : ∀ j, ν.real (C j) ≤ τ) :
    ν.real E ≤ (w : ℝ) * τ := by
  calc
    ν.real E ≤ ν.real (V ∪ ⋃ j, C j) := measureReal_mono hCover
    _ = ν.real (⋃ j, C j) := probability_union_null ν hV
    _ ≤ (w : ℝ) * τ := fin_union_probability_le ν C hC

/-- L3's event assembly: abort is already in `E`, so the TV loss is added once. -/
theorem actual_bad_probability_le (μ ν : Measure Ω)
    [IsProbabilityMeasure μ] [IsProbabilityMeasure ν]
    {w : ℕ} {E V : Set Ω} (C : Fin w → Set Ω) {ε τ : ℝ}
    (hTV : TVWithin μ ν ε) (hE : MeasurableSet E)
    (hCover : E ⊆ V ∪ ⋃ j, C j) (hV : ν.real V = 0)
    (hC : ∀ j, ν.real (C j) ≤ τ) :
    μ.real E ≤ min 1 (ε + (w : ℝ) * τ) := by
  exact tv_transfer_min hTV hE (ideal_bad_probability_le ν C hCover hV hC)

section OptionEvents

variable {X : Type*}

/-- Raw output rejection: `none`, an invalid relation, or failed quality. -/
def badOutput (valid good : X → Prop) : Set (Option X) :=
  {o | match o with
    | none => True
    | some x => ¬valid x ∨ ¬good x}

/-- Abort or an invalid algebraic relation, with no quality rejection. -/
def invalidOutput (valid : X → Prop) : Set (Option X) :=
  {o | match o with
    | none => True
    | some x => ¬valid x}

/-- Lift an ordinary event without including abort. -/
def someEvent (C : Set X) : Set (Option X) :=
  {o | match o with
    | none => False
    | some x => x ∈ C}

theorem none_mem_badOutput (valid good : X → Prop) :
    none ∈ badOutput valid good := by trivial

theorem none_not_mem_someEvent (C : Set X) : none ∉ someEvent C := by
  simp [someEvent]

/-- Exact event decomposition when quality means no bad column. -/
theorem badOutput_eq_invalid_union {ι : Type*} (valid : X → Prop)
    (C : ι → Set X) :
    badOutput valid (fun x => ∀ j, x ∉ C j) =
      invalidOutput valid ∪ ⋃ j, someEvent (C j) := by
  classical
  ext o
  cases o <;> simp [badOutput, invalidOutput, someEvent]

/-- A deterministic all-columns-good implication is enough; equality is not needed. -/
theorem badOutput_subset_invalid_union {ι : Type*} (valid good : X → Prop)
    (C : ι → Set X) (hGood : ∀ x, (∀ j, x ∉ C j) → good x) :
    badOutput valid good ⊆ invalidOutput valid ∪ ⋃ j, someEvent (C j) := by
  classical
  intro o ho
  cases o with
  | none => exact Or.inl trivial
  | some x =>
    change ¬valid x ∨ ¬good x at ho
    rcases ho with hv | hg
    · exact Or.inl hv
    · have hbad : ∃ j, x ∈ C j := by
        by_contra h
        exact hg (hGood x (by simpa using h))
      obtain ⟨j, hj⟩ := hbad
      exact Or.inr (Set.mem_iUnion.mpr ⟨j, hj⟩)

/-- Direct raw-output version of L3's probability assembly.  A caller must prove
the column tails, the ideal support property, and the deterministic quality
implication; this theorem does not silently assume the desired final bound. -/
theorem actual_badOutput_probability_le [MeasurableSpace (Option X)]
    (μ ν : Measure (Option X)) [IsProbabilityMeasure μ] [IsProbabilityMeasure ν]
    {w : ℕ} (valid good : X → Prop) (C : Fin w → Set X) {ε τ : ℝ}
    (hTV : TVWithin μ ν ε) (hE : MeasurableSet (badOutput valid good))
    (hGood : ∀ x, (∀ j, x ∉ C j) → good x)
    (hV : ν.real (invalidOutput valid) = 0)
    (hC : ∀ j, ν.real (someEvent (C j)) ≤ τ) :
    μ.real (badOutput valid good) ≤ min 1 (ε + (w : ℝ) * τ) := by
  exact actual_bad_probability_le μ ν (fun j => someEvent (C j)) hTV hE
    (badOutput_subset_invalid_union valid good C hGood) hV hC

end OptionEvents

end FooLiL3
