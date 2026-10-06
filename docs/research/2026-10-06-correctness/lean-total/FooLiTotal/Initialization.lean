import FooLiL3.ClosedL3
import Mathlib.Analysis.SpecialFunctions.Log.Basic
import Mathlib.Analysis.SpecialFunctions.Sqrt
import FooLiTotal.MasterTail

/-! Initialization arithmetic and raw probability transfer.
The MP12 basis-lifting / GS-to-smoothing bridge is EXTERNAL, a named premise.
This file must NOT be reported as a complete formalization of MP12 I1 or I2.
-/
noncomputable section
open MeasureTheory FooLiL3 FooLiL2 FooLiL2.Cosets
namespace FooLiTotal

def smoothingFactor (m : ℕ) (e : ℝ) : ℝ :=
  Real.log (2 * m * (1 + 1 / e)) / Real.pi

theorem smoothingFactor_nonneg {m : ℕ} (hm : 0 < m) {e : ℝ} (he : 0 < e) :
    0 ≤ smoothingFactor m e := by
  unfold smoothingFactor
  apply div_nonneg _ Real.pi_pos.le
  apply Real.log_nonneg
  have hme : (1 : ℝ) ≤ m := by exact_mod_cast hm
  have hie : 0 < 1 / e := one_div_pos.mpr he
  nlinarith

theorem basis_bound_relaxation {Q : ℝ} (hQ : 0 ≤ Q) :
    5 * (Real.sqrt Q + 1) ^ 2 ≤ 10 * (Q + 1) := by
  have hsq := Real.sq_sqrt hQ
  nlinarith [sq_nonneg (Real.sqrt Q - 1)]

/-- Scalar part of I1 only; actual basis construction is not hidden here. -/
theorem i1_width_arithmetic {m : ℕ} (hm : 0 < m) {Q e s b : ℝ}
    (hQ : 0 ≤ Q) (he : 0 < e)
    (hb : b ^ 2 ≤ 5 * (Real.sqrt Q + 1) ^ 2)
    (hw : 10 * (Q + 1) * smoothingFactor m e ≤ s ^ 2) :
    b ^ 2 * smoothingFactor m e ≤ s ^ 2 := by
  exact (mul_le_mul_of_nonneg_right (hb.trans (basis_bound_relaxation hQ))
    (smoothingFactor_nonneg hm he)).trans hw

/-- Explicit open bridge: `hMP12` is a PAPER-level premise, not a Lean theorem.
Neither a sampled-state check nor an internal sampler epsilon discharges it. -/
theorem i1_from_external_mp12_geometry {n m : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) ℤ) {Q e s b : ℝ}
    (hm : 0 < m) (hQ : 0 ≤ Q) (he : 0 < e) (hs : 0 < s)
    (hb : b ^ 2 ≤ 5 * (Real.sqrt Q + 1) ^ 2)
    (hMP12 : ∀ t : ℝ, 0 < t → b ^ 2 * smoothingFactor m e ≤ t ^ 2 →
      dualTheta q A t ≤ e)
    (hw : 10 * (Q + 1) * smoothingFactor m e ≤ s ^ 2) :
    dualTheta q A s ≤ e :=
  hMP12 s hs (i1_width_arithmetic hm hQ he hb hw)

/-- TV telescoping for an explicit hybrid chain; construction of each hybrid
from the finite byte-consuming scalar sampler is NOT proved by this lemma. -/
theorem tv_chain {Ω : Type*} [MeasurableSpace Ω] (N : ℕ)
    (law : ℕ → Measure Ω) (cost : ℕ → ℝ)
    (hstep : ∀ i < N, TVWithin (law i) (law (i+1)) (cost i)) :
    TVWithin (law 0) (law N) (∑ i ∈ Finset.range N, cost i) := by
  induction N with
  | zero => simpa using tvWithin_refl (law 0)
  | succ N ih =>
    have hprev := ih (fun i hi => hstep i (Nat.lt_succ_of_lt hi))
    intro E hE
    have hlast := hstep N (Nat.lt_succ_self N) E hE
    have hp := hprev E hE
    rw [Finset.sum_range_succ]
    exact (abs_sub_le (law 0 |>.real E) (law N |>.real E)
      (law (N+1) |>.real E)).trans (add_le_add hp hlast)

/-- I2 budget once explicit raw scalar hybrids have been supplied. This is
not a proof of the Python scalar certificate or variable-consumption coupling. -/
theorem i2_from_raw_hybrids {Ω : Type*} [MeasurableSpace Ω]
    (μ : Measure Ω) (law : ℕ → Measure Ω) (d : ℕ) {eU eZ : ℝ}
    (hU : TVWithin μ (law 0) eU)
    (hZ : ∀ i < d, TVWithin (law i) (law (i+1)) eZ) :
    TVWithin μ (law d) (eU + (d : ℝ)*eZ) := by
  have h := tv_chain d law (fun _ => eZ) hZ
  have hg : TVWithin (law 0) (law d) ((d : ℝ)*eZ) := by simpa using h
  intro E hE
  exact (abs_sub_le (μ.real E) ((law 0).real E) ((law d).real E)).trans
    (add_le_add (hU E hE) (hg E hE))

theorem quality_implies_c2_event {X : Type*} (valid quality c2 : X → Prop)
    (h : ∀ x, valid x → quality x → c2 x) :
    badOutput valid (fun x => quality x ∧ c2 x) = badOutput valid quality := by
  classical
  ext o
  cases o with
  | none => rfl
  | some x =>
    change (¬valid x ∨ ¬(quality x ∧ c2 x)) ↔ (¬valid x ∨ ¬quality x)
    constructor
    · intro hx
      by_cases hv : valid x
      · exact Or.inr (fun hq => hx.elim (fun hn => hn hv) (fun hn => hn ⟨hq, h x hv hq⟩))
      · exact Or.inl hv
    · intro hx
      exact hx.elim Or.inl (fun hq => Or.inr (fun hc => hq hc.1))

/-- I4 for RAW joint laws, including abort once. C2 follows from good quality
only through the explicit `hC2` premise (e.g. the unresolved MP12 bridge). -/
theorem i4_from_joint_tv_and_quality_tail {X : Type*}
    [MeasurableSpace (Option X)] [Countable X]
    [MeasurableSingletonClass (Option X)]
    (μ ν : Measure (Option X)) [IsProbabilityMeasure μ] [IsProbabilityMeasure ν]
    (valid quality c2 : X → Prop) {eGen δR : ℝ}
    (hTV : TVWithin μ ν eGen)
    (hValid : ν.real (invalidOutput valid) = 0)
    (hTail : ν.real (someEvent {x | ¬quality x}) ≤ δR)
    (hC2 : ∀ x, valid x → quality x → c2 x) :
    μ.real (badOutput valid (fun x => quality x ∧ c2 x)) ≤ min 1 (eGen + δR) := by
  rw [quality_implies_c2_event valid quality c2 hC2]
  apply tv_transfer_min hTV (Set.to_countable _).measurableSet
  have heq : badOutput valid quality = invalidOutput valid ∪ someEvent {x | ¬quality x} := by
    ext o
    cases o <;> simp [badOutput, invalidOutput, someEvent]
  rw [heq, probability_union_null ν hValid]
  exact hTail

/-- I3 and I4 composed for a joint ideal setup law, not only one matrix sample.
The projection-law premise specifies the ideal distribution; the radial tail
is derived. The raw TV and quality-to-C2 geometry remain explicit premises. -/
theorem i4_from_gaussian_projection {X : Type*} [Countable X]
    [MeasurableSpace (Option X)] [MeasurableSingletonClass (Option X)]
    (μ ν : Measure (Option X)) [IsProbabilityMeasure μ] [IsProbabilityMeasure ν]
    (valid c2 : X → Prop) (d : ℕ) (R : X → Fin d → ℤ)
    {r Q eGen : ℝ} (hr : 0 < r) (hQ : (d : ℝ)*r^2 ≤ Q)
    (hTV : TVWithin μ ν eGen)
    (hValid : ν.real (invalidOutput valid) = 0)
    (hProjection : ν.map (fun o => match o with
      | none => (fun _ : Fin d => (0 : ℤ))
      | some x => R x) = (idealMasterGaussian d r hr).toMeasure)
    (hC2 : ∀ x, valid x → vectorSq (R x) ≤ Q → c2 x) :
    μ.real (badOutput valid (fun x => vectorSq (R x) ≤ Q ∧ c2 x)) ≤
      min 1 (eGen + (1/2 : ℝ)^d) := by
  apply i4_from_joint_tv_and_quality_tail μ ν valid (fun x => vectorSq (R x) ≤ Q)
    c2 hTV hValid _ hC2
  let project : Option X → Fin d → ℤ := fun o => match o with
    | none => (fun _ => 0)
    | some x => R x
  have hp : Measurable project := measurable_of_countable project
  have ht := idealMasterGaussian_quality_tail d hr hQ
  rw [← hProjection, map_measureReal_apply hp (Set.to_countable _).measurableSet] at ht
  apply (measureReal_mono (μ := ν) ?_).trans ht
  intro o ho
  cases o with
  | none => exact False.elim ho
  | some x => exact lt_of_not_ge ho

end FooLiTotal
