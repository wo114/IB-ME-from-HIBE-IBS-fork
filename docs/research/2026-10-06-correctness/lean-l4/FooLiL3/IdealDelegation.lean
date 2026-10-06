import FooLiL3.L3
import Mathlib.Probability.ProbabilityMassFunction.Constructions
import Mathlib.Logic.Encodable.Pi

/-!
# C3's independent ideal delegation law

The ideal law is constructed by independent monadic sampling, not by assuming
its marginals.  `independentFinPMF_rectangle` certifies the product law.
The actual finite sampler and its total-variation guarantee remain separate.
-/

noncomputable section
open MeasureTheory
open scoped BigOperators
namespace FooLiL3

/-- A finite dependent product of PMFs, including the empty product. -/
def independentFinPMF : {w : ℕ} → (X : Fin w → Type*) →
    (∀ j, PMF (X j)) → PMF (∀ j, X j)
  | 0, _, _ => PMF.pure (fun j => Fin.elim0 j)
  | w + 1, X, p =>
    (p 0).bind (fun a =>
      (independentFinPMF (fun j : Fin w => X j.succ) (fun j => p j.succ)).map
        (fun x => Fin.cons a x))

/-- Every coordinate marginal is the specified PMF, proved from the construction. -/
theorem independentFinPMF_marginal {w : ℕ} (X : Fin w → Type*)
    (p : ∀ j, PMF (X j)) (j : Fin w) :
    (independentFinPMF X p).map (fun x => x j) = p j := by
  induction w with
  | zero => exact Fin.elim0 j
  | succ w ih =>
    rw [independentFinPMF, PMF.map_bind]
    induction j using Fin.cases with
    | zero =>
      simp only [PMF.map_comp, Function.comp_def, Fin.cons_zero]
      change ((p 0).bind (fun a =>
        (independentFinPMF (fun j : Fin w => X j.succ) (fun j => p j.succ)).map
          (Function.const _ a))) = p 0
      simp only [PMF.map_const, PMF.bind_pure]
    | succ j =>
      simp only [PMF.map_comp, Function.comp_def, Fin.cons_succ, ih, PMF.bind_const]

/-- Rectangular events factor exactly; hence this is the independent product law. -/
theorem independentFinPMF_rectangle {w : ℕ} (X : Fin w → Type*)
    (p : ∀ j, PMF (X j)) (S : ∀ j, Set (X j)) :
    (independentFinPMF X p).toOuterMeasure {x | ∀ j, x j ∈ S j} =
      ∏ j, (p j).toOuterMeasure (S j) := by
  classical
  induction w with
  | zero =>
    have hset : {x : ∀ j : Fin 0, X j | ∀ j, x j ∈ S j} = Set.univ := by
      ext x
      simp
    rw [hset]
    rw [Fin.prod_univ_zero]
    exact (PMF.toOuterMeasure_apply_eq_one_iff _ _).mpr (Set.subset_univ _)
  | succ w ih =>
    rw [independentFinPMF, PMF.toOuterMeasure_bind_apply, Fin.prod_univ_succ]
    have hpre (a : X 0) :
        (fun x : ∀ j : Fin w, X j.succ => Fin.cons a x) ⁻¹'
            {x | ∀ j, x j ∈ S j} =
          if a ∈ S 0 then {x | ∀ j : Fin w, x j ∈ S j.succ} else ∅ := by
      ext x
      by_cases ha : a ∈ S 0 <;> simp [Fin.forall_fin_succ, ha]
    simp_rw [PMF.toOuterMeasure_map_apply, hpre]
    have hterm (a : X 0) :
        p 0 a *
          (independentFinPMF (fun j : Fin w => X j.succ) (fun j => p j.succ)).toOuterMeasure
            (if a ∈ S 0 then {x | ∀ j : Fin w, x j ∈ S j.succ} else ∅) =
        (S 0).indicator (p 0) a * ∏ j : Fin w, (p j.succ).toOuterMeasure (S j.succ) := by
      by_cases ha : a ∈ S 0 <;> simp [ha, ih]
    simp_rw [hterm]
    rw [ENNReal.tsum_mul_right, ← PMF.toOuterMeasure_apply]

/-- Point masses also factor exactly, including the zero-column case. -/
theorem independentFinPMF_apply {w : ℕ} (X : Fin w → Type*)
    (p : ∀ j, PMF (X j)) (x : ∀ j, X j) :
    independentFinPMF X p x = ∏ j, p j (x j) := by
  have h := independentFinPMF_rectangle X p (fun j => {x j})
  have hset : {y : ∀ j, X j | ∀ j, y j ∈ ({x j} : Set (X j))} = {x} := by
    ext y
    simp only [Set.mem_ofPred_eq, Set.mem_singleton_iff]
    exact funext_iff.symm
  rw [hset, PMF.toOuterMeasure_apply_singleton] at h
  simpa only [PMF.toOuterMeasure_apply_singleton] using h

/-- C3's tuple of independent, untruncated Gaussian coset columns. -/
def idealColumnsPMF {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s) :
    PMF (∀ j : Fin w, {x // InCoset q A (fun i => B i j - G i j) x}) :=
  independentFinPMF _ (fun j =>
    cosetGaussian q A (fun i => B i j - G i j)
      (coset_nonempty_of_surjective q A hA _) s hs)

/-- The matrix-valued raw ideal output. Ideal sampling never aborts. -/
def idealDelegationPMF {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s) :
    PMF (Option (Matrix (Fin m) (Fin w) ℤ)) :=
  (idealColumnsPMF q A B G hA s hs).map
    (fun x => some (fun i j => (x j).val i))

/-- The ideal law as a probability measure, on the same raw space as the sampler. -/
def idealDelegationMeasure {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))] :
    Measure (Option (Matrix (Fin m) (Fin w) ℤ)) :=
  (idealDelegationPMF q A B G hA s hs).toMeasure

instance idealDelegationMeasure_isProbabilityMeasure {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))] :
    IsProbabilityMeasure (idealDelegationMeasure q A B G hA s hs) := by
  unfold idealDelegationMeasure
  infer_instance

/-- Independence is retained by assembling the columns into a matrix. -/
theorem idealDelegationMeasure_rectangle {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin m) (Fin w) ℤ))]
    (S : Fin w → Set (Fin m → ℤ)) :
    idealDelegationMeasure q A B G hA s hs
      (someEvent {R | ∀ j, (fun i => R i j) ∈ S j}) =
      ∏ j, (cosetGaussian q A (fun i => B i j - G i j)
        (coset_nonempty_of_surjective q A hA _) s hs).toOuterMeasure
          {x | x.val ∈ S j} := by
  rw [idealDelegationMeasure, PMF.toMeasure_apply_eq_toOuterMeasure,
    idealDelegationPMF, PMF.toOuterMeasure_map_apply]
  exact independentFinPMF_rectangle
    (fun j : Fin w => {x // InCoset q A (fun i => B i j - G i j) x})
    (fun j => cosetGaussian q A (fun i => B i j - G i j)
      (coset_nonempty_of_surjective q A hA _) s hs)
    (fun j => {x | x.val ∈ S j})

/-- Algebraic invalidity and abort have exactly zero ideal probability. -/
theorem idealDelegationMeasure_invalidOutput {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin m) (Fin w) ℤ))] :
    (idealDelegationMeasure q A B G hA s hs).real
      (invalidOutput (ValidDelegation q A B G)) = 0 := by
  rw [Measure.real, idealDelegationMeasure,
    PMF.toMeasure_apply_eq_toOuterMeasure, idealDelegationPMF,
    PMF.toOuterMeasure_map_apply]
  have hpre : (fun x : ∀ j : Fin w,
      {x // InCoset q A (fun i => B i j - G i j) x} =>
        some (fun i j => (x j).val i)) ⁻¹'
        invalidOutput (ValidDelegation q A B G) = ∅ := by
    ext x
    simp only [Set.mem_preimage, invalidOutput, Set.mem_ofPred_eq, Set.mem_empty_iff_false,
      iff_false, not_not]
    exact fun j => (x j).property
  exact (congrArg (fun E =>
    ((idealColumnsPMF q A B G hA s hs).toOuterMeasure E).toReal) hpre).trans
      (by simp only [measure_empty, ENNReal.toReal_zero])

/-- Each matrix column has the complete (not only tail-event) Gaussian marginal. -/
theorem idealDelegationMeasure_columnLaw {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin m) (Fin w) ℤ))]
    (j : Fin w) :
    CosetColumnLaw q A (fun i => B i j - G i j)
      (coset_nonempty_of_surjective q A hA _) s hs
      (idealDelegationMeasure q A B G hA s hs) j := by
  intro E
  rw [Measure.real, idealDelegationMeasure,
    PMF.toMeasure_apply_eq_toOuterMeasure, idealDelegationPMF,
    PMF.toOuterMeasure_map_apply]
  have hm := independentFinPMF_marginal
    (fun j : Fin w => {x // InCoset q A (fun i => B i j - G i j) x})
    (fun j => cosetGaussian q A (fun i => B i j - G i j)
      (coset_nonempty_of_surjective q A hA _) s hs) j
  have he := congrArg (fun p => p.toOuterMeasure {x | x.val ∈ E}) hm
  rw [PMF.toOuterMeasure_map_apply] at he
  exact congrArg ENNReal.toReal he

/-- L3 for the constructed C3 product law: support and marginals are no longer inputs.
Only the actual-to-ideal TV contract and the C2 mass certificates remain analytical inputs.
All subsets of the countable output space are measurable under the singleton hypothesis. -/
theorem l3_from_mass_certificates_and_product_ideal {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin m) (Fin w) ℤ))]
    (μ : Measure (Option (Matrix (Fin m) (Fin w) ℤ))) [IsProbabilityMeasure μ]
    {s Q e εDel : ℝ} (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q)
    (hTV : TVWithin μ (idealDelegationMeasure q A B G hA s hs) εDel)
    (hMass : ∀ j : Fin w, CosetMassComparison q A (fun i => B i j - G i j) s e) :
    μ.real (badOutput (ValidDelegation q A B G) (QualityGood Q)) ≤
      min 1 (εDel + (w : ℝ) * tailBudget m e) := by
  let : Countable (Matrix (Fin m) (Fin w) ℤ) :=
    inferInstanceAs (Countable (Fin m → Fin w → ℤ))
  apply l3_from_mass_certificates_and_marginals q A B G hA μ
    (idealDelegationMeasure q A B G hA s hs) hs he he1 hQ hTV
    (Set.to_countable _).measurableSet
    (idealDelegationMeasure_invalidOutput q A B G hA s hs) hMass
  exact idealDelegationMeasure_columnLaw q A B G hA s hs

end FooLiL3
