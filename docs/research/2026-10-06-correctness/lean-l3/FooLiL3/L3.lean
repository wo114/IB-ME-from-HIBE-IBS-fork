import FooLiL3.MatrixBounds
import FooLiL3.EventBounds
import FooLiL3.IntegerGaussian

/-!
# L3 conditional assembly (WIP at the C2-to-Gaussian-tail bridge)

`l3_from_column_tail_bounds` proves the matrix/probability assembly.
Its per-column tail hypothesis is explicit; this is not a theorem deriving
the ledger's entire L3 directly from C2 and C3.
-/

noncomputable section
open MeasureTheory
namespace FooLiL3

def ValidDelegation {n m w : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (R : Matrix (Fin m) (Fin w) ℤ) : Prop :=
  ∀ j, InCoset q A (fun i => B i j - G i j) (fun i => R i j)

def QualityGood {m w : ℕ} (Q : ℝ) (R : Matrix (Fin m) (Fin w) ℤ) : Prop :=
  frobSq R ≤ Q ∧ ‖euclideanOp R‖ ^ 2 ≤ Q

def columnLarge {m w : ℕ} (s : ℝ) (j : Fin w) :
    Set (Matrix (Fin m) (Fin w) ℤ) := {R | (m : ℝ) * s ^ 2 < colSq R j}

theorem qualityGood_iff_frobSq {m w : ℕ} (Q : ℝ)
    (R : Matrix (Fin m) (Fin w) ℤ) : QualityGood Q R ↔ frobSq R ≤ Q := by
  exact ⟨fun h => h.1, fun h => ⟨h, (euclideanOp_norm_sq_le_frobSq R).trans h⟩⟩

theorem all_columns_good_implies_quality {m w : ℕ} {s Q : ℝ}
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q)
    (R : Matrix (Fin m) (Fin w) ℤ)
    (h : ∀ j, R ∉ columnLarge s j) : QualityGood Q R := by
  have hc : ∀ j, colSq R j ≤ (m : ℝ) * s ^ 2 := by
    intro j
    exact not_lt.mp (h j)
  exact ⟨frobSq_le_of_columns R hc hQ, euclideanOp_norm_sq_le_of_columns R hc hQ⟩

/-- Actual failure includes abort, invalid modular relation and quality rejection. -/
theorem l3_from_column_tail_bounds {n m w : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    (μ ν : Measure (Option (Matrix (Fin m) (Fin w) ℤ)))
    [IsProbabilityMeasure μ] [IsProbabilityMeasure ν]
    {s Q e εDel : ℝ}
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q)
    (hTV : TVWithin μ ν εDel)
    (hE : MeasurableSet (badOutput (ValidDelegation q A B G) (QualityGood Q)))
    (hSupport : ν.real (invalidOutput (ValidDelegation q A B G)) = 0)
    (hColumnTail : ∀ j : Fin w,
      ν.real (someEvent (columnLarge s j)) ≤ tailBudget m e) :
    μ.real (badOutput (ValidDelegation q A B G) (QualityGood Q)) ≤
      min 1 (εDel + (w : ℝ) * tailBudget m e) := by
  exact actual_badOutput_probability_le μ ν
    (ValidDelegation q A B G) (QualityGood Q) (columnLarge s)
    hTV hE (all_columns_good_implies_quality hQ) hSupport hColumnTail

/-- The public rejection predicate can equivalently check Frobenius alone. -/
theorem badOutput_quality_eq_frobSq {m w : ℕ} (valid : Matrix (Fin m) (Fin w) ℤ → Prop)
    (Q : ℝ) :
    badOutput valid (QualityGood Q) = badOutput valid (fun R => frobSq R ≤ Q) := by
  ext o
  cases o <;> simp [badOutput, qualityGood_iff_frobSq]

/-- Full event-law contract for one ideal column on the actual modular coset.
Independence is not demanded; a C3 ideal product law supplies these marginals.
This definition does not assert that a particular sampler implements the law. -/
def CosetColumnLaw {n m w : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q)
    (hx : Nonempty {x // InCoset q A u x}) (s : ℝ) (hs : 0 < s)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    (ν : Measure (Option (Matrix (Fin m) (Fin w) ℤ))) (j : Fin w) : Prop :=
  ∀ E : Set (Fin m → ℤ),
    ν.real (someEvent {R | (fun i => R i j) ∈ E}) =
      ((cosetGaussian q A u hx s hs).toOuterMeasure {x | x.val ∈ E}).toReal

/-- All probability and matrix steps are linked to exact modular-coset Gaussians.
The remaining `hMass` hypotheses still need a proof from C2; the ideal support
and marginal contracts here must be instantiated by C3's specified ideal law. -/
theorem l3_from_mass_certificates_and_marginals {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    (μ ν : Measure (Option (Matrix (Fin m) (Fin w) ℤ)))
    [IsProbabilityMeasure μ] [IsProbabilityMeasure ν]
    {s Q e εDel : ℝ} (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q)
    (hTV : TVWithin μ ν εDel)
    (hE : MeasurableSet (badOutput (ValidDelegation q A B G) (QualityGood Q)))
    (hSupport : ν.real (invalidOutput (ValidDelegation q A B G)) = 0)
    (hMass : ∀ j : Fin w, CosetMassComparison q A (fun i => B i j - G i j) s e)
    (hMarginal : ∀ j : Fin w,
      CosetColumnLaw q A (fun i => B i j - G i j)
        (coset_nonempty_of_surjective q A hA _) s hs ν j) :
    μ.real (badOutput (ValidDelegation q A B G) (QualityGood Q)) ≤
      min 1 (εDel + (w : ℝ) * tailBudget m e) := by
  apply l3_from_column_tail_bounds q A B G μ ν hQ hTV hE hSupport
  intro j
  let u : Fin n → ZMod q := fun i => B i j - G i j
  have hx := coset_nonempty_of_surjective q A hA u
  have hl := hMarginal j {x | (m : ℝ) * s ^ 2 ≤ vectorSq x}
  calc
    ν.real (someEvent (columnLarge s j)) ≤
        ν.real (someEvent {R | (m : ℝ) * s ^ 2 ≤ vectorSq (fun i => R i j)}) := by
      apply measureReal_mono (μ := ν) ?_ (by finiteness)
      intro o ho
      cases o with
      | none => exact False.elim ho
      | some R =>
        change (m : ℝ) * s ^ 2 < colSq R j at ho
        change (m : ℝ) * s ^ 2 ≤ vectorSq (fun i => R i j)
        exact ho.le
    _ = ((cosetGaussian q A u hx s hs).toOuterMeasure
        {x | (m : ℝ) * s ^ 2 ≤ vectorSq x.val}).toReal := hl
    _ = _ := gaussianPMF_outer_event _ _ _ _ _
    _ ≤ tailBudget m e := coset_tail_from_mass_comparison q A u hx hs he he1 (hMass j)

end FooLiL3
