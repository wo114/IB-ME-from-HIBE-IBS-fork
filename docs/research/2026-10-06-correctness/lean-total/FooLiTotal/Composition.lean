import FooLiTotal.Model
import FooLiL4.L4
import FooLiL3.ClosedL3
import FooLiL1

/-! Actual PMF binds, with explicit good-state uniform contracts.
This is a specification law, not a certified translation of Python execution.
-/
noncomputable section
open MeasureTheory FooLiL3 FooLiL4 FooLiL2 FooLiL2.Cosets
open scoped BigOperators
namespace FooLiTotal

/-- Stage composition: failures on bad previous states cost at most their mass;
every good previous state has the same error bound. No independence premise. -/
theorem bind_event_bound {X Y : Type*} [MeasurableSpace X] [MeasurableSpace Y]
    [MeasurableSingletonClass X] [MeasurableSingletonClass Y]
    (p : PMF X) (next : X → PMF Y) (bad : Set X) (E : Set Y)
    {b : ℝ} (hb : 0 ≤ b)
    (hgood : ∀ x, x ∉ bad → (next x).toMeasure.real E ≤ b) :
    (p.bind next).toMeasure.real E ≤ p.toMeasure.real bad + b := by
  classical
  have hstep (x : X) : (next x).toMeasure E ≤
      (if x ∈ bad then 1 else 0) + ENNReal.ofReal b := by
    by_cases hx : x ∈ bad
    · simp only [hx, ite_true]
      have hle : (next x).toMeasure E ≤ 1 := by
        simpa using (measure_mono (μ := (next x).toMeasure) (Set.subset_univ E))
      exact hle.trans (le_self_add)
    · simp only [hx, ite_false, zero_add]
      have hh := ENNReal.ofReal_le_ofReal (hgood x hx)
      simpa only [Measure.real, ENNReal.ofReal_toReal (measure_ne_top _ _)] using hh
  have hbound : (p.bind next).toMeasure E ≤ p.toMeasure bad + ENNReal.ofReal b := by
    rw [PMF.toMeasure_apply_eq_toOuterMeasure, PMF.toOuterMeasure_bind_apply]
    calc
      _ ≤ ∑' x, p x * ((if x ∈ bad then 1 else 0) + ENNReal.ofReal b) := by
        apply ENNReal.tsum_le_tsum
        intro x
        rw [← PMF.toMeasure_apply_eq_toOuterMeasure]
        exact mul_le_mul_of_nonneg_left (hstep x) zero_le
      _ = p.toMeasure bad + ENNReal.ofReal b := by
        simp_rw [mul_add]
        rw [ENNReal.tsum_add, ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]
        congr 1
        rw [PMF.toMeasure_apply_eq_tsum]
        apply tsum_congr
        intro x
        by_cases hx : x ∈ bad <;> simp [hx]
  have ht := ENNReal.toReal_mono (by finiteness) hbound
  simpa only [Measure.real, ENNReal.toReal_add (measure_ne_top _ _) ENNReal.ofReal_ne_top,
    ENNReal.toReal_ofReal hb] using ht

def delegationBad {n m w : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q)) (Q : ℝ) :=
  badOutput (ValidDelegation q A B G) (QualityGood Q)

/-- Composition for a fixed good master state. L3 and L4 are called, not
replaced by premises asserting their final probability bounds.
The next-law contract is uniform over every valid quality-qualified user key. -/
theorem fixed_master_l3_l4 {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (u : Fin n → ZMod q)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSpace (SignatureOutput (m+w))]
    [MeasurableSingletonClass (SignatureOutput (m+w))]
    (del : PMF (Option (Matrix (Fin m) (Fin w) ℤ)))
    (sign : Option (Matrix (Fin m) (Fin w) ℤ) → PMF (SignatureOutput (m+w)))
    {s t e Q εDel εSP : ℝ} (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m)
    (he : 0 < e) (heQuarter : e ≤ 1/4) (hSP : 0 ≤ εSP)
    (hTheta : dualTheta q (liftMatrix q A) s ≤ e)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q)
    (hC3 : TVWithin del.toMeasure (idealDelegationMeasure q A B G hA s hs) εDel)
    (hC4 : ∀ R, R ∉ delegationBad q A B G Q → TVWithin (sign R).toMeasure
      (idealSignatureMeasure q (modMatrix q (appendMatrix (liftMatrix q A) (liftMatrix q B)))
        (fullRowRank_append q _ _ ((fullRowRank_liftMatrix_iff A).mpr hA))
        u t (hs.trans_le hst)) εSP) :
    (del.bind sign).toMeasure.real
        (signatureFailure q (modMatrix q (appendMatrix (liftMatrix q A) (liftMatrix q B))) u t) ≤
      min 1 (εDel + (w : ℝ) * tailBudget m e + εSP + tailBudget (m+w) (2*e+e^2)) := by
  have he1 : e < 1 := by linarith
  have hef : 2*e+e^2 < 1 := by nlinarith [sq_nonneg (e-1/4)]
  have hf0 : 0 ≤ 2*e+e^2 := by positivity
  have hDel := l3_from_smoothing_and_product_ideal q A B G hA del.toMeasure
    hs he.le he1 hTheta hQ hC3
  have hbind := bind_event_bound del sign (delegationBad q A B G Q)
    (signatureFailure q (modMatrix q (appendMatrix (liftMatrix q A) (liftMatrix q B))) u t)
    (add_nonneg hSP (tailBudget_nonneg (m+w) hf0 hef)) (by
      intro R hR
      exact (l4_from_c2_c4 q (liftMatrix q A) (liftMatrix q B)
        ((fullRowRank_liftMatrix_iff A).mpr hA) u (sign R).toMeasure
        hs hst hw he heQuarter hTheta (hC4 R hR)).trans (min_le_right _ _))
  apply le_min measureReal_le_one
  have hd := hDel.trans (min_le_right _ _)
  change del.toMeasure.real (delegationBad q A B G Q) ≤ _ at hd
  linarith

/-- Setup -> downstream honest experiment. The second bound must be uniform
over good initialized states, not a bound for only one sampled state. -/
theorem setup_composition {X Y : Type*} [MeasurableSpace X] [MeasurableSpace Y]
    [MeasurableSingletonClass X] [MeasurableSingletonClass Y]
    (setup : PMF X) (rest : X → PMF Y) (initBad : Set X) (failure : Set Y)
    {δ b : ℝ} (hb : 0 ≤ b)
    (hInit : setup.toMeasure.real initBad ≤ δ)
    (hRest : ∀ x, x ∉ initBad → (rest x).toMeasure.real failure ≤ b) :
    (setup.bind rest).toMeasure.real failure ≤ min 1 (δ+b) := by
  apply le_min measureReal_le_one
  exact (bind_event_bound setup rest initBad failure hb hRest).trans (add_le_add hInit le_rfl)

/-- The complete budget shape. Its setup bound and uniform downstream law
still need instantiation by the actual runtime and the MP12 geometry proof. -/
theorem total_correctness_budget {X Y : Type*} [MeasurableSpace X] [MeasurableSpace Y]
    [MeasurableSingletonClass X] [MeasurableSingletonClass Y]
    (setup : PMF X) (rest : X → PMF Y) (initBad : Set X) (failure : Set Y)
    {m w : ℕ} {e δ εDel εSP εHash : ℝ}
    (hb : 0 ≤ εDel + (w : ℝ)*tailBudget m e + εSP + tailBudget (m+w) (2*e+e^2) + εHash)
    (hInit : setup.toMeasure.real initBad ≤ δ)
    (hRest : ∀ x, x ∉ initBad → (rest x).toMeasure.real failure ≤
      εDel + (w : ℝ)*tailBudget m e + εSP + tailBudget (m+w) (2*e+e^2) + εHash) :
    (setup.bind rest).toMeasure.real failure ≤
      min 1 (δ + εDel + (w : ℝ)*tailBudget m e + εSP + tailBudget (m+w) (2*e+e^2) + εHash) := by
  simpa only [add_assoc] using setup_composition setup rest initBad failure hb hInit hRest

end FooLiTotal
