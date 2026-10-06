import FooLiL4.IdealSignature
import FooLiL2.L2

/-! Conditional L4: the C2/L2 smoothing bridge plus the explicit raw C4 contract. -/
noncomputable section
open MeasureTheory Matrix FooLiL2 FooLiL2.Cosets
namespace FooLiL4
open FooLiL3

/-- Only raw TV and genuine dual mass remain; neither the ideal tail nor support is assumed. -/
theorem l4_from_smoothing_c4 {n D : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin D) ℤ) (hC : FullRowRank q C) (u : Fin n → ZMod q)
    [MeasurableSpace (SignatureOutput D)] [MeasurableSingletonClass (SignatureOutput D)]
    (μ : Measure (SignatureOutput D)) [IsProbabilityMeasure μ]
    {t e εSP : ℝ} (ht : 0 < t) (he : 0 ≤ e) (he1 : e < 1)
    (hTheta : dualTheta q C t ≤ e)
    (hC4 : TVWithin μ (idealSignatureMeasure q (modMatrix q C) hC u t ht) εSP) :
    μ.real (signatureFailure q (modMatrix q C) u t) ≤ min 1 (εSP + tailBudget D e) := by
  apply tv_transfer_min hC4 (Set.to_countable _).measurableSet
  exact idealSignature_failure_le q (modMatrix q C) hC u ht he he1
    (massComparison_of_integer_smoothing q C hC u ht he he1 hTheta)

/-- Ledger-facing extension theorem. C2 holds for the fixed main matrix; C4 is still a premise. -/
theorem l4_from_c2_c4 {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (hA : FullRowRank q A) (u : Fin n → ZMod q)
    [MeasurableSpace (SignatureOutput (m + w))]
    [MeasurableSingletonClass (SignatureOutput (m + w))]
    (μ : Measure (SignatureOutput (m + w))) [IsProbabilityMeasure μ]
    {s t e εSP : ℝ} (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m)
    (he : 0 < e) (heQuarter : e ≤ 1 / 4)
    (hC2 : dualTheta q A s ≤ e)
    (hC4 : TVWithin μ
      (idealSignatureMeasure q (modMatrix q (appendMatrix A B))
        (fullRowRank_append q A B hA) u t (hs.trans_le hst)) εSP) :
    μ.real (signatureFailure q (modMatrix q (appendMatrix A B)) u t) ≤
      min 1 (εSP + tailBudget (m + w) (2 * e + e ^ 2)) := by
  have hL2 := l2_qary_mass_extension q A B hA hs hst hw hC2 he heQuarter
  exact l4_from_smoothing_c4 q (appendMatrix A B) (fullRowRank_append q A B hA) u μ
    (hs.trans_le hst) hL2.2.1.le hL2.2.2.1 hL2.1 hC4

/-- The same result for an explicitly defined finite uniform-tape program.
The TV premise must still be proved for that particular program. -/
theorem l4_for_uniform_tape_program {n m w L : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (hA : FullRowRank q A) (u : Fin n → ZMod q)
    [MeasurableSpace (SignatureOutput (m + w))]
    [MeasurableSingletonClass (SignatureOutput (m + w))]
    (program : ByteTape L → SignatureOutput (m + w))
    {s t e εSP : ℝ} (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m)
    (he : 0 < e) (heQuarter : e ≤ 1 / 4)
    (hC2 : dualTheta q A s ≤ e)
    (hC4 : TVWithin (rawTapeMeasure program)
      (idealSignatureMeasure q (modMatrix q (appendMatrix A B))
        (fullRowRank_append q A B hA) u t (hs.trans_le hst)) εSP) :
    (rawTapeMeasure program).real (signatureFailure q (modMatrix q (appendMatrix A B)) u t) ≤
      min 1 (εSP + tailBudget (m + w) (2 * e + e ^ 2)) := by
  exact l4_from_c2_c4 q A B hA u (rawTapeMeasure program) hs hst hw he heQuarter hC2 hC4

/-- C2's standard master relation supplies rank; no separate rank premise remains. -/
theorem l4_from_master_relation {q n r k : ℕ} [NeZero q]
    (A : Matrix (Fin n) (Fin (r + n * (k + 1))) (ZMod q))
    (R₀ : Matrix (Fin r) (Fin (n * (k + 1))) ℤ)
    (B : Matrix (Fin n) (Fin (n * (k + 1))) (ZMod q))
    (hmaster : A *
      (((fromRows R₀ (1 : Matrix (Fin (n * (k + 1))) (Fin (n * (k + 1))) ℤ)).map
        (Int.castRingHom (ZMod q))).submatrix finSumFinEquiv.symm id) =
      (powersGadget n k (2 : ZMod q)).submatrix id finProdFinEquiv.symm)
    (u : Fin n → ZMod q)
    [MeasurableSpace (SignatureOutput ((r + n * (k + 1)) + n * (k + 1)))]
    [MeasurableSingletonClass (SignatureOutput ((r + n * (k + 1)) + n * (k + 1)))]
    (μ : Measure (SignatureOutput ((r + n * (k + 1)) + n * (k + 1))))
    [IsProbabilityMeasure μ]
    {s t e εSP : ℝ} (hs : 0 < s) (hst : s ≤ t) (he : 0 < e) (heQuarter : e ≤ 1 / 4)
    (hC2 : dualTheta q (liftMatrix q A) s ≤ e)
    (hC4 : TVWithin μ
      (idealSignatureMeasure q (modMatrix q (appendMatrix (liftMatrix q A) (liftMatrix q B)))
        (fullRowRank_append q _ _ ((fullRowRank_liftMatrix_iff A).mpr
          (standard_master_relation_surjective A R₀ (2 : ZMod q) hmaster)))
        u t (hs.trans_le hst)) εSP) :
    μ.real (signatureFailure q (modMatrix q (appendMatrix (liftMatrix q A) (liftMatrix q B))) u t) ≤
      min 1 (εSP + tailBudget ((r + n * (k + 1)) + n * (k + 1)) (2 * e + e ^ 2)) := by
  exact l4_from_c2_c4 q (liftMatrix q A) (liftMatrix q B)
    ((fullRowRank_liftMatrix_iff A).mpr
      (standard_master_relation_surjective A R₀ (2 : ZMod q) hmaster))
    u μ hs hst (Nat.le_add_left _ _) he heQuarter hC2 hC4

end FooLiL4
