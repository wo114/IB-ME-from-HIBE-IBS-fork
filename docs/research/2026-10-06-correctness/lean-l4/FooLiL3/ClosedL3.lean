import FooLiL3.SmoothingBridge
import FooLiL3.IdealDelegation
import FooLiL3.SetupRank

/-!
# L3 from the ledger's fixed-good-initialization C2/C3 premises

No coset mass, tail, ideal support, or marginal hypothesis remains.
This does not prove the implementation's C2 probability or C3 TV contract.
-/
noncomputable section
open MeasureTheory Matrix FooLiL2 FooLiL2.Cosets
namespace FooLiL3

theorem l3_from_smoothing_and_product_ideal {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin m) (Fin w) ℤ))]
    (μ : Measure (Option (Matrix (Fin m) (Fin w) ℤ))) [IsProbabilityMeasure μ]
    {s Q e εDel : ℝ} (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hTheta : dualTheta q (liftMatrix q A) s ≤ e)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q)
    (hTV : TVWithin μ (idealDelegationMeasure q A B G hA s hs) εDel) :
    μ.real (badOutput (ValidDelegation q A B G) (QualityGood Q)) ≤
      min 1 (εDel + (w : ℝ) * tailBudget m e) := by
  apply l3_from_mass_certificates_and_product_ideal q A B G hA μ hs he he1 hQ hTV
  intro j
  exact cosetMassComparison_of_smoothing q A hA _ hs he he1 hTheta

/-- Ledger-facing standard binary gadget: the valid master relation supplies rank.
Here `r` denotes the unextended block width and `k+1` the gadget bit width;
the public width is `r+n*(k+1)` and the number of delegated columns is `n*(k+1)`.
The ledger's `0<e≤1/4` implies the slightly more general `0≤e<1` used here. -/
theorem l3_from_c2_c3 {q n r k : ℕ} [NeZero q]
    (A : Matrix (Fin n) (Fin (r + n * (k + 1))) (ZMod q))
    (R₀ : Matrix (Fin r) (Fin (n * (k + 1))) ℤ)
    (B : Matrix (Fin n) (Fin (n * (k + 1))) (ZMod q))
    (hmaster : A *
      (((fromRows R₀ (1 : Matrix (Fin (n * (k + 1))) (Fin (n * (k + 1))) ℤ)).map
        (Int.castRingHom (ZMod q))).submatrix finSumFinEquiv.symm id) =
      (powersGadget n k (2 : ZMod q)).submatrix id finProdFinEquiv.symm)
    [MeasurableSpace (Option (Matrix (Fin (r + n * (k + 1))) (Fin (n * (k + 1))) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin (r + n * (k + 1))) (Fin (n * (k + 1))) ℤ))]
    (μ : Measure (Option (Matrix (Fin (r + n * (k + 1))) (Fin (n * (k + 1))) ℤ)))
    [IsProbabilityMeasure μ]
    {s Q e εDel : ℝ} (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hTheta : dualTheta q (liftMatrix q A) s ≤ e)
    (hQ : ((r + n * (k + 1) : ℕ) : ℝ) * ((n * (k + 1) : ℕ) : ℝ) * s ^ 2 ≤ Q)
    (hTV : TVWithin μ
      (idealDelegationMeasure q A B
        ((powersGadget n k (2 : ZMod q)).submatrix id finProdFinEquiv.symm)
        (standard_master_relation_surjective A R₀ (2 : ZMod q) hmaster) s hs) εDel) :
    μ.real (badOutput
      (ValidDelegation q A B ((powersGadget n k (2 : ZMod q)).submatrix id finProdFinEquiv.symm))
      (QualityGood Q)) ≤
        min 1 (εDel + ((n * (k + 1) : ℕ) : ℝ) * tailBudget (r + n * (k + 1)) e) := by
  exact l3_from_smoothing_and_product_ideal q A B _
    (standard_master_relation_surjective A R₀ (2 : ZMod q) hmaster)
    μ hs he he1 hTheta hQ hTV

end FooLiL3
