import FooLiTotal.Composition

/-! Honest failure-bit experiment. The entire setup/hash law and sampler laws
remain inputs: there is no Python refinement theorem in this file. -/
noncomputable section
open MeasureTheory FooLiL3 FooLiL4 FooLiL2 FooLiL2.Cosets
namespace FooLiTotal

def eventBit {X : Type*} (E : Set X) (x : X) : Bool := by
  classical
  exact if x ∈ E then true else false

def eventLaw {X : Type*} (p : PMF X) (E : Set X) : PMF Bool := p.map (eventBit E)

/-- Bad previous states are absorbing failures, even if the supplied next
kernel would otherwise return a valid output on them. -/
def stopOnBad {X Y : Type*} (bad : Set X) (next : X → PMF (Option Y)) :
    X → PMF (Option Y) := by
  classical
  exact fun x => if x ∈ bad then PMF.pure none else next x

theorem stopOnBad_bad {X Y : Type*} (bad : Set X) (next : X → PMF (Option Y))
    (x : X) (hx : x ∈ bad) : stopOnBad bad next x = PMF.pure none := by
  simp [stopOnBad, hx]

theorem stopOnBad_good {X Y : Type*} (bad : Set X) (next : X → PMF (Option Y))
    (x : X) (hx : x ∉ bad) : stopOnBad bad next x = next x := by
  simp [stopOnBad, hx]

theorem eventLaw_failure {X : Type*} [MeasurableSpace X]
    [MeasurableSingletonClass X] (p : PMF X) (E : Set X) :
    (eventLaw p E).toMeasure.real {true} = p.toMeasure.real E := by
  classical
  have hpre : eventBit E ⁻¹' {true} = E := by
    ext x
    simp [eventBit]
  unfold Measure.real eventLaw
  rw [PMF.toMeasure_apply_eq_toOuterMeasure, PMF.toOuterMeasure_map_apply,
    PMF.toMeasure_apply_eq_toOuterMeasure, hpre]

/-- This checked theorem actually invokes L3 and L4 for every good master.
Bad setup/hash states give failure bit true. For good states the signature
failure predicate contains abort, invalid syndrome and excessive integer norm.
The mass of bad setup/hash states is explicit, not erased by conditioning. -/
theorem t1_from_uniform_stage_contracts {S : Type*}
    [MeasurableSpace S] [MeasurableSingletonClass S]
    {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : S → Matrix (Fin n) (Fin m) (ZMod q))
    (B : S → Matrix (Fin n) (Fin w) (ZMod q))
    (G : Matrix (Fin n) (Fin w) (ZMod q))
    (rank : ∀ x, Function.Surjective (A x).mulVec)
    (u : S → Fin n → ZMod q)
    [MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSingletonClass (Option (Matrix (Fin m) (Fin w) ℤ))]
    [MeasurableSpace (SignatureOutput (m+w))]
    [MeasurableSingletonClass (SignatureOutput (m+w))]
    (setup : PMF S) (bad : Set S) [DecidablePred (· ∈ bad)]
    (del : S → PMF (Option (Matrix (Fin m) (Fin w) ℤ)))
    (sign : S → Option (Matrix (Fin m) (Fin w) ℤ) → PMF (SignatureOutput (m+w)))
    {s t e Q δ εHash εDel εSP : ℝ}
    (hs : 0 < s) (hst : s ≤ t) (hw : w ≤ m) (he : 0 < e) (heQuarter : e ≤ 1/4)
    (hD : 0 ≤ εDel) (hSP : 0 ≤ εSP)
    (hInitHash : setup.toMeasure.real bad ≤ δ + εHash)
    (hTheta : ∀ x, x ∉ bad → dualTheta q (liftMatrix q (A x)) s ≤ e)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q)
    (hC3 : ∀ x, x ∉ bad → TVWithin (del x).toMeasure
      (idealDelegationMeasure q (A x) (B x) G (rank x) s hs) εDel)
    (hC4 : ∀ x, x ∉ bad → ∀ R, R ∉ delegationBad q (A x) (B x) G Q →
      TVWithin (sign x R).toMeasure
        (idealSignatureMeasure q
          (modMatrix q (appendMatrix (liftMatrix q (A x)) (liftMatrix q (B x))))
          (fullRowRank_append q _ _ ((fullRowRank_liftMatrix_iff (A x)).mpr (rank x)))
          (u x) t (hs.trans_le hst)) εSP) :
    (setup.bind (fun x => if x ∈ bad then PMF.pure true else
      eventLaw ((del x).bind (stopOnBad (delegationBad q (A x) (B x) G Q) (sign x)))
        (signatureFailure q
          (modMatrix q (appendMatrix (liftMatrix q (A x)) (liftMatrix q (B x)))) (u x) t))).toMeasure.real {true} ≤
      min 1 (δ + εDel + (w : ℝ)*tailBudget m e + εSP + tailBudget (m+w) (2*e+e^2) + εHash) := by
  classical
  have he1 : e < 1 := by linarith
  have hef : 2*e+e^2 < 1 := by nlinarith [sq_nonneg (e-1/4)]
  have hpos : 0 ≤ εDel + (w : ℝ)*tailBudget m e + εSP + tailBudget (m+w) (2*e+e^2) := by
    have ht0 := tailBudget_nonneg m he.le he1
    have ht1 := tailBudget_nonneg (m+w) (show 0 ≤ 2*e+e^2 by positivity) hef
    positivity
  have h := setup_composition setup
    (fun x => if x ∈ bad then PMF.pure true else
      eventLaw ((del x).bind (stopOnBad (delegationBad q (A x) (B x) G Q) (sign x)))
      (signatureFailure q
        (modMatrix q (appendMatrix (liftMatrix q (A x)) (liftMatrix q (B x)))) (u x) t))
    bad {true} hpos hInitHash (by
      intro x hx
      simp only [hx, ↓reduceIte, eventLaw_failure]
      exact (fixed_master_l3_l4 q (A x) (B x) G (rank x) (u x) (del x)
        (stopOnBad (delegationBad q (A x) (B x) G Q) (sign x))
        hs hst hw he heQuarter hSP (hTheta x hx) hQ (hC3 x hx) (by
          intro R hR
          rw [stopOnBad_good _ _ R hR]
          exact hC4 x hx R hR)).trans
        (min_le_right _ _))
  convert h using 1
  congr 1
  ring

/-- L1's actual integer p+[-R;I]z expression passes the algebraic verifier;
the norm bound is separate, with equality accepted. -/
theorem l1_accepts_with_norm {q n m w : ℕ}
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (R : Matrix (Fin m) (Fin w) ℤ)
    (p : (Fin m ⊕ Fin w) → ℤ) (z : Fin w → ℤ) (u : Fin n → ZMod q) (t : ℝ)
    (hB : B = A * FooLiL1.reduceMat q R + G)
    (hz : G.mulVec (FooLiL1.reduceVec q z) =
      u - (Matrix.fromCols A B).mulVec (FooLiL1.reduceVec q p))
    (hnorm : NormGood t (FooLiL1.flattenVec (FooLiL1.signature R p z))) :
    signatureAccepts q (FooLiL1.flattenCols (Matrix.fromCols A B)) u t
      (some (FooLiL1.flattenVec (FooLiL1.signature R p z))) := by
  exact ⟨FooLiL1.flattened_signature_equation A B G R p z u hB hz, hnorm⟩

end FooLiTotal
