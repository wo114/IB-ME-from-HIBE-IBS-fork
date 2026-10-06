import FooLiL3.IdealDelegation

noncomputable section
open MeasureTheory
open FooLiL3

#print axioms FooLiL3.independentFinPMF
#print axioms FooLiL3.independentFinPMF_marginal
#print axioms FooLiL3.independentFinPMF_rectangle
#print axioms FooLiL3.independentFinPMF_apply
#print axioms FooLiL3.idealColumnsPMF
#print axioms FooLiL3.idealDelegationPMF
#print axioms FooLiL3.idealDelegationMeasure
#print axioms FooLiL3.idealDelegationMeasure_isProbabilityMeasure
#print axioms FooLiL3.idealDelegationMeasure_rectangle
#print axioms FooLiL3.idealDelegationMeasure_invalidOutput
#print axioms FooLiL3.idealDelegationMeasure_columnLaw
#print axioms FooLiL3.l3_from_mass_certificates_and_product_ideal

#check FooLiL3.l3_from_mass_certificates_and_product_ideal

namespace IdealAgentChecks

theorem empty_product_point_mass :
    independentFinPMF (fun _ : Fin 0 => ℤ) (fun _ => PMF.pure 1)
      (fun j => Fin.elim0 j) = 1 := by
  rw [independentFinPMF_apply]
  simp

theorem two_column_pure_product_at_support :
    independentFinPMF (fun _ : Fin 2 => ℤ) (fun _ => PMF.pure 1) (fun _ => 1) = 1 := by
  rw [independentFinPMF_apply]
  simp

theorem two_column_pure_product_outside_support :
    independentFinPMF (fun _ : Fin 2 => ℤ) (fun _ => PMF.pure 1) (fun _ => 0) = 0 := by
  rw [independentFinPMF_apply]
  simp

theorem discrete_output_support {n m w : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (hA : Function.Surjective A.mulVec) (s : ℝ) (hs : 0 < s) :
    letI : MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ)) := ⊤
    (idealDelegationMeasure q A B G hA s hs).real
      (invalidOutput (ValidDelegation q A B G)) = 0 := by
  let : MeasurableSpace (Option (Matrix (Fin m) (Fin w) ℤ)) := ⊤
  exact idealDelegationMeasure_invalidOutput q A B G hA s hs

#print axioms empty_product_point_mass
#print axioms two_column_pure_product_at_support
#print axioms two_column_pure_product_outside_support
#print axioms discrete_output_support

end IdealAgentChecks
