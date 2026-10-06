import FooLiL3.IdealDelegation

/-! Deliberate negative control: excluded from the library target. -/

noncomputable section
open FooLiL3

example :
    independentFinPMF (fun _ : Fin 2 => ℤ) (fun _ => PMF.pure 1) (fun _ => 0) = 1 := by
  rw [independentFinPMF_apply]
  simp
