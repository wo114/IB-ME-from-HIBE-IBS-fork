import FooLiL4.Controls

/-- Deliberately false: raw aborts cannot be removed from the probability space. -/
example :
    letI : MeasurableSpace (FooLiL4.SignatureOutput 1) := ⊤
    (FooLiL4.rawTapeMeasure (fun _ : FooLiL4.ByteTape 1 => none)).real
      (FooLiL4.signatureFailure 3 (fun (_ : Fin 1) (_ : Fin 1) => 1) (fun _ => 0) 1) ≤ 0 := by
  rw [FooLiL4.Controls.constant_abort_tape_probability]
  norm_num
