import FooLiL4.Controls

/-- Deliberately false: equality at the cutoff is not failure. -/
example : ¬FooLiL4.signatureAccepts 3 (fun (_ : Fin 1) (_ : Fin 1) => 1)
    (fun _ => 1) 1 (some (fun _ => 1)) := by
  simp only [FooLiL4.Controls.equality_at_cutoff_accepted, not_true_eq_false]
