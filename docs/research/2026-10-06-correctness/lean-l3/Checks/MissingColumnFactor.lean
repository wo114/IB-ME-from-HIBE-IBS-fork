import FooLiL3.Controls

/-- Intentionally false: dropping the number of columns must be rejected. -/
example : FooLiL3.frobSq (fun (_ : Fin 1) (_ : Fin 2) => (1 : ℤ)) ≤ 1 := by
  rw [FooLiL3.Controls.column_count_cannot_be_dropped]
  norm_num
