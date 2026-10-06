import FooLiL4.Controls

/-- Deliberately false: the full signature dimension cannot be replaced by the base width. -/
example : FooLiL3.vectorSq (fun _ : Fin 2 => (1 : ℤ)) ≤ (1 : ℝ) := by
  norm_num [FooLiL3.vectorSq, Fin.sum_univ_two]
