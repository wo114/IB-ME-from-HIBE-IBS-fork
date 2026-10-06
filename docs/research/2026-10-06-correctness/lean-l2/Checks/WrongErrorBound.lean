import FooLiL2.MassBounds

/-! Deliberately false assertion: the quadratic error term is omitted. -/
example : FooLiL2.extensionError (1 / 4) ≤ 1 / 2 := by
  norm_num [FooLiL2.extensionError]
