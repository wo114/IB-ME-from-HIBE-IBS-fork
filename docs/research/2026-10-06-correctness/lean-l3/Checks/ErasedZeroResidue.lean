import FooLiL3.BridgeControls
open scoped BigOperators

/-! Deliberate false conclusion: removing the entire zero residue branch. -/
example : ‖(∑ _ : Fin 1, (1 : ℂ) * (2 : ℂ)) - 1‖ = 0 := by
  rw [FooLiL3.zero_residue_remainder_not_erased]
  norm_num
