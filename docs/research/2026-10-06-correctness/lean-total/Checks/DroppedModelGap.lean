import FooLiTotal.Controls
-- FALSE: G0 failure zero does not force G1 failure zero without a gap premise.
example : |(1 : ℝ) - 0| ≤ 0 := by norm_num
