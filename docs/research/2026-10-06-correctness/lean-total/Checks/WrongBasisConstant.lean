import FooLiTotal.Controls
-- FALSE: the conservative factor 10 cannot be replaced by 5 in this inequality.
example : 5 * (Real.sqrt (1 : ℝ) + 1)^2 ≤ 5*(1+1) := by norm_num
