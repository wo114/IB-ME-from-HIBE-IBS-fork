import FooLiL3.ClosedL3
import Mathlib.Tactic.NormNum

/-! Exact checks guarding the bridge conventions; not cryptographic parameters. -/
noncomputable section
open scoped BigOperators
namespace FooLiL3

/-- The zero residue class still contains nonzero grid points. Removing that
entire branch instead of only the origin would incorrectly erase this remainder. -/
theorem zero_residue_remainder_not_erased :
    ‖(∑ _ : Fin 1, (1 : ℂ) * (2 : ℂ)) - 1‖ = 1 := by
  norm_num [Fin.sum_univ_one]

theorem centered_weighted_bound_exact :
    ‖(∑ _ : Fin 1, (1 : ℂ) * (2 : ℂ)) - 1‖ ≤ (∑ _ : Fin 1, (2 : ℝ)) - 1 := by
  exact weighted_mass_deviation 0 (fun _ : Fin 1 => 1) (fun _ => 2)
    (by intro a; norm_num) rfl (by intro a; norm_num) (by norm_num)

/-- A composite modulus is covered by the character indicator, not only primes. -/
theorem composite_character_zero_sum :
    (∑ a : Fin 1 → ZMod 6, ZMod.stdAddChar (dotProduct (fun _ => 1) a)) = 0 := by
  rw [sum_vectorChar]
  have h : (fun _ : Fin 1 => (1 : ZMod 6)) ≠ 0 := by
    intro h
    have h10 : (1 : ZMod 6) = 0 := congrFun h 0
    exact (by decide : (1 : ZMod 6) ≠ 0) h10
  simp [h]

/-- The e=0 case retains the dimension factor. -/
theorem zero_smoothing_error_tail (m : ℕ) : tailBudget m 0 = (1 / 2 : ℝ) ^ m := by
  simp [tailBudget]

end FooLiL3
