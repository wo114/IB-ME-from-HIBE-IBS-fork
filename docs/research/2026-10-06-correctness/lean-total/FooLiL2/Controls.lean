import FooLiL2.L2

/-! Exact symbolic boundary checks, not numerical experiments or security tests. -/

noncomputable section
open scoped BigOperators
namespace FooLiL2.Controls
open FooLiL2 Cosets

theorem quarter_error_exact : extensionError (1 / 4) = 9 / 16 := by
  norm_num [extensionError]

theorem quadratic_term_cannot_be_dropped : 1 / 2 < extensionError (1 / 4) := by
  norm_num [extensionError]

theorem error_range_is_needed : ¬ extensionError 1 < 1 := by
  norm_num [extensionError]

/-- Counterexample to the finite mass assembly without w <= m; not a lattice parameter set. -/
theorem dimension_bound_is_needed :
    (11 / 10 : ℝ) * (11 / 10) ^ 2 - 1 > extensionError (1 / 10) := by
  norm_num [extensionError]

theorem modular_zero_is_not_full_rank :
    ¬ FullRowRank 2 (0 : Matrix (Fin 1) (Fin 1) ℤ) := by
  intro h
  obtain ⟨x, hx⟩ := h (fun _ => 1)
  have hc := congrFun hx 0
  norm_num [modMatrix, Matrix.mulVec, dotProduct] at hc

theorem zero_coset_contains_nonzero_integer :
    (fun _ : Fin 1 => (1 : ℝ)) ∈
      residueCoset 2 (0 : Matrix (Fin 1) (Fin 1) ℤ) 0 := by
  rw [residueCoset_zero]
  refine ⟨fun _ => 1, ?_⟩
  funext i
  simp [intVector]

theorem zero_added_block_dimension (m : ℕ) (t : ℝ)
    (c : Fin m → ℝ) (b : Fin 0 → ℝ) :
    gridMass (m + 0) t (Fin.append c b) = gridMass m t c := by
  rw [gridMass_append]
  simp [gridMass]

end FooLiL2.Controls
