import Mathlib.Analysis.Normed.Ring.InfiniteSum
import Mathlib.Data.Fin.Tuple.Basic
import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Order.BigOperators.GroupWithZero.Finset

/-! Finite-dimensional products of full integer sums, with explicit summability. -/

noncomputable section
open scoped BigOperators
namespace FooLiL2

theorem summable_fin_product (d : ℕ) (f : Fin d → ℤ → ℝ)
    (hf : ∀ i, Summable (f i)) (hn : ∀ i z, 0 ≤ f i z) :
    Summable (fun z : Fin d → ℤ => ∏ i, f i (z i)) := by
  induction d with
  | zero => exact Summable.of_finite
  | succ d ih =>
    have htail := ih (fun i => f i.succ) (fun i => hf i.succ) (fun i => hn i.succ)
    have hmul := (hf 0).mul_of_nonneg htail (hn 0)
      (fun z => Finset.prod_nonneg (fun i _ => hn i.succ (z i)))
    apply (Fin.consEquiv (fun _ : Fin (d + 1) => ℤ)).summable_iff.mp
    simpa [Function.comp_def, Fin.prod_univ_succ, Fin.consEquiv_apply] using hmul

theorem tsum_fin_product (d : ℕ) (f : Fin d → ℤ → ℝ)
    (hf : ∀ i, Summable (f i)) (hn : ∀ i z, 0 ≤ f i z) :
    (∑' z : Fin d → ℤ, ∏ i, f i (z i)) = ∏ i, ∑' z : ℤ, f i z := by
  induction d with
  | zero => simp
  | succ d ih =>
    have htail := summable_fin_product d (fun i => f i.succ)
      (fun i => hf i.succ) (fun i => hn i.succ)
    have hmul := (hf 0).mul_of_nonneg htail (hn 0)
      (fun z => Finset.prod_nonneg (fun i _ => hn i.succ (z i)))
    rw [← (Fin.consEquiv (fun _ : Fin (d + 1) => ℤ)).tsum_eq]
    simp only [Fin.prod_univ_succ, Fin.consEquiv_apply, Fin.cons_zero, Fin.cons_succ]
    rw [← (hf 0).tsum_mul_tsum htail hmul]
    rw [ih (fun i => f i.succ) (fun i => hf i.succ) (fun i => hn i.succ)]

end FooLiL2
