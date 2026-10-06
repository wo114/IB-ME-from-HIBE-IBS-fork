import Mathlib.Algebra.Order.Archimedean.Real.Basic
import Mathlib.Algebra.BigOperators.Ring.Finset
import Mathlib.Algebra.Order.BigOperators.GroupWithZero.Finset
import Mathlib.Algebra.Order.BigOperators.Group.Finset
import Mathlib.Order.ConditionallyCompleteLattice.Basic
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.Ring

/-!
# Finite mass assembly for L2

This module proves the order-theoretic assembly independently of Gaussian analysis.
Its inputs are explicit finite mass bounds, not a statement about a dual lattice.
The link to actual lattice Gaussian masses must be established separately.
-/

noncomputable section
open scoped BigOperators

namespace FooLiL2

/-- The increase in the nonzero mass after adjoining a block. -/
def extensionError (e : ℝ) : ℝ := 2 * e + e ^ 2

theorem extensionError_pos {e : ℝ} (he : 0 < e) : 0 < extensionError e := by
  unfold extensionError
  nlinarith [sq_nonneg e]

theorem extensionError_le_nine_sixteenths {e : ℝ}
    (he : 0 ≤ e) (he' : e ≤ 1 / 4) : extensionError e ≤ 9 / 16 := by
  unfold extensionError
  nlinarith

theorem extensionError_lt_one {e : ℝ} (he : 0 ≤ e) (he' : e ≤ 1 / 4) :
    extensionError e < 1 :=
  lt_of_le_of_lt (extensionError_le_nine_sixteenths he he') (by norm_num)

/-- The zero coset is retained: its full mass supplies the lower bound. -/
theorem zero_coset_le_total {ι : Type*} [Fintype ι] (a : ι → ℝ) (zeroCoset : ι)
    (ha : ∀ i, 0 ≤ a i) : a zeroCoset ≤ ∑ i, a i := by
  exact Finset.single_le_sum (fun i _ => ha i) (Finset.mem_univ zeroCoset)

/-- An elementary mass bound. It does not assert a lattice/coset identity. -/
theorem finite_mass_extension_bound {ι : Type*} [Fintype ι]
    (a b : ι → ℝ) (zeroCoset : ι) (r e : ℝ) (m w : ℕ)
    (ha : ∀ i, 0 ≤ a i) (hr : 1 ≤ r) (hw : w ≤ m)
    (ha0 : a zeroCoset = r ^ m) (hb : ∀ i, b i ≤ r ^ w)
    (hA : ∑ i, a i ≤ 1 + e) :
    (∑ i, a i * b i) - 1 ≤ extensionError e := by
  have hsum0 : 0 ≤ ∑ i, a i := Finset.sum_nonneg (fun i _ => ha i)
  have hpow : r ^ w ≤ ∑ i, a i := by
    calc
      r ^ w ≤ r ^ m := pow_le_pow_right₀ hr hw
      _ = a zeroCoset := ha0.symm
      _ ≤ ∑ i, a i := zero_coset_le_total a zeroCoset ha
  have he0 : 0 ≤ 1 + e := hsum0.trans hA
  have htotal : ∑ i, a i * b i ≤ (1 + e) ^ 2 := by
    calc
      ∑ i, a i * b i ≤ ∑ i, a i * r ^ w :=
        Finset.sum_le_sum (fun i _ => mul_le_mul_of_nonneg_left (hb i) (ha i))
      _ = (∑ i, a i) * r ^ w := (Finset.sum_mul ..).symm
      _ ≤ (∑ i, a i) * (∑ i, a i) := mul_le_mul_of_nonneg_left hpow hsum0
      _ ≤ (1 + e) * (1 + e) := mul_le_mul hA hA hsum0 he0
      _ = (1 + e) ^ 2 := by ring
  unfold extensionError
  nlinarith

/-- Infimum convention for an explicitly supplied nonzero-mass function. -/
def smoothingInf (theta : ℝ → ℝ) (e : ℝ) : ℝ :=
  sInf {t : ℝ | 0 < t ∧ theta t ≤ e}

/-- Membership gives an upper bound without assuming that the infimum is attained. -/
theorem smoothingInf_le_of_mass_le (theta : ℝ → ℝ) (e t : ℝ)
    (ht : 0 < t) (h : theta t ≤ e) : smoothingInf theta e ≤ t := by
  unfold smoothingInf
  apply csInf_le
  · exact ⟨0, fun _ hx => hx.1.le⟩
  · exact ⟨ht, h⟩

end FooLiL2
