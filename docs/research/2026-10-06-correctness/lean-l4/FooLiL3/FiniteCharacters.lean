import FooLiL3.IntegerGaussian
import Mathlib.Analysis.SpecialFunctions.Complex.CircleAddChar
import Mathlib.Analysis.Fourier.FiniteAbelian.Orthogonality

/-! Finite Fourier indicator for actual modular cosets. -/
noncomputable section
open scoped BigOperators
open Matrix
open Classical
namespace FooLiL3

def vectorChar {n : ℕ} (q : ℕ) [NeZero q] (x : Fin n → ZMod q) :
    AddChar (Fin n → ZMod q) ℂ where
  toFun a := ZMod.stdAddChar (dotProduct x a)
  map_zero_eq_one' := by simp
  map_add_eq_mul' a b := by rw [dotProduct_add, AddChar.map_add_eq_mul]

theorem vectorChar_eq_zero_iff {n : ℕ} (q : ℕ) [NeZero q]
    (x : Fin n → ZMod q) : vectorChar q x = 0 ↔ x = 0 := by
  constructor
  · intro h
    funext i
    have hi := DFunLike.congr_fun h (Pi.single i 1)
    change ZMod.stdAddChar (dotProduct x (Pi.single i 1)) = 1 at hi
    rw [dotProduct_single_one] at hi
    exact (ZMod.isPrimitive_stdAddChar q).zmod_char_eq_one_iff q (x i) |>.mp hi
  · rintro rfl
    ext a
    simp [vectorChar]

theorem sum_vectorChar {n : ℕ} (q : ℕ) [NeZero q]
    (x : Fin n → ZMod q) :
    ∑ a : Fin n → ZMod q, ZMod.stdAddChar (dotProduct x a) =
      if x = 0 then (q : ℂ) ^ n else 0 := by
  classical
  change (∑ a, vectorChar q x a) = _
  rw [AddChar.sum_eq_ite]
  simp [vectorChar_eq_zero_iff, ZMod.card]

theorem norm_stdAddChar (q : ℕ) [NeZero q] (a : ZMod q) :
    ‖ZMod.stdAddChar a‖ = 1 := by
  exact (ZMod.stdAddChar (N := q)).norm_apply a

theorem coset_indicator_fourier {n m : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q)
    (x : Fin m → ℤ) :
    (if InCoset q A u x then (1 : ℂ) else 0) =
      (1 / (q : ℂ) ^ n) * ∑ a : Fin n → ZMod q,
        ZMod.stdAddChar (dotProduct (u - A.mulVec (fun i => (x i : ZMod q))) a) := by
  classical
  rw [sum_vectorChar]
  have hq : (q : ℂ) ^ n ≠ 0 := pow_ne_zero _ (Nat.cast_ne_zero.mpr (NeZero.ne q))
  by_cases hx : InCoset q A u x
  · have hu : u - A.mulVec (fun i => (x i : ZMod q)) = 0 := by
      exact sub_eq_zero.mpr hx.symm
    simp [hx, hu, hq]
  · have hu : u - A.mulVec (fun i => (x i : ZMod q)) ≠ 0 := by
      intro h
      exact hx (sub_eq_zero.mp h).symm
    simp [hx, hu]

end FooLiL3
