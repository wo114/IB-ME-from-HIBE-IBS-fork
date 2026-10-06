import FooLiL3.FiniteCharacters
import FooLiL2.DualMass

noncomputable section
open scoped BigOperators
open Matrix FooLiL2.Cosets
namespace FooLiL3

theorem modular_phase_factorization {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (a : Fin n → ZMod q) (x : Fin m → ℤ) :
    ZMod.stdAddChar (-dotProduct ((modMatrix q C).mulVec (modVector q x)) a) =
      ∏ i, Complex.exp (-2 * Real.pi * Complex.I *
        (FooLiL2.residueShift q C a i : ℂ) * (x i : ℂ)) := by
  have hdot : dotProduct (C.transpose *ᵥ liftVector q a) x =
      dotProduct (liftVector q a) (C *ᵥ x) := by
    rw [dotProduct_mulVec, mulVec_transpose]
  have hcast : ((-dotProduct (C.transpose *ᵥ liftVector q a) x : ℤ) : ZMod q) =
      -dotProduct ((modMatrix q C).mulVec (modVector q x)) a := by
    rw [hdot, ← mod_mulVec, dotProduct_comm]
    simp [dotProduct, modVector, liftVector, Int.cast_sum, Int.cast_mul]
  rw [← hcast, ZMod.stdAddChar_coe]
  rw [← Complex.exp_sum]
  congr 1
  have hp := shift_pairing (K := ℝ) q C (liftVector q a) x
  rw [← hdot] at hp
  have hc := congrArg (fun r : ℝ => (r : ℂ)) hp
  simp only [dotProduct, intVector, Complex.ofReal_sum, Complex.ofReal_mul,
    Complex.ofReal_intCast, Complex.ofReal_div, Complex.ofReal_natCast] at hc
  calc
    _ = (-2 * Real.pi * Complex.I) *
        (((dotProduct (C.transpose *ᵥ liftVector q a) x : ℤ) : ℂ) / (q : ℂ)) := by
      push_cast
      ring
    _ = (-2 * Real.pi * Complex.I) * ∑ i,
        (FooLiL2.residueShift q C a i : ℂ) * (x i : ℂ) := by
      congr 1
      exact hc.symm
    _ = _ := by rw [Finset.mul_sum]; apply Finset.sum_congr rfl; intro i _; ring

theorem phase_split {n m : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q)
    (a : Fin n → ZMod q) (x : Fin m → ℤ) :
    ZMod.stdAddChar (dotProduct (u - A.mulVec (fun i => (x i : ZMod q))) a) =
      ZMod.stdAddChar (dotProduct u a) *
        ZMod.stdAddChar (-dotProduct (A.mulVec (fun i => (x i : ZMod q))) a) := by
  rw [sub_dotProduct, sub_eq_add_neg, AddChar.map_add_eq_mul]

end FooLiL3
