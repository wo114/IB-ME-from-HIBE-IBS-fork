import FooLiL3.PhaseFactors
import FooLiL3.FourierGaussian

/-! Exact q-ary coset Poisson summation, including all infinite grid terms. -/
noncomputable section
open scoped BigOperators
open Matrix FooLiL2.Cosets Classical
namespace FooLiL3

def modularGaussian {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (a : Fin n → ZMod q)
    (s : ℝ) (x : Fin m → ℤ) : ℂ :=
  (rho s (vectorSq x) : ℂ) *
    ZMod.stdAddChar (-dotProduct ((modMatrix q C).mulVec (modVector q x)) a)

theorem modularGaussian_eq_product {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (a : Fin n → ZMod q)
    (s : ℝ) (x : Fin m → ℤ) :
    modularGaussian q C a s x = ∏ i, phaseTerm s (FooLiL2.residueShift q C a i) (x i) := by
  simp_rw [modularGaussian, phaseTerm_eq_rho_mul_exp]
  rw [Finset.prod_mul_distrib, ← Complex.ofReal_prod, ← vector_rho_eq_product,
    modular_phase_factorization]

theorem summable_modularGaussian {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (a : Fin n → ZMod q)
    {s : ℝ} (hs : 0 < s) : Summable (modularGaussian q C a s) := by
  exact (summable_prod_phaseTerm m hs (FooLiL2.residueShift q C a)).congr
    (fun x => (modularGaussian_eq_product q C a s x).symm)

theorem tsum_modularGaussian {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (a : Fin n → ZMod q)
    {s : ℝ} (hs : 0 < s) :
    (∑' x, modularGaussian q C a s x) =
      (s : ℂ) ^ m * (FooLiL2.gridMass m s (FooLiL2.residueShift q C a) : ℂ) := by
  simp_rw [modularGaussian_eq_product]
  exact tsum_prod_phaseTerm_eq_gridMass m hs _

theorem coset_poisson {n m : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin m) ℤ) (u : Fin n → ZMod q)
    {s : ℝ} (hs : 0 < s) :
    (gaussianZ (fun x : {x // InCoset q (modMatrix q C) u x} => vectorSq x.val) s : ℂ) =
      ((s : ℂ) ^ m / (q : ℂ) ^ n) * ∑ a : Fin n → ZMod q,
        ZMod.stdAddChar (dotProduct u a) *
          (FooLiL2.gridMass m s (FooLiL2.residueShift q C a) : ℂ) := by
  rw [gaussianZ, Complex.ofReal_tsum]
  trans ∑' x : Fin m → ℤ,
    ({x | InCoset q (modMatrix q C) u x} : Set (Fin m → ℤ)).indicator
      (fun x => (rho s (vectorSq x) : ℂ)) x
  · exact tsum_subtype {x | InCoset q (modMatrix q C) u x}
      (fun x : Fin m → ℤ => (rho s (vectorSq x) : ℂ))
  have hp (x : Fin m → ℤ) :
      ({x | InCoset q (modMatrix q C) u x} : Set (Fin m → ℤ)).indicator
        (fun x => (rho s (vectorSq x) : ℂ)) x =
      (1 / (q : ℂ) ^ n) * ∑ a : Fin n → ZMod q,
        ZMod.stdAddChar (dotProduct u a) * modularGaussian q C a s x := by
    change (if InCoset q (modMatrix q C) u x then (rho s (vectorSq x) : ℂ) else 0) = _
    calc
      _ = (rho s (vectorSq x) : ℂ) *
          (if InCoset q (modMatrix q C) u x then 1 else 0) := by split_ifs <;> simp
      _ = _ := by
        rw [coset_indicator_fourier]
        simp_rw [phase_split]
        simp only [Finset.mul_sum]
        apply Finset.sum_congr rfl
        intro a _
        unfold modularGaussian modVector
        ring
  simp_rw [hp]
  rw [tsum_mul_left, Summable.tsum_finsetSum
    (fun a _ => (summable_modularGaussian q C a hs).mul_left _)]
  simp_rw [tsum_mul_left, tsum_modularGaussian q C _ hs]
  have he : (∑ a : Fin n → ZMod q, ZMod.stdAddChar (dotProduct u a) *
        ((s : ℂ) ^ m * (FooLiL2.gridMass m s (FooLiL2.residueShift q C a) : ℂ))) =
      (s : ℂ) ^ m * ∑ a : Fin n → ZMod q, ZMod.stdAddChar (dotProduct u a) *
        (FooLiL2.gridMass m s (FooLiL2.residueShift q C a) : ℂ) := by
    rw [Finset.mul_sum]
    apply Finset.sum_congr rfl
    intro a _
    ring
  rw [he]
  ring

end FooLiL3
