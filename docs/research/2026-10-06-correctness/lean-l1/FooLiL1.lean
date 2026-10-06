import Mathlib.Data.Matrix.ColumnRowPartitioned
import Mathlib.Data.ZMod.Basic
import Mathlib.Logic.Equiv.Fin.Basic

/-!
# Foo--Li L1: trapdoor and signature congruences

This file proves algebra only, not a distribution, a norm bound, a sampler
implementation, or a security reduction. All signature arithmetic is over Z
before entrywise reduction into ZMod q.
-/

namespace FooLiL1

open Matrix

variable {q n m w : ℕ}

/-- Reduction of an integer vector, not selection of a modular representative. -/
def reduceVec {ι : Type*} (q : ℕ) (v : ι → ℤ) : ι → ZMod q :=
  fun i => (v i : ZMod q)

/-- Entrywise reduction of an integer matrix. -/
def reduceMat {ι κ : Type*} (q : ℕ) (M : Matrix ι κ ℤ) : Matrix ι κ (ZMod q) :=
  M.map (Int.castRingHom (ZMod q))

/-- Vertical concatenation J = [-R; I], in the integer domain. -/
def trapdoorLift (R : Matrix (Fin m) (Fin w) ℤ) :
    Matrix (Fin m ⊕ Fin w) (Fin w) ℤ :=
  fromRows (-R) 1

/-- Signature output x = p + Jz, still an integer vector. -/
def signature (R : Matrix (Fin m) (Fin w) ℤ)
    (p : (Fin m ⊕ Fin w) → ℤ) (z : Fin w → ℤ) : (Fin m ⊕ Fin w) → ℤ :=
  p + trapdoorLift R *ᵥ z

theorem reduceVec_add {ι : Type*} (p v : ι → ℤ) :
    reduceVec q (p + v) = reduceVec q p + reduceVec q v := by
  funext i
  exact Int.cast_add (p i) (v i)

theorem reduceVec_mulVec {ι κ : Type*} [Fintype κ]
    (M : Matrix ι κ ℤ) (v : κ → ℤ) :
    reduceVec q (M *ᵥ v) = reduceMat q M *ᵥ reduceVec q v := by
  funext i
  exact (Int.castRingHom (ZMod q)).map_mulVec M v i

theorem reduceMat_trapdoorLift (R : Matrix (Fin m) (Fin w) ℤ) :
    reduceMat q (trapdoorLift R) = fromRows (-reduceMat q R) 1 := by
  ext i j
  cases i with
  | inl i => simp [reduceMat, trapdoorLift]
  | inr i => simp [reduceMat, trapdoorLift, Matrix.one_apply]

/-- L1 first conclusion: F J = G in ZMod q. -/
theorem trapdoor_equation
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (R : Matrix (Fin m) (Fin w) ℤ)
    (hB : B = A * reduceMat q R + G) :
    fromCols A B * reduceMat q (trapdoorLift R) = G := by
  rw [reduceMat_trapdoorLift, fromCols_mul_fromRows, Matrix.mul_neg, Matrix.mul_one, hB]
  exact neg_add_cancel_left _ _

/-- Integer construction and modular computation commute. -/
theorem reduceVec_signature (R : Matrix (Fin m) (Fin w) ℤ)
    (p : (Fin m ⊕ Fin w) → ℤ) (z : Fin w → ℤ) :
    reduceVec q (signature R p z) =
      reduceVec q p + reduceMat q (trapdoorLift R) *ᵥ reduceVec q z := by
  rw [signature, reduceVec_add, reduceVec_mulVec]

/-- L1 second conclusion, conditional on the explicit gadget syndrome. -/
theorem signature_equation
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (R : Matrix (Fin m) (Fin w) ℤ)
    (p : (Fin m ⊕ Fin w) → ℤ) (z : Fin w → ℤ) (u : Fin n → ZMod q)
    (hB : B = A * reduceMat q R + G)
    (hz : G *ᵥ reduceVec q z = u - fromCols A B *ᵥ reduceVec q p) :
    fromCols A B *ᵥ reduceVec q (signature R p z) = u := by
  rw [reduceVec_signature, mulVec_add, mulVec_mulVec,
    trapdoor_equation A B G R hB, hz]
  exact add_sub_cancel _ _

/-- Main L1, with both conclusions and precisely its two algebraic premises. -/
theorem l1
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (R : Matrix (Fin m) (Fin w) ℤ)
    (p : (Fin m ⊕ Fin w) → ℤ) (z : Fin w → ℤ) (u : Fin n → ZMod q)
    (hB : B = A * reduceMat q R + G)
    (hz : G *ᵥ reduceVec q z = u - fromCols A B *ᵥ reduceVec q p) :
    (fromCols A B * reduceMat q (trapdoorLift R) = G) ∧
    (fromCols A B *ᵥ reduceVec q (signature R p z) = u) := by
  exact ⟨trapdoor_equation A B G R hB, signature_equation A B G R p z u hB hz⟩

/-! ## Algebraic sign and index conventions used in the L1 explanation -/

theorem reduceMat_neg (R : Matrix (Fin m) (Fin w) ℤ) :
    reduceMat q (-R) = -reduceMat q R := by
  ext i j
  exact Int.cast_neg (R i j)

/-- MP12's AT = G - B is equivalent to Foo--Li's B = A(-T) + G. -/
theorem mp12_sign_iff
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (T : Matrix (Fin m) (Fin w) ℤ) :
    A * reduceMat q T = G - B ↔ B = A * reduceMat q (-T) + G := by
  rw [reduceMat_neg, Matrix.mul_neg]
  constructor
  · intro hT
    rw [hT, neg_sub, sub_add_cancel]
  · intro hB
    rw [hB]
    simp only [sub_eq_add_neg, neg_add_rev, neg_neg]
    simp only [← add_assoc, add_neg_cancel, zero_add]

/-- The master-stage lift has the opposite sign: [R0; I], not [-R0; I]. -/
theorem master_trapdoor_equation
    (Abar : Matrix (Fin n) (Fin m) (ZMod q))
    (G : Matrix (Fin n) (Fin w) (ZMod q))
    (R0 : Matrix (Fin m) (Fin w) ℤ) :
    fromCols Abar (G - Abar * reduceMat q R0) *
      reduceMat q (fromRows R0 (1 : Matrix (Fin w) (Fin w) ℤ)) = G := by
  have hcast : reduceMat q (fromRows R0 (1 : Matrix (Fin w) (Fin w) ℤ)) =
      fromRows (reduceMat q R0) 1 := by
    ext i j
    cases i with
    | inl i => rfl
    | inr i => simp [reduceMat, Matrix.one_apply]
  rw [hcast, fromCols_mul_fromRows, Matrix.mul_one]
  exact add_sub_cancel _ _

/-- Flatten the block index using the standard first-m-then-w ordering. -/
def flattenVec {α : Type*} (v : (Fin m ⊕ Fin w) → α) : Fin (m + w) → α :=
  v ∘ finSumFinEquiv.symm

def flattenCols {α : Type*} (F : Matrix (Fin n) (Fin m ⊕ Fin w) α) :
    Matrix (Fin n) (Fin (m + w)) α :=
  F.submatrix id finSumFinEquiv.symm

theorem flatten_mulVec (F : Matrix (Fin n) (Fin m ⊕ Fin w) (ZMod q))
    (v : (Fin m ⊕ Fin w) → ZMod q) :
    flattenCols F *ᵥ flattenVec v = F *ᵥ v := by
  rw [flattenCols, submatrix_mulVec_equiv]
  simp [flattenVec, Function.comp_def]

/-- Same L1 signature conclusion with exactly m+w integer coordinates. -/
theorem flattened_signature_equation
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (R : Matrix (Fin m) (Fin w) ℤ)
    (p : (Fin m ⊕ Fin w) → ℤ) (z : Fin w → ℤ) (u : Fin n → ZMod q)
    (hB : B = A * reduceMat q R + G)
    (hz : G *ᵥ reduceVec q z = u - fromCols A B *ᵥ reduceVec q p) :
    flattenCols (fromCols A B) *ᵥ reduceVec q (flattenVec (signature R p z)) = u := by
  change flattenCols (fromCols A B) *ᵥ
    flattenVec (reduceVec q (signature R p z)) = u
  rw [flatten_mulVec]
  exact signature_equation A B G R p z u hB hz

/-- General tag case: K is a supplied right inverse of H. IBS uses H = I.
This proves the algebraic variant, not that a sampler accepts every such tag. -/
theorem tagged_signature_equation
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (B G : Matrix (Fin n) (Fin w) (ZMod q))
    (H K : Matrix (Fin n) (Fin n) (ZMod q))
    (R : Matrix (Fin m) (Fin w) ℤ)
    (p : (Fin m ⊕ Fin w) → ℤ) (z : Fin w → ℤ) (u : Fin n → ZMod q)
    (hHK : H * K = 1)
    (hB : B = A * reduceMat q R + H * G)
    (hz : G *ᵥ reduceVec q z = K *ᵥ (u - fromCols A B *ᵥ reduceVec q p)) :
    (fromCols A B * reduceMat q (trapdoorLift R) = H * G) ∧
    (fromCols A B *ᵥ reduceVec q (signature R p z) = u) := by
  apply l1 A B (H * G) R p z u hB
  rw [← mulVec_mulVec, hz, mulVec_mulVec, hHK, one_mulVec]

end FooLiL1
