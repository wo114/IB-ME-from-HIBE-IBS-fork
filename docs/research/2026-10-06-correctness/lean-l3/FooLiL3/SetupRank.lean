import FooLiL2.Cosets
import FooLiL3.IntegerGaussian
import Mathlib.Data.Matrix.ColumnRowPartitioned
import Mathlib.Logic.Equiv.Fin.Basic

/-!
# Setup rank and integer-lift compatibility for L3

These are algebraic consequences of a valid master trapdoor, not assumptions
that the public matrix is already surjective.  A supplied right inverse of
the tag suffices over any semiring; no prime-modulus hypothesis is needed.
The standard gadget contains one identity column in each block.
-/

namespace FooLiL3

open Matrix
open scoped BigOperators

section Algebra

variable {S : Type*} [Semiring S]
variable {ι κ ω : Type*} [Fintype ι] [Fintype κ] [Fintype ω] [DecidableEq ι]

/-- A concrete matrix right inverse gives an explicit preimage of every vector. -/
theorem mulVec_surjective_of_rightInverse (A : Matrix ι κ S) (J : Matrix κ ι S)
    (hAJ : A * J = 1) : Function.Surjective A.mulVec := by
  intro u
  refine ⟨J *ᵥ u, ?_⟩
  rw [mulVec_mulVec, hAJ, one_mulVec]

/-- The right inverse derived from `A T = H G` is `T J K`. -/
theorem rightInverse_of_trapdoor (A : Matrix ι κ S) (T : Matrix κ ω S)
    (H K : Matrix ι ι S) (G : Matrix ι ω S) (J : Matrix ω ι S)
    (hAT : A * T = H * G) (hHK : H * K = 1) (hGJ : G * J = 1) :
    A * (T * J * K) = 1 := by
  rw [← Matrix.mul_assoc, ← Matrix.mul_assoc, hAT,
    Matrix.mul_assoc H G J, hGJ, Matrix.mul_one, hHK]

/-- Alternatively the gadget may be supplied by its surjectivity theorem. -/
theorem mulVec_surjective_of_trapdoor (A : Matrix ι κ S) (T : Matrix κ ω S)
    (H K : Matrix ι ι S) (G : Matrix ι ω S)
    (hAT : A * T = H * G) (hHK : H * K = 1)
    (hG : Function.Surjective G.mulVec) : Function.Surjective A.mulVec := by
  intro u
  obtain ⟨z, hz⟩ := hG (K *ᵥ u)
  refine ⟨T *ᵥ z, ?_⟩
  rw [mulVec_mulVec, hAT, ← mulVec_mulVec, hz, mulVec_mulVec, hHK, one_mulVec]

/-- An invertible tag supplies the required right inverse automatically. -/
theorem mulVec_surjective_of_trapdoor_unit_tag (A : Matrix ι κ S)
    (T : Matrix κ ω S) (H : Matrix ι ι S) (G : Matrix ι ω S)
    (hAT : A * T = H * G) (hH : IsUnit H)
    (hG : Function.Surjective G.mulVec) : Function.Surjective A.mulVec := by
  obtain ⟨h, rfl⟩ := hH
  exact mulVec_surjective_of_trapdoor A T h (↑h⁻¹) G hAT (by simp) hG

variable [DecidableEq κ]

/-- The explicit matrix selecting the column `sel j` for each output coordinate. -/
def columnSelector (sel : ι → κ) : Matrix κ ι S :=
  fun k j => if k = sel j then 1 else 0

omit [Fintype ι] [DecidableEq ι] in
theorem mul_columnSelector (A : Matrix ι κ S) (sel : ι → κ) :
    A * columnSelector sel = A.submatrix id sel := by
  ext i j
  simp [Matrix.mul_apply, columnSelector]

omit [Fintype ι] in
/-- Identity columns certify a right inverse, without any rank premise. -/
theorem rightInverse_of_identity_columns (A : Matrix ι κ S) (sel : ι → κ)
    (hcol : ∀ i j, A i (sel j) = if i = j then 1 else 0) :
    A * columnSelector (S := S) sel = 1 := by
  rw [mul_columnSelector]
  ext i j
  exact hcol i j

theorem mulVec_surjective_of_identity_columns (A : Matrix ι κ S) (sel : ι → κ)
    (hcol : ∀ i j, A i (sel j) = if i = j then 1 else 0) :
    Function.Surjective A.mulVec :=
  mulVec_surjective_of_rightInverse A (columnSelector sel)
    (rightInverse_of_identity_columns A sel hcol)

end Algebra

section Gadget

variable {S : Type*} [Semiring S] {n ℓ : ℕ}

/-- Block gadget `I_n ⊗ g`, with explicit row/block-coordinate indexing. -/
def blockGadget (n : ℕ) (g : Fin ℓ → S) : Matrix (Fin n) (Fin n × Fin ℓ) S :=
  fun i j => if i = j.1 then g j.2 else 0

/-- Selecting the entry equal to one in every block produces `I_n`. -/
theorem blockGadget_identity_columns (g : Fin ℓ → S) (j₀ : Fin ℓ)
    (hg : g j₀ = 1) (i j : Fin n) :
    blockGadget n g i (j, j₀) = if i = j then 1 else 0 := by
  simp [blockGadget, hg]

theorem blockGadget_rightInverse (g : Fin ℓ → S) (j₀ : Fin ℓ) (hg : g j₀ = 1) :
    blockGadget n g * columnSelector (S := S) (fun j : Fin n => (j, j₀)) = 1 :=
  rightInverse_of_identity_columns _ _ (blockGadget_identity_columns g j₀ hg)

theorem blockGadget_surjective (g : Fin ℓ → S) (j₀ : Fin ℓ) (hg : g j₀ = 1) :
    Function.Surjective (blockGadget n g).mulVec :=
  mulVec_surjective_of_rightInverse _ _ (blockGadget_rightInverse g j₀ hg)

/-- Standard powers gadget `[1,b,...,b^ℓ]`; base two is the usual instance. -/
def powersGadget (n ℓ : ℕ) (b : S) : Matrix (Fin n) (Fin n × Fin (ℓ + 1)) S :=
  blockGadget n (fun j => b ^ j.val)

theorem powersGadget_rightInverse (n ℓ : ℕ) (b : S) :
    powersGadget n ℓ b * columnSelector (S := S)
      (fun j : Fin n => (j, (0 : Fin (ℓ + 1)))) = 1 :=
  blockGadget_rightInverse (fun j : Fin (ℓ + 1) => b ^ j.val) 0 (by simp)

theorem powersGadget_surjective (n ℓ : ℕ) (b : S) :
    Function.Surjective (powersGadget n ℓ b).mulVec :=
  mulVec_surjective_of_rightInverse _ _ (powersGadget_rightInverse n ℓ b)

end Gadget

section MasterSetup

variable {q n m w : ℕ}

/-- Exact C2 master relation `A [R₀; I] = G`, with the integer lift reduced
entrywise. Identity columns of G are the only gadget premise; no H or K is
introduced and no surjectivity premise is imposed on A or G. -/
theorem master_relation_surjective_of_identity_columns
    (A : Matrix (Fin n) (Fin m ⊕ Fin w) (ZMod q))
    (R₀ : Matrix (Fin m) (Fin w) ℤ) (G : Matrix (Fin n) (Fin w) (ZMod q))
    (sel : Fin n → Fin w)
    (hmaster : A * (fromRows R₀ (1 : Matrix (Fin w) (Fin w) ℤ)).map
      (Int.castRingHom (ZMod q)) = G)
    (hcol : ∀ i j, G i (sel j) = if i = j then 1 else 0) :
    Function.Surjective A.mulVec := by
  apply mulVec_surjective_of_trapdoor A
    ((fromRows R₀ (1 : Matrix (Fin w) (Fin w) ℤ)).map (Int.castRingHom (ZMod q)))
    1 1 G
  · simpa only [Matrix.one_mul] using hmaster
  · exact Matrix.one_mul 1
  · exact mulVec_surjective_of_identity_columns G sel hcol

/-- The concrete Setup shape satisfies the positive-sign master trapdoor equation.
`R` is the reduction of the integer master trapdoor, not the signing-stage `-R`. -/
theorem master_setup_trapdoor_equation
    (Abar : Matrix (Fin n) (Fin m) (ZMod q))
    (R : Matrix (Fin m) (Fin w) (ZMod q))
    (H : Matrix (Fin n) (Fin n) (ZMod q))
    (G : Matrix (Fin n) (Fin w) (ZMod q)) :
    fromCols Abar (H * G - Abar * R) * fromRows R 1 = H * G := by
  rw [fromCols_mul_fromRows, Matrix.mul_one, add_sub_cancel]

/-- A valid master trapdoor and a right-invertible tag imply public-matrix
surjectivity. This specializes to `H=K=I` for the IBS master setup. -/
theorem master_setup_surjective
    (Abar : Matrix (Fin n) (Fin m) (ZMod q))
    (R : Matrix (Fin m) (Fin w) (ZMod q))
    (H K : Matrix (Fin n) (Fin n) (ZMod q))
    (G : Matrix (Fin n) (Fin w) (ZMod q))
    (hHK : H * K = 1) (hG : Function.Surjective G.mulVec) :
    Function.Surjective (fromCols Abar (H * G - Abar * R)).mulVec :=
  mulVec_surjective_of_trapdoor _ (fromRows R 1) H K G
    (master_setup_trapdoor_equation Abar R H G) hHK hG

/-- Changing only the column indexing preserves surjectivity. -/
theorem mulVec_surjective_reindex_columns {α β : Type*} [Fintype α] [Fintype β]
    (A : Matrix (Fin n) α (ZMod q)) (e : β ≃ α)
    (hA : Function.Surjective A.mulVec) :
    Function.Surjective (A.submatrix id e).mulVec := by
  intro u
  obtain ⟨v, hv⟩ := hA u
  refine ⟨v ∘ e, ?_⟩
  rw [submatrix_mulVec_equiv]
  simpa [Function.comp_def] using hv

/-- Exact C2 implication transported to L3's flat public-matrix indexing. -/
theorem master_relation_flat_surjective_of_identity_columns
    (A : Matrix (Fin n) (Fin m ⊕ Fin w) (ZMod q))
    (R₀ : Matrix (Fin m) (Fin w) ℤ) (G : Matrix (Fin n) (Fin w) (ZMod q))
    (sel : Fin n → Fin w)
    (hmaster : A * (fromRows R₀ (1 : Matrix (Fin w) (Fin w) ℤ)).map
      (Int.castRingHom (ZMod q)) = G)
    (hcol : ∀ i j, G i (sel j) = if i = j then 1 else 0) :
    Function.Surjective (A.submatrix id finSumFinEquiv.symm).mulVec :=
  mulVec_surjective_reindex_columns _ _
    (master_relation_surjective_of_identity_columns A R₀ G sel hmaster hcol)

/-- Flat `Fin (m+w)` API for L3's public matrix, in L1's block order. -/
theorem master_setup_flat_surjective
    (Abar : Matrix (Fin n) (Fin m) (ZMod q))
    (R : Matrix (Fin m) (Fin w) (ZMod q))
    (H K : Matrix (Fin n) (Fin n) (ZMod q))
    (G : Matrix (Fin n) (Fin w) (ZMod q))
    (hHK : H * K = 1) (hG : Function.Surjective G.mulVec) :
    Function.Surjective
      ((fromCols Abar (H * G - Abar * R)).submatrix id finSumFinEquiv.symm).mulVec :=
  mulVec_surjective_reindex_columns _ _ (master_setup_surjective Abar R H K G hHK hG)

/-- Row-major flattening of the standard block gadget into `n*(ℓ+1)` columns. -/
theorem powersGadget_flat_surjective (n ℓ : ℕ) (b : ZMod q) :
    Function.Surjective
      ((powersGadget n ℓ b).submatrix id finProdFinEquiv.symm).mulVec :=
  mulVec_surjective_reindex_columns _ _ (powersGadget_surjective n ℓ b)

/-- Explicit flat identity-column locations are `j*(ℓ+1)`, expressed by the
canonical product equivalence so the block-order convention is checked. -/
theorem powersGadget_flat_identity_columns (n ℓ : ℕ) (b : ZMod q) (i j : Fin n) :
    ((powersGadget n ℓ b).submatrix id finProdFinEquiv.symm)
      i (finProdFinEquiv (j, (0 : Fin (ℓ + 1)))) = if i = j then 1 else 0 := by
  change powersGadget n ℓ b i
    (finProdFinEquiv.symm (finProdFinEquiv (j, (0 : Fin (ℓ + 1))))) = _
  rw [Equiv.symm_apply_apply]
  simp [powersGadget, blockGadget]

/-- Primary ledger-facing C2 interface: the actual flat A satisfies
`A [R₀; I] = G` for the standard gadget, and therefore is surjective.
There is no tag, rank, or gadget-surjectivity hypothesis in this signature. -/
theorem standard_master_relation_surjective {ℓ : ℕ}
    (A : Matrix (Fin n) (Fin (m + n * (ℓ + 1))) (ZMod q))
    (R₀ : Matrix (Fin m) (Fin (n * (ℓ + 1))) ℤ) (b : ZMod q)
    (hmaster : A *
      (((fromRows R₀ (1 : Matrix (Fin (n * (ℓ + 1))) (Fin (n * (ℓ + 1))) ℤ)).map
        (Int.castRingHom (ZMod q))).submatrix finSumFinEquiv.symm id) =
      (powersGadget n ℓ b).submatrix id finProdFinEquiv.symm) :
    Function.Surjective A.mulVec := by
  apply mulVec_surjective_of_trapdoor A _ 1 1
    ((powersGadget n ℓ b).submatrix id finProdFinEquiv.symm)
  · simpa only [Matrix.one_mul] using hmaster
  · exact Matrix.one_mul 1
  · exact powersGadget_flat_surjective n ℓ b

/-- Full concrete standard-gadget Setup, with no rank/surjectivity premise on A or G. -/
theorem standard_master_setup_surjective {ℓ : ℕ}
    (Abar : Matrix (Fin n) (Fin m) (ZMod q))
    (R : Matrix (Fin m) (Fin (n * (ℓ + 1))) (ZMod q))
    (H K : Matrix (Fin n) (Fin n) (ZMod q)) (b : ZMod q)
    (hHK : H * K = 1) :
    Function.Surjective
      ((fromCols Abar
        (H * (powersGadget n ℓ b).submatrix id finProdFinEquiv.symm - Abar * R)).submatrix
          id finSumFinEquiv.symm).mulVec :=
  master_setup_flat_surjective Abar R H K _ hHK (powersGadget_flat_surjective n ℓ b)

end MasterSetup

section IntegerLift

variable {q n m : ℕ}
open FooLiL2.Cosets

/- `mod_liftMatrix` and `mod_liftVector` already prove the exact round trips
in L2 and are intentionally reused here, without creating duplicate lemmas. -/

theorem fullRowRank_liftMatrix_iff (A : Matrix (Fin n) (Fin m) (ZMod q)) :
    FullRowRank q (liftMatrix q A) ↔ Function.Surjective A.mulVec := by
  simp only [FullRowRank, mod_liftMatrix]

/-- Direct handoff to L2's integer-matrix hypothesis from a trapdoor certificate. -/
theorem fullRowRank_liftMatrix_of_trapdoor {w : ℕ}
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (T : Matrix (Fin m) (Fin w) (ZMod q))
    (H K : Matrix (Fin n) (Fin n) (ZMod q)) (G : Matrix (Fin n) (Fin w) (ZMod q))
    (hAT : A * T = H * G) (hHK : H * K = 1)
    (hG : Function.Surjective G.mulVec) : FullRowRank q (liftMatrix q A) :=
  (fullRowRank_liftMatrix_iff A).mpr
    (mulVec_surjective_of_trapdoor A T H K G hAT hHK hG)

/-- Direct handoff to the actual integer-coset distributions in L3. -/
theorem coset_nonempty_of_trapdoor {w : ℕ} [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (T : Matrix (Fin m) (Fin w) (ZMod q))
    (H K : Matrix (Fin n) (Fin n) (ZMod q)) (G : Matrix (Fin n) (Fin w) (ZMod q))
    (hAT : A * T = H * G) (hHK : H * K = 1)
    (hG : Function.Surjective G.mulVec) (u : Fin n → ZMod q) :
    Nonempty {x // InCoset q A u x} :=
  coset_nonempty_of_surjective q A
    (mulVec_surjective_of_trapdoor A T H K G hAT hHK hG) u

theorem inCoset_liftMatrix_iff (A : Matrix (Fin n) (Fin m) (ZMod q))
    (u : Fin n → ZMod q) (x : Fin m → ℤ) :
    InCoset q A u x ↔ modVector q ((liftMatrix q A) *ᵥ x) = u := by
  rw [mod_mulVec, mod_liftMatrix]
  rfl

theorem inKernel_liftMatrix_iff (A : Matrix (Fin n) (Fin m) (ZMod q))
    (x : Fin m → ℤ) :
    InKernel q (liftMatrix q A) x ↔ InCoset q A 0 x := by
  simp only [InKernel, mod_liftMatrix, InCoset]
  rfl

/-- A coset is exactly a translate of the L2 integer kernel by any solution. -/
theorem inCoset_iff_sub_inKernel (A : Matrix (Fin n) (Fin m) (ZMod q))
    (u : Fin n → ZMod q) (x x₀ : Fin m → ℤ) (hx₀ : InCoset q A u x₀) :
    InCoset q A u x ↔ InKernel q (liftMatrix q A) (x - x₀) := by
  rw [inKernel_liftMatrix_iff]
  have hcast : (fun i => ((x - x₀) i : ZMod q)) =
      (fun i => (x i : ZMod q)) - (fun i => (x₀ i : ZMod q)) := by
    funext i
    exact Int.cast_sub _ _
  unfold InCoset at hx₀ ⊢
  rw [hcast, mulVec_sub, hx₀, sub_eq_zero]

end IntegerLift

end FooLiL3
