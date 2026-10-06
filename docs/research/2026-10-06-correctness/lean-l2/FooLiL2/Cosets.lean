import Mathlib.Data.ZMod.Basic
import Mathlib.Algebra.Field.ZMod
import Mathlib.Data.Matrix.Mul
import Mathlib.Basic.Real.Basic
import Mathlib.LinearAlgebra.Matrix.Rank
import Mathlib.LinearAlgebra.BilinearForm.DualLattice
import Mathlib.Tactic.Ring
import Mathlib.Data.Fin.Tuple.Basic
import Mathlib.Algebra.BigOperators.Fin

/-!
# Matrix and coset component of Foo--Li L2

The matrix is an integer lift `C : Matrix (Fin n) (Fin d) ℤ`.
Its reduction is explicitly `modMatrix q C`.  Full row rank is expressed by
surjectivity of its action on `(Fin d → ZMod q)`.
No Gaussian claim is made in this file.
-/

namespace FooLiL2.Cosets

open Matrix
open scoped BigOperators

variable {n d : ℕ}

def modVector (q : ℕ) (x : Fin d → ℤ) : Fin d → ZMod q := fun j => x j

def modMatrix (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) :
    Matrix (Fin n) (Fin d) (ZMod q) := fun i j => C i j

def liftVector (q : ℕ) (a : Fin n → ZMod q) : Fin n → ℤ :=
  fun i => ZMod.cast (a i)

def liftMatrix (q : ℕ) (C : Matrix (Fin n) (Fin d) (ZMod q)) :
    Matrix (Fin n) (Fin d) ℤ := fun i j => ZMod.cast (C i j)

@[simp] theorem mod_liftMatrix (q : ℕ) (C : Matrix (Fin n) (Fin d) (ZMod q)) :
    modMatrix q (liftMatrix q C) = C := by
  ext i j
  exact ZMod.intCast_zmod_cast (C i j)

@[simp] theorem mod_liftVector (q : ℕ) (a : Fin n → ZMod q) :
    modVector q (liftVector q a) = a := by
  funext i
  exact ZMod.intCast_zmod_cast (a i)

theorem mod_mulVec (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (x : Fin d → ℤ) :
    modVector q (C *ᵥ x) = modMatrix q C *ᵥ modVector q x := by
  funext i
  simp [modVector, modMatrix, mulVec, dotProduct, Int.cast_sum, Int.cast_mul]

/-- The full-row-rank hypothesis, as surjectivity of the finite modular linear map. -/
def FullRowRank (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) : Prop :=
  Function.Surjective (modMatrix q C).mulVec

/-- Over a field, the surjectivity hypothesis is exactly rank n. -/
theorem matrix_surjective_iff_rank {R : Type*} [Field R]
    (C : Matrix (Fin n) (Fin d) R) : Function.Surjective C.mulVec ↔ C.rank = n := by
  constructor
  · intro h
    have hr := LinearMap.range_eq_top.mpr (show Function.Surjective C.mulVecLin from h)
    unfold Matrix.rank
    rw [hr]
    simp
  · intro h
    change Function.Surjective C.mulVecLin
    apply LinearMap.range_eq_top.mp
    apply Submodule.eq_top_of_finrank_eq (K := R)
    simpa only [Matrix.rank, Module.finrank_pi, Module.finrank_self, Finset.sum_const,
      Finset.card_univ, Fintype.card_fin, smul_eq_mul, mul_one] using h

/-- Stable source-facing API: prime-modulus full row rank is exactly rank n. -/
theorem fullRowRank_iff_rank (q : ℕ) [Fact q.Prime]
    (C : Matrix (Fin n) (Fin d) ℤ) : FullRowRank q C ↔ (modMatrix q C).rank = n :=
  matrix_surjective_iff_rank (modMatrix q C)

/-- Surjectivity implies injectivity of the transpose, proved using coordinate dot products. -/
theorem transpose_injective_of_surjective {R : Type*} [CommRing R]
    (C : Matrix (Fin n) (Fin d) R) (hC : Function.Surjective C.mulVec) :
    Function.Injective C.transpose.mulVec := by
  intro a b hab
  funext i
  obtain ⟨x, hx⟩ := hC (Pi.single i 1)
  have h := congrArg (fun v => dotProduct v x) hab
  have ha : dotProduct (C.transpose *ᵥ a) x = dotProduct a (C *ᵥ x) := by
    rw [dotProduct_mulVec, mulVec_transpose]
  have hb : dotProduct (C.transpose *ᵥ b) x = dotProduct b (C *ᵥ x) := by
    rw [dotProduct_mulVec, mulVec_transpose]
  rw [ha, hb, hx, dotProduct_single_one, dotProduct_single_one] at h
  exact h

theorem transpose_mod_injective (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ)
    (hC : FullRowRank q C) : Function.Injective (modMatrix q C).transpose.mulVec :=
  transpose_injective_of_surjective _ hC

/-- A q-ary kernel vector, still represented over the integers. -/
def InKernel (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (x : Fin d → ℤ) : Prop :=
  modMatrix q C *ᵥ modVector q x = 0

theorem inKernel_iff_dvd (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (x : Fin d → ℤ) :
    InKernel q C x ↔ ∀ i, (q : ℤ) ∣ (C *ᵥ x) i := by
  rw [InKernel, ← mod_mulVec]
  constructor
  · intro h i
    exact (ZMod.intCast_zmod_eq_zero_iff_dvd _ _).mp (congrFun h i)
  · intro h
    funext i
    exact (ZMod.intCast_zmod_eq_zero_iff_dvd _ _).mpr (h i)

section CoordinateDual

variable {K : Type*} [Field K] [CharZero K]

def intVector (x : Fin d → ℤ) : Fin d → K := fun j => x j

omit [CharZero K] in
@[simp] theorem intVector_sub (x z : Fin d → ℤ) :
    intVector (K := K) (x - z) = intVector x - intVector z := by
  funext j
  simp [intVector]

omit [CharZero K] in
@[simp] theorem intVector_single (j : Fin d) (a : ℤ) :
    intVector (K := K) (Pi.single j a) = Pi.single j (a : K) := by
  funext k
  by_cases h : j = k <;> simp [intVector, h]

/-- Integral-pairing definition of the dual in coordinate space. -/
def DualSet (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) : Set (Fin d → K) :=
  {y | ∀ x : Fin d → ℤ, InKernel q C x → ∃ k : ℤ, dotProduct y (intVector x) = k}

def shift (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (a : Fin n → ℤ) : Fin d → K :=
  fun j => ((C.transpose *ᵥ a) j : K) / (q : K)

def integerCoset (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (a : Fin n → ℤ) :
    Set (Fin d → K) := {y | ∃ z : Fin d → ℤ, y = intVector z + shift q C a}

omit [CharZero K] in
theorem shift_pairing (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ)
    (a : Fin n → ℤ) (x : Fin d → ℤ) :
    dotProduct (shift q C a : Fin d → K) (intVector x) =
      ((dotProduct a (C *ᵥ x) : ℤ) : K) / (q : K) := by
  have h : dotProduct (C.transpose *ᵥ a) x = dotProduct a (C *ᵥ x) := by
    rw [dotProduct_mulVec, mulVec_transpose]
  rw [← h]
  simp only [shift, intVector, dotProduct, Int.cast_sum, Int.cast_mul]
  simp_rw [div_mul_eq_mul_div]
  simp only [div_eq_mul_inv, Finset.sum_mul]

theorem integerCoset_subset_dual (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (a : Fin n → ℤ) :
    integerCoset q C a ⊆ (DualSet q C : Set (Fin d → K)) := by
  rintro y ⟨z, rfl⟩ x hx
  have hd := (inKernel_iff_dvd q C x).mp hx
  choose k hk using hd
  refine ⟨dotProduct z x + dotProduct a k, ?_⟩
  rw [add_dotProduct, shift_pairing]
  have hdot : dotProduct a (C *ᵥ x) = (q : ℤ) * dotProduct a k := by
    simp only [dotProduct, hk, Finset.mul_sum]
    apply Finset.sum_congr rfl
    intro i _
    ring
  rw [hdot]
  have hqK : (q : K) ≠ 0 := Nat.cast_ne_zero.mpr hq
  simp [intVector, dotProduct, Int.cast_sum, Int.cast_mul, hqK]

omit [CharZero K] in
/-- Zero label retains the whole integer lattice, including nonzero integer points. -/
theorem integerCoset_zero (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) :
    integerCoset q C (0 : Fin n → ℤ) = Set.range (intVector (K := K) (d := d)) := by
  have hs : (shift q C 0 : Fin d → K) = 0 := by
    funext j
    simp [shift]
  ext y
  simp [integerCoset, hs, Set.mem_range, eq_comm]

/-- A modular right inverse with entries lifted to the integers. -/
theorem exists_integer_right_inverse (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ)
    (hC : FullRowRank q C) :
    ∃ D : Matrix (Fin d) (Fin n) ℤ, modMatrix q C * modMatrix q D = 1 := by
  classical
  choose v hv using fun i : Fin n => hC (Pi.single i 1)
  let D : Matrix (Fin d) (Fin n) ℤ := fun j i => liftVector q (v i) j
  refine ⟨D, ?_⟩
  ext i j
  have h := congrFun (hv j) i
  simpa [D, mul_apply, mulVec, dotProduct, modMatrix, liftVector,
    Matrix.one_apply, Pi.single_apply, eq_comm] using h

@[simp] theorem modVector_sub (q : ℕ) (x z : Fin d → ℤ) :
    modVector q (x - z) = modVector q x - modVector q z := by
  funext j
  simp [modVector]

theorem right_inverse_residual_inKernel (q : ℕ)
    (C : Matrix (Fin n) (Fin d) ℤ) (D : Matrix (Fin d) (Fin n) ℤ)
    (hD : modMatrix q C * modMatrix q D = 1) (x : Fin d → ℤ) :
    InKernel q C (x - D *ᵥ (C *ᵥ x)) := by
  unfold InKernel
  rw [modVector_sub, mod_mulVec, mod_mulVec, mulVec_sub, mulVec_mulVec, hD,
    one_mulVec, sub_self]

theorem q_single_inKernel (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (j : Fin d) :
    InKernel q C (Pi.single j (q : ℤ)) := by
  have hz : modVector q (Pi.single j (q : ℤ)) = 0 := by
    funext k
    by_cases h : j = k <;> simp [modVector, h]
  simp [InKernel, hz]

omit [CharZero K] in
/-- Every dual point has denominator dividing q, obtained by pairing with q e_j. -/
theorem dual_denominator (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ)
    {y : Fin d → K} (hy : y ∈ DualSet q C) :
    ∃ b : Fin d → ℤ, ∀ j, y j * (q : K) = (b j : K) := by
  have h : ∀ j : Fin d, ∃ b : ℤ, y j * (q : K) = (b : K) := by
    intro j
    obtain ⟨b, hb⟩ := hy _ (q_single_inKernel q C j)
    exact ⟨b, by simpa using hb⟩
  choose b hb using h
  exact ⟨b, hb⟩

theorem denominator_pairing (q : ℕ) (hq : q ≠ 0) {y : Fin d → K}
    (b : Fin d → ℤ) (hb : ∀ j, y j * (q : K) = (b j : K)) (x : Fin d → ℤ) :
    dotProduct y (intVector x) = ((dotProduct b x : ℤ) : K) / (q : K) := by
  have hqK : (q : K) ≠ 0 := Nat.cast_ne_zero.mpr hq
  have hy : ∀ j, y j = (b j : K) / (q : K) := fun j => (eq_div_iff hqK).mpr (hb j)
  simp only [dotProduct, intVector, hy, Int.cast_sum, Int.cast_mul]
  simp_rw [div_mul_eq_mul_div]
  simp only [div_eq_mul_inv, Finset.sum_mul]

/-- Constructive reverse inclusion; no decomposition conclusion is assumed. -/
theorem dual_subset_integerCosets (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C) :
    (DualSet q C : Set (Fin d → K)) ⊆ ⋃ a : Fin n → ℤ, integerCoset q C a := by
  intro y hy
  obtain ⟨D, hD⟩ := exists_integer_right_inverse q C hC
  obtain ⟨b, hb⟩ := dual_denominator q C hy
  have hz : ∀ j : Fin d, ∃ z : ℤ,
      y j - ((C.transpose *ᵥ (D.transpose *ᵥ b)) j : K) / (q : K) = (z : K) := by
    intro j
    obtain ⟨z, hz⟩ := hy _ (right_inverse_residual_inKernel q C D hD (Pi.single j 1))
    have hdot : dotProduct b (D *ᵥ (C *ᵥ Pi.single j 1)) =
        (C.transpose *ᵥ (D.transpose *ᵥ b)) j := by
      simp only [mulVec_transpose]
      rw [dotProduct_mulVec, dotProduct_mulVec, dotProduct_single_one]
    refine ⟨z, ?_⟩
    simpa only [intVector_sub, dotProduct_sub, intVector_single, Int.cast_one,
      dotProduct_single_one, denominator_pairing q hq b hb, hdot] using hz
  choose z hz using hz
  refine Set.mem_iUnion.mpr ⟨D.transpose *ᵥ b, z, ?_⟩
  funext j
  exact sub_eq_iff_eq_add.mp (hz j)

theorem dual_eq_integerCosets (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C) :
    (DualSet q C : Set (Fin d → K)) = ⋃ a : Fin n → ℤ, integerCoset q C a := by
  apply Set.Subset.antisymm (dual_subset_integerCosets q hq C hC)
  intro y hy
  obtain ⟨a, ha⟩ := Set.mem_iUnion.mp hy
  exact integerCoset_subset_dual q hq C a ha

theorem div_eq_integer_add_of_mod_eq (q : ℕ) (hq : q ≠ 0) (a b : ℤ)
    (hab : (a : ZMod q) = (b : ZMod q)) :
    ∃ z : ℤ, (a : K) / (q : K) = (z : K) + (b : K) / (q : K) := by
  have hz : ((a - b : ℤ) : ZMod q) = 0 := by simp [hab]
  obtain ⟨z, hz⟩ := (ZMod.intCast_zmod_eq_zero_iff_dvd _ _).mp hz
  refine ⟨z, ?_⟩
  have hqK : (q : K) ≠ 0 := Nat.cast_ne_zero.mpr hq
  rw [← sub_eq_iff_eq_add, div_sub_div_same, div_eq_iff hqK]
  calc
    (a : K) - (b : K) = ((a - b : ℤ) : K) := (Int.cast_sub _ _).symm
    _ = (z : K) * (q : K) := by rw [hz]; simp [mul_comm]

/-- Changing an integer label by multiples of q does not change its real/rational coset. -/
theorem integerCoset_eq_of_mod_eq (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (a b : Fin n → ℤ)
    (hab : modVector q a = modVector q b) :
    (integerCoset q C a : Set (Fin d → K)) = integerCoset q C b := by
  have hn : modVector q (C.transpose *ᵥ a) = modVector q (C.transpose *ᵥ b) := by
    rw [mod_mulVec, mod_mulVec, hab]
  have hsub : ∀ (a b : Fin n → ℤ),
      modVector q (C.transpose *ᵥ a) = modVector q (C.transpose *ᵥ b) →
      (integerCoset q C a : Set (Fin d → K)) ⊆ integerCoset q C b := by
    intro a b h y hy
    obtain ⟨z, rfl⟩ := hy
    have hh := fun j => div_eq_integer_add_of_mod_eq (K := K) q hq
      ((C.transpose *ᵥ a) j) ((C.transpose *ᵥ b) j) (congrFun h j)
    choose k hk using hh
    refine ⟨z + k, ?_⟩
    funext j
    simp only [Pi.add_apply, intVector, shift, Int.cast_add, hk]
    ring
  exact Set.Subset.antisymm (hsub a b hn) (hsub b a hn.symm)

def residueCoset (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (a : Fin n → ZMod q) :
    Set (Fin d → K) := integerCoset q C (liftVector q a)

/-- The dual decomposition with exactly the ZMod labels used in L2. -/
theorem dual_eq_residueCosets (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C) :
    (DualSet q C : Set (Fin d → K)) = ⋃ a : Fin n → ZMod q, residueCoset q C a := by
  rw [dual_eq_integerCosets q hq C hC]
  apply Set.Subset.antisymm
  · intro y hy
    obtain ⟨a, ha⟩ := Set.mem_iUnion.mp hy
    refine Set.mem_iUnion.mpr ⟨modVector q a, ?_⟩
    have he := integerCoset_eq_of_mod_eq (K := K) q hq C a
      (liftVector q (modVector q a)) (mod_liftVector q _).symm
    change y ∈ integerCoset q C (liftVector q (modVector q a))
    rw [← he]
    exact ha
  · intro y hy
    obtain ⟨a, ha⟩ := Set.mem_iUnion.mp hy
    exact Set.mem_iUnion.mpr ⟨liftVector q a, ha⟩

/-- An intersection forces the transpose labels to agree modulo q. -/
theorem overlap_mod_transpose (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (a b : Fin n → ℤ) {y : Fin d → K}
    (ha : y ∈ integerCoset q C a) (hb : y ∈ integerCoset q C b) :
    modVector q (C.transpose *ᵥ a) = modVector q (C.transpose *ᵥ b) := by
  obtain ⟨z, hz⟩ := ha
  obtain ⟨w, hw⟩ := hb
  have hqK : (q : K) ≠ 0 := Nat.cast_ne_zero.mpr hq
  funext j
  have he := congrArg (fun v : Fin d → K => v j * (q : K)) (hz.symm.trans hw)
  simp only [Pi.add_apply, intVector, shift, add_mul, div_mul_cancel₀ _ hqK] at he
  have hi : (C.transpose *ᵥ a) j - (C.transpose *ᵥ b) j = (q : ℤ) * (w j - z j) := by
    apply Int.cast_injective (α := K)
    simp only [Int.cast_sub, Int.cast_mul, Int.cast_natCast]
    calc
      ((C.transpose *ᵥ a) j : K) - ((C.transpose *ᵥ b) j : K) =
          ((z j : K) * q + ((C.transpose *ᵥ a) j : K)) - (z j : K) * q -
            ((C.transpose *ᵥ b) j : K) := by ring
      _ = ((w j : K) * q + ((C.transpose *ᵥ b) j : K)) - (z j : K) * q -
            ((C.transpose *ᵥ b) j : K) := by rw [he]
      _ = (q : K) * ((w j : K) - (z j : K)) := by ring
  have hm := congrArg (fun k : ℤ => (k : ZMod q)) hi
  simp only [Int.cast_sub, Int.cast_mul, Int.cast_natCast, ZMod.natCast_self,
    zero_mul] at hm
  exact sub_eq_zero.mp hm

theorem residueCoset_label_unique (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C)
    (a b : Fin n → ZMod q) {y : Fin d → K}
    (ha : y ∈ residueCoset q C a) (hb : y ∈ residueCoset q C b) : a = b := by
  have h := overlap_mod_transpose q hq C (liftVector q a) (liftVector q b) ha hb
  rw [mod_mulVec, mod_mulVec, mod_liftVector, mod_liftVector] at h
  exact transpose_mod_injective q C hC h

theorem residueCosets_pairwiseDisjoint (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C) :
    Pairwise (fun a b : Fin n → ZMod q =>
      Disjoint (residueCoset (K := K) q C a) (residueCoset q C b)) := by
  intro a b hab
  apply Set.disjoint_left.mpr
  intro y ha hb
  exact hab (residueCoset_label_unique q hq C hC a b ha hb)

omit [CharZero K] in
@[simp] theorem residueCoset_zero (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) :
    residueCoset (K := K) q C 0 = Set.range (intVector (K := K) (d := d)) := by
  have hz : liftVector q (0 : Fin n → ZMod q) = 0 := by
    funext i
    simp [liftVector]
  simp only [residueCoset, hz, integerCoset_zero]

/-- The actual q-ary integer lattice embedded in coordinate space. -/
def qaryLattice (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) : Submodule ℤ (Fin d → K) where
  carrier := {y | ∃ x : Fin d → ℤ, InKernel q C x ∧ y = intVector x}
  zero_mem' := by
    refine ⟨0, ?_, ?_⟩
    · have hm : modVector q (0 : Fin d → ℤ) = 0 := by
        ext j
        simp [modVector]
      rw [InKernel, hm, mulVec_zero]
    · ext j
      simp [intVector]
  add_mem' := by
    rintro _ _ ⟨x, hx, rfl⟩ ⟨z, hz, rfl⟩
    refine ⟨x + z, ?_, ?_⟩
    · have hm : modVector q (x + z) = modVector q x + modVector q z := by
        ext j
        simp [modVector]
      change modMatrix q C *ᵥ modVector q x = 0 at hx
      change modMatrix q C *ᵥ modVector q z = 0 at hz
      rw [InKernel, hm, mulVec_add, hx, hz, add_zero]
    · ext j
      simp [intVector]
  smul_mem' := by
    rintro r _ ⟨x, hx, rfl⟩
    refine ⟨r • x, ?_, ?_⟩
    · have hm : modVector q (r • x) = r • modVector q x := by
        ext j
        simp [modVector]
      change modMatrix q C *ᵥ modVector q x = 0 at hx
      rw [InKernel, hm, mulVec_smul, hx, smul_zero]
    · ext j
      simp [intVector]

omit [CharZero K] in
/-- The explicit integral-pairing set agrees with Mathlib's genuine dual submodule. -/
theorem dualSet_eq_dualSubmodule (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) :
    (DualSet q C : Set (Fin d → K)) =
      (LinearMap.BilinForm.dualSubmodule
        (dotProductBilin K K : LinearMap.BilinForm K (Fin d → K))
        (qaryLattice (K := K) q C) : Set (Fin d → K)) := by
  ext y
  constructor
  · intro hy
    apply (LinearMap.BilinForm.mem_dualSubmodule _).mpr
    rintro _ ⟨x, hx, rfl⟩
    obtain ⟨k, hk⟩ := hy x hx
    apply Submodule.mem_one.mpr
    exact ⟨k, by simpa using hk.symm⟩
  · intro hy x hx
    have hm := (LinearMap.BilinForm.mem_dualSubmodule _).mp hy (intVector x) ⟨x, hx, rfl⟩
    obtain ⟨k, hk⟩ := Submodule.mem_one.mp hm
    exact ⟨k, by simpa using hk.symm⟩

/-- Real-coordinate dual lattice equals the union of integer translates of Cᵀ a / q. -/
theorem real_dual_eq_residueCosets (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C) :
    (LinearMap.BilinForm.dualSubmodule
      (dotProductBilin ℝ ℝ : LinearMap.BilinForm ℝ (Fin d → ℝ))
      (qaryLattice (K := ℝ) q C) : Set (Fin d → ℝ)) =
      ⋃ a : Fin n → ZMod q, residueCoset q C a := by
  rw [← dualSet_eq_dualSubmodule, dual_eq_residueCosets q hq C hC]

def cosetParam (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ)
    (az : (Fin n → ZMod q) × (Fin d → ℤ)) : Fin d → K :=
  intVector az.2 + shift q C (liftVector q az.1)

theorem cosetParam_mem_dual (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (az : (Fin n → ZMod q) × (Fin d → ℤ)) :
    cosetParam (K := K) q C az ∈ DualSet q C :=
  integerCoset_subset_dual q hq C (liftVector q az.1) ⟨az.2, rfl⟩

theorem cosetParam_injective (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C) :
    Function.Injective (cosetParam (K := K) q C) := by
  rintro ⟨a, z⟩ ⟨b, w⟩ hab
  have ha : cosetParam (K := K) q C (a, z) ∈ residueCoset q C a := ⟨z, rfl⟩
  have hb : cosetParam (K := K) q C (a, z) ∈ residueCoset q C b := ⟨w, hab⟩
  have hl := residueCoset_label_unique q hq C hC a b ha hb
  subst b
  have hv : intVector (K := K) z = intVector w := add_right_cancel hab
  have hzw : z = w := by
    funext j
    exact Int.cast_injective (α := K) (congrFun hv j)
  subst w
  rfl

/-- Exact reindexing map requested for the Gaussian integration task: (a,z) ↦ z+Cᵀlift(a)/q. -/
noncomputable def dualEquiv (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C) :
    ((Fin n → ZMod q) × (Fin d → ℤ)) ≃ {y : Fin d → K // y ∈ DualSet q C} :=
  Equiv.ofBijective
    (fun az => ⟨cosetParam q C az, cosetParam_mem_dual q hq C az⟩)
    ⟨fun _ _ h => cosetParam_injective q hq C hC (congrArg Subtype.val h), by
      rintro ⟨y, hy⟩
      rw [dual_eq_residueCosets q hq C hC] at hy
      obtain ⟨a, z, hz⟩ := Set.mem_iUnion.mp hy
      exact ⟨(a, z), Subtype.ext hz.symm⟩⟩

@[simp] theorem dualEquiv_apply (q : ℕ) (hq : q ≠ 0)
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C)
    (az : (Fin n → ZMod q) × (Fin d → ℤ)) :
    ((dualEquiv (K := K) q hq C hC az : {y // y ∈ DualSet q C}) : Fin d → K) =
      intVector az.2 + shift q C (liftVector q az.1) := rfl

end CoordinateDual

def appendMatrix {m w : ℕ} (A : Matrix (Fin n) (Fin m) ℤ)
    (B : Matrix (Fin n) (Fin w) ℤ) : Matrix (Fin n) (Fin (m + w)) ℤ :=
  fun i => Fin.append (A i) (B i)

theorem fullRowRank_append {m w : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (hA : FullRowRank q A) : FullRowRank q (appendMatrix A B) := by
  intro y
  obtain ⟨x, hx⟩ := hA y
  refine ⟨Fin.append x 0, ?_⟩
  rw [← hx]
  funext i
  simp [modMatrix, appendMatrix, mulVec, dotProduct, Fin.sum_univ_add]

theorem shift_append {K : Type*} [Field K] {m w : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) ℤ) (B : Matrix (Fin n) (Fin w) ℤ)
    (a : Fin n → ℤ) :
    (shift q (appendMatrix A B) a : Fin (m + w) → K) =
      Fin.append (shift q A a) (shift q B a) := by
  funext j
  refine Fin.addCases ?_ ?_ j
  · intro i
    simp [shift, mulVec, dotProduct, transpose_apply, appendMatrix]
  · intro i
    simp [shift, mulVec, dotProduct, transpose_apply, appendMatrix]

end FooLiL2.Cosets
