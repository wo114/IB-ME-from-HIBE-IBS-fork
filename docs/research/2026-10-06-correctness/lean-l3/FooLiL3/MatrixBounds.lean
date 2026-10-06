import Mathlib.Analysis.InnerProductSpace.PiL2
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.Ring

/-!
# L3: deterministic matrix quality bounds

The entries are integers, but every norm is the real Euclidean norm.  In
particular, `euclideanOp` acts between `EuclideanSpace` instances, not between
the default sup-norm function spaces.  No probabilistic independence is used.
-/

namespace FooLiL3

open scoped BigOperators

variable {m w : ℕ}

/-- Squared Euclidean norm of one integer column, embedded in the reals. -/
def colSq (R : Matrix (Fin m) (Fin w) ℤ) (j : Fin w) : ℝ :=
  ∑ i, (R i j : ℝ) ^ 2

/-- Squared Frobenius norm, grouped by columns. -/
def frobSq (R : Matrix (Fin m) (Fin w) ℤ) : ℝ :=
  ∑ j, colSq R j

theorem colSq_nonneg (R : Matrix (Fin m) (Fin w) ℤ) (j : Fin w) :
    0 ≤ colSq R j :=
  Finset.sum_nonneg fun _ _ => sq_nonneg _

theorem frobSq_nonneg (R : Matrix (Fin m) (Fin w) ℤ) : 0 ≤ frobSq R :=
  Finset.sum_nonneg fun j _ => colSq_nonneg R j

theorem frobSq_le_of_columns (R : Matrix (Fin m) (Fin w) ℤ) {s Q : ℝ}
    (hcols : ∀ j, colSq R j ≤ (m : ℝ) * s ^ 2)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q) : frobSq R ≤ Q := by
  calc
    frobSq R ≤ ∑ _j : Fin w, (m : ℝ) * s ^ 2 :=
      Finset.sum_le_sum fun j _ => hcols j
    _ = (m : ℝ) * (w : ℝ) * s ^ 2 := by simp; ring
    _ ≤ Q := hQ

/-- The exact integer sum used by a squared-norm check equals `frobSq`. -/
theorem frobSq_eq_int_sum (R : Matrix (Fin m) (Fin w) ℤ) :
    frobSq R = ((∑ j, ∑ i, (R i j) ^ 2 : ℤ) : ℝ) := by
  simp [frobSq, colSq]

theorem colSq_eq_norm_sq (R : Matrix (Fin m) (Fin w) ℤ) (j : Fin w) :
    colSq R j = ‖(WithLp.toLp 2 (fun i => (R i j : ℝ)) :
      EuclideanSpace ℝ (Fin m))‖ ^ 2 := by
  rw [EuclideanSpace.real_norm_sq_eq]
  rfl

/-- The paper's unsquared column cutoff is the exact squared-norm cutoff. -/
theorem colSq_le_iff_column_norm_le (R : Matrix (Fin m) (Fin w) ℤ)
    (j : Fin w) {s : ℝ} (hs : 0 ≤ s) :
    colSq R j ≤ (m : ℝ) * s ^ 2 ↔
      ‖(WithLp.toLp 2 (fun i => (R i j : ℝ)) : EuclideanSpace ℝ (Fin m))‖ ≤
        s * Real.sqrt (m : ℝ) := by
  rw [colSq_eq_norm_sq]
  have hm := Real.sq_sqrt (Nat.cast_nonneg m : (0 : ℝ) ≤ m)
  have hn := norm_nonneg
    (WithLp.toLp 2 (fun i => (R i j : ℝ)) : EuclideanSpace ℝ (Fin m))
  have hp : 0 ≤ s * Real.sqrt (m : ℝ) := mul_nonneg hs (Real.sqrt_nonneg _)
  constructor <;> intro h <;> nlinarith

theorem column_norm_gt_iff_colSq_gt (R : Matrix (Fin m) (Fin w) ℤ)
    (j : Fin w) {s : ℝ} (hs : 0 ≤ s) :
    s * Real.sqrt (m : ℝ) <
      ‖(WithLp.toLp 2 (fun i => (R i j : ℝ)) : EuclideanSpace ℝ (Fin m))‖ ↔
      (m : ℝ) * s ^ 2 < colSq R j := by
  simpa only [not_le] using (colSq_le_iff_column_norm_le R j hs).not.symm

/-- Flattening the actual matrix into an actual Euclidean space. -/
def frobeniusVec (R : Matrix (Fin m) (Fin w) ℤ) :
    EuclideanSpace ℝ (Fin w × Fin m) :=
  WithLp.toLp 2 (fun ji => (R ji.2 ji.1 : ℝ))

/-- Frobenius norm is the Euclidean norm of all entries. -/
noncomputable def frobeniusNorm (R : Matrix (Fin m) (Fin w) ℤ) : ℝ :=
  ‖frobeniusVec R‖

theorem frobeniusNorm_sq (R : Matrix (Fin m) (Fin w) ℤ) :
    frobeniusNorm R ^ 2 = frobSq R := by
  simp [frobeniusNorm, EuclideanSpace.real_norm_sq_eq, frobeniusVec,
    Fintype.sum_prod_type, frobSq, colSq]

theorem frobeniusNorm_eq_sqrt (R : Matrix (Fin m) (Fin w) ℤ) :
    frobeniusNorm R = Real.sqrt (frobSq R) := by
  rw [← frobeniusNorm_sq]
  exact (Real.sqrt_sq (show 0 ≤ frobeniusNorm R from norm_nonneg _)).symm

theorem frobSq_eq_row_sum (R : Matrix (Fin m) (Fin w) ℤ) :
    frobSq R = ∑ i, ∑ j, (R i j : ℝ) ^ 2 := by
  exact Finset.sum_comm

/-- The actual real matrix linear map on Euclidean spaces. -/
noncomputable def euclideanLin (R : Matrix (Fin m) (Fin w) ℤ) :
    EuclideanSpace ℝ (Fin w) →ₗ[ℝ] EuclideanSpace ℝ (Fin m) :=
  Matrix.toEuclideanLin (R.map (Int.castRingHom ℝ))

theorem euclideanLin_apply (R : Matrix (Fin m) (Fin w) ℤ)
    (x : EuclideanSpace ℝ (Fin w)) (i : Fin m) :
    euclideanLin R x i = ∑ j, (R i j : ℝ) * x j := by
  rfl

/-- Cauchy--Schwarz row by row gives the squared norm bound. -/
theorem euclideanLin_norm_sq_le (R : Matrix (Fin m) (Fin w) ℤ)
    (x : EuclideanSpace ℝ (Fin w)) :
    ‖euclideanLin R x‖ ^ 2 ≤ frobSq R * ‖x‖ ^ 2 := by
  rw [EuclideanSpace.real_norm_sq_eq, EuclideanSpace.real_norm_sq_eq,
    frobSq_eq_row_sum, Finset.sum_mul]
  apply Finset.sum_le_sum
  intro i _
  rw [euclideanLin_apply]
  exact Finset.sum_mul_sq_le_sq_mul_sq Finset.univ (fun j => (R i j : ℝ))
    (fun j => x j)

theorem euclideanLin_norm_le (R : Matrix (Fin m) (Fin w) ℤ)
    (x : EuclideanSpace ℝ (Fin w)) :
    ‖euclideanLin R x‖ ≤ Real.sqrt (frobSq R) * ‖x‖ := by
  have hb := euclideanLin_norm_sq_le R x
  have hs := Real.sq_sqrt (frobSq_nonneg R)
  have hp : 0 ≤ Real.sqrt (frobSq R) * ‖x‖ :=
    mul_nonneg (Real.sqrt_nonneg _) (norm_nonneg _)
  nlinarith [sq_nonneg (‖euclideanLin R x‖ + Real.sqrt (frobSq R) * ‖x‖)]

/-- Continuous realization; the ambient operator norm is the Euclidean one. -/
noncomputable def euclideanOp (R : Matrix (Fin m) (Fin w) ℤ) :
    EuclideanSpace ℝ (Fin w) →L[ℝ] EuclideanSpace ℝ (Fin m) :=
  (euclideanLin R).mkContinuous (Real.sqrt (frobSq R)) (euclideanLin_norm_le R)

theorem euclideanOp_apply (R : Matrix (Fin m) (Fin w) ℤ)
    (x : EuclideanSpace ℝ (Fin w)) (i : Fin m) :
    euclideanOp R x i = ∑ j, (R i j : ℝ) * x j := by
  rfl

theorem euclideanOp_norm_le_frobenius (R : Matrix (Fin m) (Fin w) ℤ) :
    ‖euclideanOp R‖ ≤ Real.sqrt (frobSq R) :=
  LinearMap.mkContinuous_norm_le _ (Real.sqrt_nonneg _) _

theorem euclideanOp_norm_le_frobeniusNorm (R : Matrix (Fin m) (Fin w) ℤ) :
    ‖euclideanOp R‖ ≤ frobeniusNorm R := by
  rw [frobeniusNorm_eq_sqrt]
  exact euclideanOp_norm_le_frobenius R

theorem frobeniusNorm_le_sqrt_of_columns
    (R : Matrix (Fin m) (Fin w) ℤ) {s Q : ℝ}
    (hcols : ∀ j, colSq R j ≤ (m : ℝ) * s ^ 2)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q) :
    frobeniusNorm R ≤ Real.sqrt Q := by
  rw [frobeniusNorm_eq_sqrt]
  exact Real.sqrt_le_sqrt (frobSq_le_of_columns R hcols hQ)

theorem euclideanOp_norm_sq_le_frobSq (R : Matrix (Fin m) (Fin w) ℤ) :
    ‖euclideanOp R‖ ^ 2 ≤ frobSq R := by
  have hb := euclideanOp_norm_le_frobenius R
  have hs := Real.sq_sqrt (frobSq_nonneg R)
  nlinarith [norm_nonneg (euclideanOp R)]

theorem euclideanOp_norm_le_sqrt_of_columns
    (R : Matrix (Fin m) (Fin w) ℤ) {s Q : ℝ}
    (hcols : ∀ j, colSq R j ≤ (m : ℝ) * s ^ 2)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q) :
    ‖euclideanOp R‖ ≤ Real.sqrt Q :=
  (euclideanOp_norm_le_frobenius R).trans
    (Real.sqrt_le_sqrt (frobSq_le_of_columns R hcols hQ))

theorem euclideanOp_norm_sq_le_of_columns
    (R : Matrix (Fin m) (Fin w) ℤ) {s Q : ℝ}
    (hcols : ∀ j, colSq R j ≤ (m : ℝ) * s ^ 2)
    (hQ : (m : ℝ) * (w : ℝ) * s ^ 2 ≤ Q) :
    ‖euclideanOp R‖ ^ 2 ≤ Q :=
  (euclideanOp_norm_sq_le_frobSq R).trans (frobSq_le_of_columns R hcols hQ)

end FooLiL3
