import FooLiL2.Assembly
import FooLiL2.Cosets
import Mathlib.Analysis.InnerProductSpace.PiL2

/-! Actual q-ary dual-lattice masses, connected to the proved Gaussian coset model. -/

noncomputable section
set_option maxHeartbeats 1000000
open scoped BigOperators
namespace FooLiL2
open Cosets

def gaussianWeight {d : ℕ} (t : ℝ) (x : Fin d → ℝ) : ℝ :=
  Real.exp (-Real.pi * t ^ 2 * ∑ i, x i ^ 2)

/-- The weight uses the Euclidean norm, not the default sup norm on functions. -/
theorem gaussianWeight_eq_euclidean {d : ℕ} (t : ℝ) (x : Fin d → ℝ) :
    gaussianWeight t x =
      Real.exp (-Real.pi * t ^ 2 * ‖WithLp.toLp 2 x‖ ^ 2) := by
  rw [EuclideanSpace.real_norm_sq_eq]
  rfl

def residueShift {n d : ℕ} (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ)
    (a : Fin n → ZMod q) : Fin d → ℝ :=
  shift q C (liftVector q a)

def dualMass {n d : ℕ} (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (t : ℝ) : ℝ :=
  ∑' y : {y : Fin d → ℝ // y ∈ DualSet q C}, gaussianWeight t y.val

/-- Total dual mass minus the origin. The nonzero-sum identity is proved below. -/
def dualTheta {n d : ℕ} (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (t : ℝ) : ℝ :=
  dualMass q C t - 1

theorem dualSet_eq_of_modMatrix_eq {n d : ℕ} (q : ℕ)
    (C D : Matrix (Fin n) (Fin d) ℤ) (h : modMatrix q C = modMatrix q D) :
    (DualSet q C : Set (Fin d → ℝ)) = DualSet q D := by
  ext y
  simp only [DualSet, Set.mem_ofPred_eq, InKernel, h]

theorem dualTheta_eq_of_modMatrix_eq {n d : ℕ} (q : ℕ)
    (C D : Matrix (Fin n) (Fin d) ℤ) (h : modMatrix q C = modMatrix q D) (t : ℝ) :
    dualTheta q C t = dualTheta q D t := by
  unfold dualTheta dualMass
  rw [dualSet_eq_of_modMatrix_eq q C D h]

/-- MP12's scalar spherical smoothing relation, stated directly as a mass bound. -/
def SmoothAt {n d : ℕ} (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) (e t : ℝ) : Prop :=
  0 < t ∧ dualMass q C t ≤ 1 + e

theorem smoothAt_iff_theta {n d : ℕ} (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ)
    (e t : ℝ) : SmoothAt q C e t ↔ 0 < t ∧ dualTheta q C t ≤ e := by
  unfold SmoothAt dualTheta
  constructor <;> rintro ⟨ht, hm⟩ <;> constructor <;> first | exact ht | linarith

theorem summable_cosetParam_weight {n d : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin d) ℤ) {t : ℝ} (ht : 0 < t) :
    Summable (fun az : (Fin n → ZMod q) × (Fin d → ℤ) =>
      gaussianWeight t (cosetParam (K := ℝ) q C az)) := by
  apply (summable_prod_of_nonneg (fun _ => (Real.exp_pos _).le)).mpr
  refine ⟨?_, Summable.of_finite⟩
  intro a
  exact summable_grid_gaussian_exp d ht (residueShift q C a)

theorem summable_dual_weight {n d : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C)
    {t : ℝ} (ht : 0 < t) :
    Summable (fun y : {y : Fin d → ℝ // y ∈ DualSet q C} => gaussianWeight t y.val) := by
  apply (dualEquiv (K := ℝ) q (NeZero.ne q) C hC).summable_iff.mp
  exact summable_cosetParam_weight q C ht

theorem dualMass_eq_coset_sum {n d : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C)
    {t : ℝ} (ht : 0 < t) :
    dualMass q C t = ∑ a : Fin n → ZMod q, gridMass d t (residueShift q C a) := by
  unfold dualMass
  rw [← (dualEquiv (K := ℝ) q (NeZero.ne q) C hC).tsum_eq]
  change (∑' az : (Fin n → ZMod q) × (Fin d → ℤ),
    gaussianWeight t (cosetParam (K := ℝ) q C az)) = _
  rw [(summable_cosetParam_weight q C ht).tsum_prod, tsum_fintype]
  apply Finset.sum_congr rfl
  intro a _
  exact (gridMass_eq_gaussian_tsum d ht (residueShift q C a)).symm

theorem dualTheta_eq_cosetTheta {n d : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C)
    {t : ℝ} (ht : 0 < t) :
    dualTheta q C t = cosetTheta (residueShift q C) t := by
  unfold dualTheta cosetTheta
  rw [dualMass_eq_coset_sum q C hC ht]

theorem zero_mem_dualSet {n d : ℕ} (q : ℕ) (C : Matrix (Fin n) (Fin d) ℤ) :
    (0 : Fin d → ℝ) ∈ DualSet q C := by
  intro x _
  exact ⟨0, by simp⟩

theorem dualTheta_eq_nonzero_tsum {n d : ℕ} (q : ℕ) [NeZero q]
    (C : Matrix (Fin n) (Fin d) ℤ) (hC : FullRowRank q C)
    {t : ℝ} (ht : 0 < t) :
    dualTheta q C t = ∑' y : {y : Fin d → ℝ // y ∈ DualSet q C},
      if y.val = 0 then 0 else gaussianWeight t y.val := by
  classical
  let zeroPoint : {y : Fin d → ℝ // y ∈ DualSet q C} := ⟨0, zero_mem_dualSet q C⟩
  have h := (summable_dual_weight q C hC ht).tsum_eq_add_tsum_ite zeroPoint
  have hz : gaussianWeight t zeroPoint.val = 1 := by simp [gaussianWeight, zeroPoint]
  rw [hz] at h
  have heq : ∀ y : {y : Fin d → ℝ // y ∈ DualSet q C}, y = zeroPoint ↔ y.val = 0 := by
    intro y
    exact Subtype.ext_iff
  simp_rw [heq] at h
  unfold dualTheta dualMass
  linarith

end FooLiL2
