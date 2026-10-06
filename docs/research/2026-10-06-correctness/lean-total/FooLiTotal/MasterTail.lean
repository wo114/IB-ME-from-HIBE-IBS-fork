import FooLiL3.IntegerGaussian
import FooLiL3.FourierGaussian
import Mathlib.Probability.Independence.Basic

/-!
# I3: the zero-centred ideal master-trapdoor Gaussian tail

Width convention: rho r a = exp (-pi * a / r^2).  The lattice is the
entire integer grid, not a truncated implementation distribution.
Reference: MP12, Lemma 2.6 (zero-centre branch), PDF page 13;
runtime-integration/实际接入与初始化证据.md, section 4.2.

The Poisson identity and monotonicity below PROVE the width-doubling
comparison for every r > 0. No smoothing or mass-comparison premise is
exported. This file concerns ideal correctness probabilities only.
-/

noncomputable section
open scoped BigOperators
open MeasureTheory FooLiL3
namespace FooLiTotal

/-- Exact Poisson identity on the centred integer grid. -/
theorem master_gaussianZ_poisson (d : ℕ) {r : ℝ} (hr : 0 < r) :
    gaussianZ (@vectorSq d) r = r ^ d * FooLiL2.gridMass d r (fun _ => 0) := by
  have h := tsum_prod_phaseTerm_eq_gridMass d hr (fun _ => 0)
  have hp (x : Fin d → ℤ) :
      (∏ i, phaseTerm r 0 (x i)) = (rho r (vectorSq x) : ℂ) := by
    rw [prod_phaseTerm_eq_rho_mul_exp]
    simp [vectorSq]
  simp_rw [hp] at h
  rw [← Complex.ofReal_tsum] at h
  exact_mod_cast h

/-- The substantive mass comparison: proved from Poisson, not an assumption. -/
theorem master_gaussianZ_double_le (d : ℕ) {r : ℝ} (hr : 0 < r) :
    gaussianZ (@vectorSq d) (2 * r) ≤ (2 : ℝ) ^ d * gaussianZ (@vectorSq d) r := by
  rw [master_gaussianZ_poisson d (by positivity), master_gaussianZ_poisson d hr]
  have hm := FooLiL2.gridMass_antitone d hr (show r ≤ 2 * r by linarith)
    (fun _ => 0)
  calc
    (2 * r) ^ d * FooLiL2.gridMass d (2 * r) (fun _ => 0)
      ≤ (2 * r) ^ d * FooLiL2.gridMass d r (fun _ => 0) :=
        mul_le_mul_of_nonneg_left hm (by positivity)
    _ = _ := by rw [mul_pow]; ring

theorem master_gaussianZ_pos (d : ℕ) {r : ℝ} (hr : 0 < r) :
    0 < gaussianZ (@vectorSq d) r := by
  exact (Real.exp_pos _).trans_le ((vector_rho_summable d hr).le_tsum
    (fun _ => 0) (fun _ _ => (Real.exp_pos _).le))

/-- The normalized infinite Gaussian mass has radial tail at most 2^(-d). -/
theorem master_radial_mass_tail (d : ℕ) {r : ℝ} (hr : 0 < r) :
    (∑' x : {x : Fin d → ℤ // (d : ℝ) * r ^ 2 ≤ vectorSq x},
        rho r (vectorSq x.val)) / gaussianZ (@vectorSq d) r ≤ (1 / 2 : ℝ) ^ d := by
  have h := gaussian_tail_from_mass_comparison (@vectorSq d) d hr
    (e := 0) (by norm_num) (by norm_num)
    (vector_rho_summable d hr) (vector_rho_summable d (by positivity))
    (master_gaussianZ_pos d hr)
    (by simpa using master_gaussianZ_double_le d hr)
  simpa [tailBudget] using h

/-- The exact spherical integer Gaussian, with all convergence proved. -/
def idealMasterGaussian (d : ℕ) (r : ℝ) (hr : 0 < r) : PMF (Fin d → ℤ) :=
  gaussianPMF (@vectorSq d) r (vector_rho_summable d hr) (master_gaussianZ_pos d hr)

theorem integer_gaussianZ_pos {r : ℝ} (hr : 0 < r) :
    0 < gaussianZ (fun z : ℤ => (z : ℝ) ^ 2) r := by
  exact (Real.exp_pos _).trans_le ((integer_rho_summable hr).le_tsum
    0 (fun _ _ => (Real.exp_pos _).le))

/-- The exact one-dimensional D_{Z,r}, normalized over all integers. -/
def idealIntegerGaussian (r : ℝ) (hr : 0 < r) : PMF ℤ :=
  gaussianPMF (fun z : ℤ => (z : ℝ) ^ 2) r
    (integer_rho_summable hr) (integer_gaussianZ_pos hr)

/-- Normalization factorizes; no independence premise is hidden in the mass. -/
theorem master_gaussianZ_product (d : ℕ) {r : ℝ} (hr : 0 < r) :
    gaussianZ (@vectorSq d) r =
      (gaussianZ (fun z : ℤ => (z : ℝ) ^ 2) r) ^ d := by
  unfold gaussianZ
  simp_rw [vector_rho_eq_product]
  rw [FooLiL2.tsum_fin_product d (fun _ z => rho r ((z : ℝ) ^ 2))
    (fun _ => integer_rho_summable hr) (fun _ _ => (Real.exp_pos _).le)]
  simp

/-- Point probabilities are exactly the iid product of scalar Gaussians. -/
theorem idealMasterGaussian_apply_product (d : ℕ) {r : ℝ} (hr : 0 < r)
    (x : Fin d → ℤ) :
    idealMasterGaussian d r hr x = ∏ i, idealIntegerGaussian r hr (x i) := by
  simp only [idealMasterGaussian, idealIntegerGaussian, gaussianPMF_apply]
  have hn (i : Fin d) (_ : i ∈ Finset.univ) :
      0 ≤ rho r ((x i : ℝ) ^ 2) / gaussianZ (fun z : ℤ => (z : ℝ) ^ 2) r :=
    div_nonneg (Real.exp_pos _).le (integer_gaussianZ_pos hr).le
  rw [← ENNReal.ofReal_prod_of_nonneg hn]
  congr 1
  rw [Finset.prod_div_distrib, ← vector_rho_eq_product, master_gaussianZ_product d hr]
  simp

/-- Measure-level identification with the usual product probability law. -/
theorem idealMasterGaussian_toMeasure_eq_pi (d : ℕ) {r : ℝ} (hr : 0 < r) :
    (idealMasterGaussian d r hr).toMeasure =
      Measure.pi (fun _ : Fin d => (idealIntegerGaussian r hr).toMeasure) := by
  apply Measure.ext_of_singleton
  intro x
  simp only [Measure.pi_singleton,
    PMF.toMeasure_apply_singleton _ _ (measurableSet_singleton _)]
  exact idealMasterGaussian_apply_product d hr x

/-- All coordinates are independent under the ideal master law. -/
theorem idealMasterGaussian_independent (d : ℕ) {r : ℝ} (hr : 0 < r) :
    ProbabilityTheory.iIndepFun (fun i (x : Fin d → ℤ) => x i)
      (idealMasterGaussian d r hr).toMeasure := by
  rw [idealMasterGaussian_toMeasure_eq_pi d hr]
  exact ProbabilityTheory.iIndepFun_pi (X := fun _ => id) (fun _ => aemeasurable_id)

/-- Every coordinate has the same exact scalar discrete Gaussian law. -/
theorem idealMasterGaussian_coordinate_law (d : ℕ) {r : ℝ} (hr : 0 < r) (i : Fin d) :
    (idealMasterGaussian d r hr).toMeasure.map (fun x => x i) =
      (idealIntegerGaussian r hr).toMeasure := by
  rw [idealMasterGaussian_toMeasure_eq_pi d hr]
  exact (measurePreserving_eval (fun _ : Fin d =>
    (idealIntegerGaussian r hr).toMeasure) i).map_eq

/-- I3 radial branch: any quality threshold Q >= d*r^2, including d = 0. -/
theorem idealMasterGaussian_quality_tail (d : ℕ) {r Q : ℝ} (hr : 0 < r)
    (hQ : (d : ℝ) * r ^ 2 ≤ Q) :
    (idealMasterGaussian d r hr).toMeasure.real {x | Q < vectorSq x} ≤
      (1 / 2 : ℝ) ^ d := by
  have hE : MeasurableSet {x : Fin d → ℤ | (d : ℝ) * r ^ 2 ≤ vectorSq x} :=
    Set.to_countable _ |>.measurableSet
  have ht := gaussianPMF_tail_from_mass_comparison (@vectorSq d) d hr
    (e := 0) (by norm_num) (by norm_num)
    (vector_rho_summable d hr) (vector_rho_summable d (by positivity))
    (master_gaussianZ_pos d hr)
    (by simpa using master_gaussianZ_double_le d hr) hE
  have hi : {x : Fin d → ℤ | Q < vectorSq x} ⊆
      {x | (d : ℝ) * r ^ 2 ≤ vectorSq x} := fun x hx => hQ.trans hx.le
  have hm := measureReal_mono (μ := (idealMasterGaussian d r hr).toMeasure) hi
  exact hm.trans (by simpa [idealMasterGaussian, tailBudget] using ht)

/-- User-facing I3 for arbitrary iid integer Gaussian random variables.
The only distributional premises specify measurability, independence, and
the scalar Gaussian marginal law; the tail bound itself is not a premise. -/
theorem iid_integerGaussian_quality_tail {Ω : Type*} [MeasurableSpace Ω]
    (μ : Measure Ω) [IsProbabilityMeasure μ] (d : ℕ)
    (X : Fin d → Ω → ℤ) {r Q : ℝ} (hr : 0 < r)
    (hX : ∀ i, Measurable (X i))
    (hInd : ProbabilityTheory.iIndepFun X μ)
    (hLaw : ∀ i, μ.map (X i) = (idealIntegerGaussian r hr).toMeasure)
    (hQ : (d : ℝ) * r ^ 2 ≤ Q) :
    μ.real {ω | Q < ∑ i, (X i ω : ℝ) ^ 2} ≤ (1 / 2 : ℝ) ^ d := by
  have hJoint : μ.map (fun ω i => X i ω) = (idealMasterGaussian d r hr).toMeasure := by
    rw [ProbabilityTheory.iIndepFun.map_fun_eq_pi_map
      (fun i => (hX i).aemeasurable) hInd]
    simp_rw [hLaw]
    exact (idealMasterGaussian_toMeasure_eq_pi d hr).symm
  have ht := idealMasterGaussian_quality_tail d hr hQ
  rw [← hJoint, map_measureReal_apply (Measurable.of_eval hX)
    (Set.to_countable _).measurableSet] at ht
  exact ht

end FooLiTotal
