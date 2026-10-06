import FooLiL3.GaussianTail
import Mathlib.Probability.ProbabilityMassFunction.Basic
import Mathlib.Topology.Algebra.InfiniteSum.ENNReal
import Mathlib.MeasureTheory.Measure.Typeclasses.Probability

/-! The exact normalized Gaussian probability measure, not an empirical sampler. -/

noncomputable section
open MeasureTheory
open scoped BigOperators
namespace FooLiL3

def gaussianPMF {X : Type*} (sqLength : X → ℝ) (s : ℝ)
    (hsum : Summable (fun x => rho s (sqLength x)))
    (hz : 0 < gaussianZ sqLength s) : PMF X := by
  refine ⟨fun x => ENNReal.ofReal (rho s (sqLength x) / gaussianZ sqLength s), ?_⟩
  apply ENNReal.summable.hasSum_iff.mpr
  have hn : ∀ x, 0 ≤ rho s (sqLength x) / gaussianZ sqLength s :=
    fun _ => div_nonneg (Real.exp_pos _).le hz.le
  rw [← ENNReal.ofReal_tsum_of_nonneg hn (hsum.div_const _)]
  rw [tsum_div_const]
  change ENNReal.ofReal (gaussianZ sqLength s / gaussianZ sqLength s) = 1
  rw [div_self hz.ne', ENNReal.ofReal_one]

theorem gaussianPMF_apply {X : Type*} (sqLength : X → ℝ) (s : ℝ)
    (hsum : Summable (fun x => rho s (sqLength x)))
    (hz : 0 < gaussianZ sqLength s) (x : X) :
    gaussianPMF sqLength s hsum hz x =
      ENNReal.ofReal (rho s (sqLength x) / gaussianZ sqLength s) := rfl

/-- Probability of every measurable event is the complete normalized mass. -/
theorem gaussianPMF_real_event {X : Type*} [MeasurableSpace X]
    (sqLength : X → ℝ) (s : ℝ)
    (hsum : Summable (fun x => rho s (sqLength x)))
    (hz : 0 < gaussianZ sqLength s) (E : Set X) (hE : MeasurableSet E) :
    (gaussianPMF sqLength s hsum hz).toMeasure.real E =
      (∑' x : E, rho s (sqLength x)) / gaussianZ sqLength s := by
  rw [Measure.real, PMF.toMeasure_apply _ hE, ← tsum_subtype]
  rw [ENNReal.tsum_toReal_eq (fun x : E => by simp [gaussianPMF_apply])]
  have hn : ∀ x : E, 0 ≤ rho s (sqLength x) / gaussianZ sqLength s :=
    fun _ => div_nonneg (Real.exp_pos _).le hz.le
  calc
    _ = ∑' x : E, rho s (sqLength x) / gaussianZ sqLength s := by
      apply tsum_congr
      intro x
      rw [gaussianPMF_apply, ENNReal.toReal_ofReal (hn x)]
    _ = _ := tsum_div_const

theorem gaussianPMF_outer_event {X : Type*}
    (sqLength : X → ℝ) (s : ℝ)
    (hsum : Summable (fun x => rho s (sqLength x)))
    (hz : 0 < gaussianZ sqLength s) (E : Set X) :
    ((gaussianPMF sqLength s hsum hz).toOuterMeasure E).toReal =
      (∑' x : E, rho s (sqLength x)) / gaussianZ sqLength s := by
  let : MeasurableSpace X := ⊤
  have hE : MeasurableSet E := trivial
  have h := gaussianPMF_real_event sqLength s hsum hz E hE
  simpa only [Measure.real, PMF.toMeasure_apply_eq_toOuterMeasure_apply _ hE] using h

/-- The conditional analytic theorem is now about a genuine probability measure. -/
theorem gaussianPMF_tail_from_mass_comparison {X : Type*} [MeasurableSpace X]
    (sqLength : X → ℝ) (m : ℕ) {s e : ℝ}
    (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hsum : Summable (fun x => rho s (sqLength x)))
    (hsum2 : Summable (fun x => rho (2 * s) (sqLength x)))
    (hz : 0 < gaussianZ sqLength s)
    (hdouble : gaussianZ sqLength (2 * s) ≤
      (2 : ℝ) ^ m * ((1 + e) / (1 - e)) * gaussianZ sqLength s)
    (hE : MeasurableSet {x | (m : ℝ) * s ^ 2 ≤ sqLength x}) :
    (gaussianPMF sqLength s hsum hz).toMeasure.real
        {x | (m : ℝ) * s ^ 2 ≤ sqLength x} ≤ tailBudget m e := by
  rw [gaussianPMF_real_event _ _ _ _ _ hE]
  exact gaussian_tail_from_mass_comparison sqLength m hs he he1 hsum hsum2 hz hdouble

end FooLiL3
