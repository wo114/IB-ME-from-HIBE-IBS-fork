import FooLiTotal.MasterTail

/-!
I3 independent audit entry point.
Run after compiling MasterTail with `lake env lean -o ...` (or by the main
agent's serialized library build). Every printed dependency list should
contain only propext, Classical.choice, and Quot.sound.

This is an ideal zero-centred integer Gaussian theorem. It does not discharge
I1 geometry, byte-sampler TV, SHAKE/CSPRNG replacement, matrix serialization,
or the implementation-to-probability-law refinement.
-/

#check FooLiTotal.idealMasterGaussian_quality_tail
#check FooLiTotal.iid_integerGaussian_quality_tail
#print axioms FooLiTotal.master_gaussianZ_poisson
#print axioms FooLiTotal.master_gaussianZ_double_le
#print axioms FooLiTotal.master_radial_mass_tail
#print axioms FooLiTotal.idealMasterGaussian_apply_product
#print axioms FooLiTotal.idealMasterGaussian_toMeasure_eq_pi
#print axioms FooLiTotal.idealMasterGaussian_independent
#print axioms FooLiTotal.idealMasterGaussian_coordinate_law
#print axioms FooLiTotal.idealMasterGaussian_quality_tail
#print axioms FooLiTotal.iid_integerGaussian_quality_tail

open MeasureTheory FooLiL3 FooLiTotal

-- Equality at Q = d*r^2 is accepted, with no epsilon or smoothing witness.
example (d : ℕ) (r : ℝ) (hr : 0 < r) :
    (idealMasterGaussian d r hr).toMeasure.real
      {x | (d : ℝ) * r ^ 2 < vectorSq x} ≤ (1 / 2 : ℝ) ^ d :=
  idealMasterGaussian_quality_tail d hr le_rfl

-- The zero-dimensional case requires no nonempty-index premise.
example (r Q : ℝ) (hr : 0 < r) (hQ : 0 ≤ Q) :
    (idealMasterGaussian 0 r hr).toMeasure.real {x | Q < vectorSq x} ≤ 1 := by
  have hthreshold : ((0 : ℕ) : ℝ) * r ^ 2 ≤ Q := by
    simpa only [Nat.cast_zero, zero_mul] using hQ
  simpa only [pow_zero] using idealMasterGaussian_quality_tail 0 hr hthreshold
