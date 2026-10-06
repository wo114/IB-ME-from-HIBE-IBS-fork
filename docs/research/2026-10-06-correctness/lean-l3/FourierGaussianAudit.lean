import FooLiL3.FourierGaussian

-- Dedicated audit scratch: every public declaration introduced in FourierGaussian.
#print axioms FooLiL3.phaseTerm
#print axioms FooLiL3.norm_phaseTerm
#print axioms FooLiL3.phaseTerm_eq_mul_exp
#print axioms FooLiL3.phaseTerm_eq_rho_mul_exp
#print axioms FooLiL3.norm_phaseTerm_eq_rho
#print axioms FooLiL3.summable_norm_phaseTerm
#print axioms FooLiL3.summable_phaseTerm
#print axioms FooLiL3.gaussian_poisson_prefactor
#print axioms FooLiL3.tsum_phaseTerm_eq_gaussianMass
#print axioms FooLiL3.hasSum_phaseTerm
#print axioms FooLiL3.summable_norm_dualGaussian
#print axioms FooLiL3.tsum_gaussian_mul_phase
#print axioms FooLiL3.summable_norm_fin_complex_product
#print axioms FooLiL3.tsum_fin_complex_product
#print axioms FooLiL3.summable_norm_prod_phaseTerm
#print axioms FooLiL3.summable_prod_phaseTerm
#print axioms FooLiL3.tsum_prod_phaseTerm_eq_gridMass
#print axioms FooLiL3.hasSum_prod_phaseTerm
#print axioms FooLiL3.norm_prod_phaseTerm_eq_rho
#print axioms FooLiL3.prod_phaseTerm_eq_rho_mul_exp

#check FooLiL3.tsum_phaseTerm_eq_gaussianMass
#check FooLiL3.tsum_prod_phaseTerm_eq_gridMass
#check FooLiL3.prod_phaseTerm_eq_rho_mul_exp

-- The full-domain result also handles the empty product (dimension zero).
example (s : ℝ) :
    (∑' z : Fin 0 → ℤ, ∏ i, FooLiL3.phaseTerm s 0 (z i)) = 1 := by
  simp

-- The centered one-dimensional formula still has the factor s.
example (s : ℝ) (hs : 0 < s) :
    (∑' z : ℤ, (FooLiL3.rho s ((z : ℝ) ^ 2) : ℂ)) =
      (s : ℂ) * (FooLiL2.gaussianMass s 0 : ℂ) := by
  simpa [FooLiL3.phaseTerm_eq_rho_mul_exp] using
    FooLiL3.tsum_phaseTerm_eq_gaussianMass hs 0
