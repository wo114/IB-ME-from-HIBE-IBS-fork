import FooLiL3.Controls

/-! Public transitive dependencies and the exact principal theorem statements. -/

#print axioms FooLiL3.Controls.quarter_tail_exact
#print axioms FooLiL3.Controls.column_count_cannot_be_dropped
#print axioms FooLiL3.Controls.each_column_can_be_small
#print axioms FooLiL3.Controls.equality_at_cutoff_is_good
#print axioms FooLiL3.Controls.negative_quality_cutoff_rejects_zero
#print axioms FooLiL3.Controls.zero_columns_have_zero_mass
#print axioms FooLiL3.Controls.probability_budget_is_clipped
#print axioms FooLiL3.Controls.epsilon_one_makes_formula_invalid
#print axioms FooLiL3.Controls.raw_abort_is_not_success_conditioned
#print axioms FooLiL3.TVWithin
#print axioms FooLiL3.tvWithin_nonneg
#print axioms FooLiL3.tvWithin_refl
#print axioms FooLiL3.tvWithin_symm
#print axioms FooLiL3.tv_event_le
#print axioms FooLiL3.tv_transfer_min
#print axioms FooLiL3.finite_union_probability_le
#print axioms FooLiL3.fin_union_probability_le
#print axioms FooLiL3.probability_union_null
#print axioms FooLiL3.ideal_bad_probability_le
#print axioms FooLiL3.actual_bad_probability_le
#print axioms FooLiL3.badOutput
#print axioms FooLiL3.invalidOutput
#print axioms FooLiL3.someEvent
#print axioms FooLiL3.none_mem_badOutput
#print axioms FooLiL3.none_not_mem_someEvent
#print axioms FooLiL3.badOutput_eq_invalid_union
#print axioms FooLiL3.badOutput_subset_invalid_union
#print axioms FooLiL3.actual_badOutput_probability_le
#print axioms FooLiL3.gaussianPMF
#print axioms FooLiL3.gaussianPMF_apply
#print axioms FooLiL3.gaussianPMF_real_event
#print axioms FooLiL3.gaussianPMF_outer_event
#print axioms FooLiL3.gaussianPMF_tail_from_mass_comparison
#print axioms FooLiL3.rho
#print axioms FooLiL3.gaussianZ
#print axioms FooLiL3.tailBudget
#print axioms FooLiL3.tailBudget_nonneg
#print axioms FooLiL3.exp_three_pi_div_four_ge_four
#print axioms FooLiL3.tail_constant
#print axioms FooLiL3.rho_tail_le
#print axioms FooLiL3.gaussian_tail_mass_le
#print axioms FooLiL3.gaussian_tail_from_mass_comparison
#print axioms FooLiL3.vectorSq
#print axioms FooLiL3.InCoset
#print axioms FooLiL3.integer_rho_summable
#print axioms FooLiL3.summable_product_integer
#print axioms FooLiL3.vector_rho_eq_product
#print axioms FooLiL3.vector_rho_summable
#print axioms FooLiL3.coset_rho_summable
#print axioms FooLiL3.coset_nonempty_of_surjective
#print axioms FooLiL3.coset_gaussianZ_pos
#print axioms FooLiL3.cosetGaussian
#print axioms FooLiL3.CosetMassComparison
#print axioms FooLiL3.coset_tail_from_mass_comparison
#print axioms FooLiL3.ValidDelegation
#print axioms FooLiL3.QualityGood
#print axioms FooLiL3.columnLarge
#print axioms FooLiL3.qualityGood_iff_frobSq
#print axioms FooLiL3.all_columns_good_implies_quality
#print axioms FooLiL3.l3_from_column_tail_bounds
#print axioms FooLiL3.badOutput_quality_eq_frobSq
#print axioms FooLiL3.CosetColumnLaw
#print axioms FooLiL3.l3_from_mass_certificates_and_marginals
#print axioms FooLiL3.colSq
#print axioms FooLiL3.frobSq
#print axioms FooLiL3.colSq_nonneg
#print axioms FooLiL3.frobSq_nonneg
#print axioms FooLiL3.frobSq_le_of_columns
#print axioms FooLiL3.frobSq_eq_int_sum
#print axioms FooLiL3.colSq_eq_norm_sq
#print axioms FooLiL3.colSq_le_iff_column_norm_le
#print axioms FooLiL3.column_norm_gt_iff_colSq_gt
#print axioms FooLiL3.frobeniusVec
#print axioms FooLiL3.frobeniusNorm
#print axioms FooLiL3.frobeniusNorm_sq
#print axioms FooLiL3.frobeniusNorm_eq_sqrt
#print axioms FooLiL3.frobSq_eq_row_sum
#print axioms FooLiL3.euclideanLin
#print axioms FooLiL3.euclideanLin_apply
#print axioms FooLiL3.euclideanLin_norm_sq_le
#print axioms FooLiL3.euclideanLin_norm_le
#print axioms FooLiL3.euclideanOp
#print axioms FooLiL3.euclideanOp_apply
#print axioms FooLiL3.euclideanOp_norm_le_frobenius
#print axioms FooLiL3.euclideanOp_norm_le_frobeniusNorm
#print axioms FooLiL3.frobeniusNorm_le_sqrt_of_columns
#print axioms FooLiL3.euclideanOp_norm_sq_le_frobSq
#print axioms FooLiL3.euclideanOp_norm_le_sqrt_of_columns
#print axioms FooLiL3.euclideanOp_norm_sq_le_of_columns

#check FooLiL3.l3_from_column_tail_bounds
#check FooLiL3.l3_from_mass_certificates_and_marginals
#check FooLiL3.CosetMassComparison
#check FooLiL3.CosetColumnLaw
#check FooLiL3.gaussian_tail_from_mass_comparison
#check FooLiL3.gaussianPMF_tail_from_mass_comparison
#check FooLiL3.euclideanOp_norm_le_sqrt_of_columns
#check FooLiL3.actual_badOutput_probability_le
