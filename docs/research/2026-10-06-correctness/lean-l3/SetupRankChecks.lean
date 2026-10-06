import FooLiL3.SetupRank

open FooLiL3 Matrix

-- Composite modulus: no field/primality hypothesis is hidden in the gadget proof.
example : Function.Surjective
    ((powersGadget 2 2 (2 : ZMod 6)).submatrix id finProdFinEquiv.symm).mulVec :=
  powersGadget_flat_surjective 2 2 2

-- A single entry [1] per block is already sufficient, including base zero.
example : Function.Surjective (powersGadget 2 0 (0 : ZMod 6)).mulVec :=
  powersGadget_surjective 2 0 0

-- The empty-row corner case is also included.
example : Function.Surjective (powersGadget 0 0 (2 : ZMod 7)).mulVec :=
  powersGadget_surjective 0 0 2

-- Full concrete Setup over Z/6Z: H=I, arbitrary Abar and trapdoor R.
example (Abar : Matrix (Fin 2) (Fin 3) (ZMod 6))
    (R : Matrix (Fin 3) (Fin (2 * (2 + 1))) (ZMod 6)) :
    Function.Surjective
      ((fromCols Abar
        ((powersGadget 2 2 (2 : ZMod 6)).submatrix id finProdFinEquiv.symm - Abar * R)).submatrix
          id finSumFinEquiv.symm).mulVec := by
  simpa only [Matrix.one_mul] using
    standard_master_setup_surjective Abar R 1 1 2 (Matrix.one_mul 1)

-- The master relation alone cannot give surjectivity for an invalid zero gadget.
example : ¬ Function.Surjective (0 : Matrix (Fin 1) (Fin 1) (ZMod 7)).mulVec := by
  intro h
  obtain ⟨v, hv⟩ := h (fun _ => 1)
  have h01 : (0 : ZMod 7) = 1 := by simpa using congrFun hv 0
  exact (by decide : (0 : ZMod 7) ≠ 1) h01

#print axioms FooLiL3.mulVec_surjective_of_rightInverse
#print axioms FooLiL3.rightInverse_of_trapdoor
#print axioms FooLiL3.mulVec_surjective_of_trapdoor
#print axioms FooLiL3.mulVec_surjective_of_trapdoor_unit_tag
#print axioms FooLiL3.columnSelector
#print axioms FooLiL3.mul_columnSelector
#print axioms FooLiL3.rightInverse_of_identity_columns
#print axioms FooLiL3.mulVec_surjective_of_identity_columns
#print axioms FooLiL3.blockGadget
#print axioms FooLiL3.blockGadget_identity_columns
#print axioms FooLiL3.blockGadget_rightInverse
#print axioms FooLiL3.blockGadget_surjective
#print axioms FooLiL3.powersGadget
#print axioms FooLiL3.powersGadget_rightInverse
#print axioms FooLiL3.powersGadget_surjective
#print axioms FooLiL3.master_relation_surjective_of_identity_columns
#print axioms FooLiL3.master_setup_trapdoor_equation
#print axioms FooLiL3.master_setup_surjective
#print axioms FooLiL3.mulVec_surjective_reindex_columns
#print axioms FooLiL3.master_relation_flat_surjective_of_identity_columns
#print axioms FooLiL3.master_setup_flat_surjective
#print axioms FooLiL3.powersGadget_flat_surjective
#print axioms FooLiL3.powersGadget_flat_identity_columns
#print axioms FooLiL3.standard_master_relation_surjective
#print axioms FooLiL3.standard_master_setup_surjective
#print axioms FooLiL3.fullRowRank_liftMatrix_iff
#print axioms FooLiL3.fullRowRank_liftMatrix_of_trapdoor
#print axioms FooLiL3.coset_nonempty_of_trapdoor
#print axioms FooLiL3.inCoset_liftMatrix_iff
#print axioms FooLiL3.inKernel_liftMatrix_iff
#print axioms FooLiL3.inCoset_iff_sub_inKernel

#check @FooLiL2.Cosets.mod_liftMatrix
#check @FooLiL2.Cosets.mod_liftVector
#check @FooLiL3.master_relation_flat_surjective_of_identity_columns
#check @FooLiL3.fullRowRank_liftMatrix_iff
