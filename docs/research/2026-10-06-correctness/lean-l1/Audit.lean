import FooLiL1.Controls

-- Statements are printed so that type checking is not confused with
-- having formalized the intended mathematical claim.
#check @FooLiL1.l1
#check @FooLiL1.flattened_signature_equation
#check @FooLiL1.master_trapdoor_equation
#check @FooLiL1.mp12_sign_iff
#check @FooLiL1.tagged_signature_equation

-- Every locally authored theorem is included, not only the main result.
#print axioms FooLiL1.reduceVec_add
#print axioms FooLiL1.reduceVec_mulVec
#print axioms FooLiL1.reduceMat_trapdoorLift
#print axioms FooLiL1.trapdoor_equation
#print axioms FooLiL1.reduceVec_signature
#print axioms FooLiL1.signature_equation
#print axioms FooLiL1.l1
#print axioms FooLiL1.reduceMat_neg
#print axioms FooLiL1.mp12_sign_iff
#print axioms FooLiL1.master_trapdoor_equation
#print axioms FooLiL1.flatten_mulVec
#print axioms FooLiL1.flattened_signature_equation
#print axioms FooLiL1.tagged_signature_equation
#print axioms FooLiL1.Controls.valid_premises
#print axioms FooLiL1.Controls.valid_signature
#print axioms FooLiL1.Controls.wrong_sign_fails
#print axioms FooLiL1.Controls.wrong_syndrome_fails
#print axioms FooLiL1.Controls.wrong_key_fails
