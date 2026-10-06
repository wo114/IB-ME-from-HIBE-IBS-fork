import FooLiL1.Controls

/- Expected to fail compilation. Excluded from the default library build.
   This asserts the opposite of the proved wrong_sign_fails control. -/
open Matrix FooLiL1 FooLiL1.Controls

example :
    fromCols a b * reduceMat 7 (fromRows r (1 : Matrix (Fin 1) (Fin 1) ℤ)) = g := by
  decide
