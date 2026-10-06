import FooLiL1

/-! Small, kernel-checked sanity witnesses. These are not the general proof. -/
namespace FooLiL1.Controls

open Matrix

def a : Matrix (Fin 1) (Fin 1) (ZMod 7) := fun _ _ => 1
def b : Matrix (Fin 1) (Fin 1) (ZMod 7) := fun _ _ => 2
def g : Matrix (Fin 1) (Fin 1) (ZMod 7) := fun _ _ => 1
def r : Matrix (Fin 1) (Fin 1) ℤ := fun _ _ => 1
def p : (Fin 1 ⊕ Fin 1) → ℤ := fun _ => 0
def z : Fin 1 → ℤ := fun _ => 1
def u : Fin 1 → ZMod 7 := fun _ => 1

/-- The two main premises are jointly satisfiable, not contradictory. -/
theorem valid_premises :
    (b = a * reduceMat 7 r + g) ∧
    (g *ᵥ reduceVec 7 z = u - fromCols a b *ᵥ reduceVec 7 p) := by
  decide

theorem valid_signature :
    fromCols a b *ᵥ reduceVec 7 (signature r p z) = u :=
  signature_equation a b g r p z u valid_premises.1 valid_premises.2

/-- Removing the required minus sign gives 3, rather than 1, modulo 7. -/
theorem wrong_sign_fails :
    fromCols a b * reduceMat 7 (fromRows r (1 : Matrix (Fin 1) (Fin 1) ℤ)) ≠ g := by
  decide

/-- Keeping the trapdoor but using a wrong gadget syndrome does not suffice. -/
theorem wrong_syndrome_fails :
    fromCols a b *ᵥ reduceVec 7 (signature r p (fun _ => 2)) ≠ u := by
  decide

/-- Keeping the syndrome for p=0 but violating B=AR+G does not suffice. -/
theorem wrong_key_fails :
    fromCols a (fun _ _ => 3) *ᵥ reduceVec 7 (signature r p z) ≠ u := by
  decide

end FooLiL1.Controls
