import FooLiL3.GaussianLaw
import Mathlib.NumberTheory.ModularForms.JacobiTheta.TwoVariable
import Mathlib.Analysis.Normed.Ring.InfiniteSum
import Mathlib.Algebra.Order.BigOperators.GroupWithZero.Finset
import Mathlib.Data.Fin.Tuple.Basic
import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Data.Matrix.Mul
import Mathlib.Data.ZMod.Basic

/-!
Exact integer-vector and modular-coset distributions. Summability is proved,
not assumed, using the same Jacobi-theta/product argument as L2.
This lower-level tail theorem uses a mass certificate. SmoothingBridge derives
that certificate from C2; ClosedL3 exports the resulting ledger-facing theorem.
-/

noncomputable section
set_option maxHeartbeats 1000000
open scoped BigOperators
namespace FooLiL3

def vectorSq {m : ℕ} (x : Fin m → ℤ) : ℝ := ∑ i, (x i : ℝ) ^ 2

def InCoset {n m : ℕ} (q : ℕ) (A : Matrix (Fin n) (Fin m) (ZMod q))
    (u : Fin n → ZMod q) (x : Fin m → ℤ) : Prop :=
  A.mulVec (fun i => (x i : ZMod q)) = u

theorem integer_rho_summable {s : ℝ} (hs : 0 < s) :
    Summable (fun z : ℤ => rho s ((z : ℝ) ^ 2)) := by
  have ha : 0 < (s ^ 2)⁻¹ := inv_pos.mpr (sq_pos_of_pos hs)
  let a : ℝ := (s ^ 2)⁻¹
  have h := ((summable_jacobiTheta₂_term_iff 0 ((a : ℂ) * Complex.I)).mpr
    (by simpa only [Complex.mul_I_im, Complex.ofReal_re] using ha)).norm
  convert h using 1
  ext z
  rw [norm_jacobiTheta₂_term]
  simp only [Complex.mul_I_im, Complex.ofReal_re, Complex.zero_im]
  unfold rho a
  congr 1
  ring

theorem summable_product_integer (m : ℕ) (f : Fin m → ℤ → ℝ)
    (hf : ∀ i, Summable (f i)) (hn : ∀ i z, 0 ≤ f i z) :
    Summable (fun z : Fin m → ℤ => ∏ i, f i (z i)) := by
  induction m with
  | zero => exact Summable.of_finite
  | succ m ih =>
    have ht := ih (fun i => f i.succ) (fun i => hf i.succ) (fun i => hn i.succ)
    have hm := (hf 0).mul_of_nonneg ht (hn 0)
      (fun z => Finset.prod_nonneg (fun i _ => hn i.succ (z i)))
    apply (Fin.consEquiv (fun _ : Fin (m + 1) => ℤ)).summable_iff.mp
    simpa [Function.comp_def, Fin.prod_univ_succ, Fin.consEquiv_apply] using hm

theorem vector_rho_eq_product {m : ℕ} (s : ℝ) (x : Fin m → ℤ) :
    rho s (vectorSq x) = ∏ i, rho s ((x i : ℝ) ^ 2) := by
  unfold rho vectorSq
  rw [Finset.mul_sum, Finset.sum_div, Real.exp_sum]

theorem vector_rho_summable (m : ℕ) {s : ℝ} (hs : 0 < s) :
    Summable (fun x : Fin m → ℤ => rho s (vectorSq x)) := by
  have h := summable_product_integer m (fun _ z => rho s ((z : ℝ) ^ 2))
    (fun _ => integer_rho_summable hs) (fun _ _ => (Real.exp_pos _).le)
  exact h.congr (fun x => (vector_rho_eq_product s x).symm)

theorem coset_rho_summable {n m : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q)
    {s : ℝ} (hs : 0 < s) :
    Summable (fun x : {x // InCoset q A u x} => rho s (vectorSq x.val)) :=
  (vector_rho_summable m hs).subtype _

theorem coset_nonempty_of_surjective {n m : ℕ} (q : ℕ) [NeZero q]
    (A : Matrix (Fin n) (Fin m) (ZMod q))
    (hA : Function.Surjective A.mulVec) (u : Fin n → ZMod q) :
    Nonempty {x // InCoset q A u x} := by
  obtain ⟨z, hz⟩ := hA u
  refine ⟨⟨fun i => (z i).val, ?_⟩⟩
  simpa [InCoset] using hz

theorem coset_gaussianZ_pos {n m : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q)
    (hx : Nonempty {x // InCoset q A u x}) {s : ℝ} (hs : 0 < s) :
    0 < gaussianZ (fun x : {x // InCoset q A u x} => vectorSq x.val) s := by
  obtain ⟨x⟩ := hx
  exact (Real.exp_pos _).trans_le ((coset_rho_summable q A u hs).le_tsum x
    (fun _ _ => (Real.exp_pos _).le))

/-- This is the untruncated discrete Gaussian on the actual modular coset. -/
def cosetGaussian {n m : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q)
    (hx : Nonempty {x // InCoset q A u x}) (s : ℝ) (hs : 0 < s) :
    PMF {x // InCoset q A u x} :=
  gaussianPMF (fun x => vectorSq x.val) s
    (coset_rho_summable q A u hs) (coset_gaussianZ_pos q A u hx hs)

/-- Exact mass certificate, derived from C2 in SmoothingBridge rather than
identified definitionally with C2 or with the L2 transfer theorem. -/
def CosetMassComparison {n m : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q) (s e : ℝ) : Prop :=
  gaussianZ (fun x : {x // InCoset q A u x} => vectorSq x.val) (2 * s) ≤
    (2 : ℝ) ^ m * ((1 + e) / (1 - e)) *
      gaussianZ (fun x : {x // InCoset q A u x} => vectorSq x.val) s

theorem coset_tail_from_mass_comparison {n m : ℕ} (q : ℕ)
    (A : Matrix (Fin n) (Fin m) (ZMod q)) (u : Fin n → ZMod q)
    (hx : Nonempty {x // InCoset q A u x}) {s e : ℝ}
    (hs : 0 < s) (he : 0 ≤ e) (he1 : e < 1)
    (hMass : CosetMassComparison q A u s e) :
    (∑' x : {x : {x // InCoset q A u x} // (m : ℝ) * s ^ 2 ≤ vectorSq x.val},
        rho s (vectorSq x.val.val)) /
      gaussianZ (fun x : {x // InCoset q A u x} => vectorSq x.val) s ≤ tailBudget m e := by
  exact gaussian_tail_from_mass_comparison
    (fun x : {x : Fin m → ℤ // InCoset q A u x} => vectorSq x.val) m hs he he1
    (coset_rho_summable q A u hs) (coset_rho_summable q A u (by positivity))
    (coset_gaussianZ_pos q A u hx hs) hMass

end FooLiL3
