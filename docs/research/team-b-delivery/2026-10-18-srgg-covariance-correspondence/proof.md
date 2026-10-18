# Table 3 / Algorithm 7 Gaussian correspondence

Source: frozen Jia–Liu–Tang–Wang PDF `papers/2025_efficient_ibs_jia.pdf`, SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`. The Gaussian density is defined in §2.2 (PDF p.3); Table 3 (p.6) prints `ζ=1+X^(n/2)`, `ζζ*=2`, and `Σ̄_p=Σ̄−r²[y;1][yᵗ,1]`; Algorithm 7 (p.8) prints `u←D_(R,r,−c/ζ)` and `z=p+[y;1](ζu+c)`. We checked the actual rendered pages, as the text extraction loses superscripts and bars. These are source statements, not newly admitted conditions.

## Exact ring and finite-lattice statements

Put `n=2h` and use coefficient vectors in `R=Z[X]/(X^n+1)`. Multiplication by `X^h` is the signed block swap `J(a,b)=(-b,a)`, so `J²=−I` and `Jᵗ=−J`. The multiplication matrix `Z=I+J` of `ζ` satisfies

```
Zᵗ=I−J=M(ζ*),     ZᵗZ=ZZᵗ=2I,     Z⁻¹=Zᵗ/2.
```

For any integral challenge `c` and `u∈R`, Algorithm 7's center and shift obey

```
center = −c/ζ = −Zᵗc/2,
t = ζu+c = Z(u−center),
||t||² = 2 ||u−center||².
```

Thus, **for the exact discrete Gaussian stated in Algorithm 7**, if its scalar density shape is `s=r²`, the pushforward `t` has weights proportional to `exp(−π||t||²/(2s))` on `c+ζR`: it is `D_(c+ζR,2s,0)`. This is a density-shape identity, not an assertion that the finite implementation or the final signature has ideal Gaussian law. The mathematical physical-SD conversion `s=2πr_physical²` motivates the repository's explicit `table-standard-deviation` interpretation; its code uses a rational enclosure midpoint for `2π`. Either common scale changes both sides together, so the ratio remains two. A discrete Gaussian's actual covariance is generally not exactly `s/(2π)I`.

The paired coefficient formula is `Z(a,b)=(a−b,a+b)`. Consequently,

```
ζR = { t∈Z^n : t_i ≡ t_(i+h) (mod 2) for every 0≤i<h }.
```

Its index is `2^h`, or `2^256` at the original `n=512`. For `t∈c+ζR`, the parity relation is `t_i−c_i ≡ t_(i+h)−c_(i+h) (mod 2)`. The inverse, when this holds, is `u_i=(t_i−c_i+t_(i+h)−c_(i+h))/2` and `u_(i+h)=(t_(i+h)−c_(i+h)−t_i+c_i)/2`.

The formulas here use the coefficient Euclidean norm implemented by the repository. For this power-of-two cyclotomic ring, using an unnormalised canonical-embedding norm multiplies the entire coefficient quadratic form by one common positive factor; it does not change `ZᵗZ=2I`, the coset index, or the relative shape factor two. The scalar `s` in the following parity sums would be rescaled by that common factor.

The exact normalizer is challenge-coset dependent. With `E(s)=Σ_(j even) exp(−πj²/(2s))` and `O(s)=Σ_(j odd) exp(−πj²/(2s))`, a paired challenge with equal bit parity contributes `A=E²+O²`; unequal parity contributes `B=2EO`. If `k` of the `h` challenge pairs have unequal parity, then

```
Z_(c+ζR,2s)(0) = A^(h−k) B^k,
A−B = (E−O)² > 0.
```

The strict inequality follows from Poisson summation:

```
E−O = Σ_(j∈Z) (−1)^j exp(−πj²/(2s))
    = sqrt(2s) Σ_(m∈Z) exp(−2πs(m+1/2)²) > 0.
```

For example, `c=0` has `k=0`, while binary `c=e_0` has `k=1`. This establishes an exact finite-lattice distinction for either positive width convention, though it does **not** quantify its effect on the complete Fiat–Shamir signature distribution. Our tests independently evaluate positive interval margins for both original width readings.

## Conditional continuous-convolution check

Let `L=[y;1]` denote the linear map from the ring challenge shift into the response vector. Under the usual *hypothetical independent continuous Gaussian* convolution used to motivate Table 3, Algorithm 7 contributes density shape `2sLLᵗ`. The Table 3 perturbation has shape `P=Σ̄−sLLᵗ`. Hence

```
P + 2sLLᵗ = Σ̄ + sLLᵗ ≠ Σ̄.
```

The bottom `n×n` block of this excess is `sI_n` because the last entry of `[y;1]` is one, so no choice of user key `y` removes it. In physical-covariance notation all shape matrices are divided by `2π`, again preserving the relative factor two. This calculation is **conditional on independent continuous variables**. It must not be quoted as the actual covariance of discrete `p`, `u`, or `z`, especially because `c=H̄(w,μ)` depends on the commitment to `p`. The exact finite pushforward statement above needs no such independence assumption.

For this continuous accounting alone, replacing Table 3's subtraction by `2sLLᵗ`, or Algorithm 7's scalar input shape by `s/2`, would cancel the term. Neither replacement is printed in the frozen paper, and neither is made to the implementation. Even either replacement alone would still require finite-lattice normalizer, sampling-error, security-game and parameter proofs.

## Bounded route ledger and conclusion

1. **Original-source continuous route:** apply the printed Table 3 and Algorithm 7 formulas. Exact `ZᵗZ=2I` leaves `+sLLᵗ`; it fails to derive the advertised `Σ̄` through ordinary convolution.
2. **First alternative, notation conversion:** regard Table 3 widths as physical standard deviations and multiply every density shape by `2π`. The same relative factor two and nonzero excess remain. The paper's separate smoothing-`η` unit discrepancy is not repaired here.
3. **Second alternative, exact discrete ring:** avoid continuous covariance entirely. The pushforward is a Gaussian on `c+ζR` with shape `2s`, index `2^256`, and a challenge-dependent normalizer. This gives a sharper source-correspondence obstruction, not a repaired target law.

The maximum two route switches is exhausted for this correspondence question. A different theorem, an author correction, or an explicitly revised algorithm would be required to claim the printed target law; no such resolution is in this package. The source's `Σ̄_p` positivity, norm retries, accepted Setup-root distribution, finite sampler TV and full signature/history law are separate obligations. This is **not** a proof of insecurity or a replacement for security reduction. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
