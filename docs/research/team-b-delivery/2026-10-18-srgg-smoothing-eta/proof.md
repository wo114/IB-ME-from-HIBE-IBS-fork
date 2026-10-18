# Exact scope and theta inequality

The frozen source's §2.2 p.3 explicitly sets `ρ(x)=exp(-π⟨x,x⟩)` and `η_ε(Λ)=min{s>0:ρ(sΛ*)≤1+ε}`. Its §5.1 sets `r=η_ε(Z^((2+w)(d+1)n))≈1.16`; the largest original row has `n=512,w=2,d=4`, hence `m=10240`, and the visually checked source radical yields `ε=2^-24`. The formal definition fixes the exponent coefficient `πs²`. We separately audit the hypothetical conversion to physical standard deviation that would explain the printed decimal; it is not a step written in the definition.

For the paper's formal `η` definition, dual mass for `Z^m` at `s` equals

```text
Θ_m(s) = (1 + 2 sum_{k>=1} a^(k²))^m - 1,
a = exp(-πs²).
```

If one *additionally hypothesizes* `r=s/sqrt(2π)` as a physical standard deviation, replace `a` by `exp(-2π²r²)`. This is a unit conversion outside the source's formal `η` definition. The product formula uses coordinate independence of `Z^m`. Both functions strictly decrease in positive width, so one lower-end failure and one upper-end pass bracket each unique threshold.

`paper_smoothing_eta.py` evaluates `a` with Sage's 512-bit directed `RealIntervalField`, converts each binary endpoint by `exact_rational()` (never `QQ(RealNumber)`), then does rational arithmetic. With `K=4`, positive terms give

```text
t_lower = 2 sum_{k=1}^{K-1} a_lower^(k²),
t_upper = 2 [sum_{k=1}^{K-1} a_upper^(k²)
             + a_upper^(K²)/(1-a_upper^(2K+1))].
```

The tail bound follows from `(K+j)^2 >= K²+j(2K+1)`. Bernoulli's inequality gives `Θ_m>=m*t_lower`. Whenever `m*t_upper<1`, the binomial expansion bounded by a geometric series gives `Θ_m<=m*t_upper/(1-m*t_upper)`. The public 20-place decimal floors/ceilings are widened from these exact rational bounds. The verifier reruns the complete report, checks frozen file hashes and strict threshold comparisons, including that exact `1.16` fails under both branches. Tests compare a small-dimension case to an independent 1024-bit interval product and reject invalid inputs.

The **formal source eta** lies in `(2.9077794,2.9077796)`; it does not round to `1.16`. The hypothetical physical-standard-deviation conversion lies in `(1.1600361,1.1600363)`, both endpoints of which round to `1.16`. This is an internal source-unit discrepancy, not a license to change Table 4 inputs. A successful local master/sign normalizer bound in a dimension below `10240` cannot replace the source's full-dimension `η_ε` requirement. These scalar gates do not identify finite SampleF, HNF key, signature, adaptive history, hardness or strong-unforgeability laws. The exact unprinted width and its application to sampler notation remain unresolved.
