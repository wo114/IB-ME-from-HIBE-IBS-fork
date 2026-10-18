# Frozen-source symbol and game mapping (WIP)

Scope: Jia, Liu, Tang, Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, the repository's frozen `papers/2025_efficient_ibs_jia.pdf` (SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`). PDF pages 3, 4, 8, and 9 were also rendered and visually checked. This note concerns only the standalone IBS and original Table 4 rows. It changes no protocol, parameter, sampler, signature game, or HIBE component.

## The three moduli and Theorem 1

Table 3 (PDF p.6) defines gadget `(p,q)`, `Q=pq`; §5.1 (p.9) instantiates `p=2^14−1=16383`, `q=31²=961`, `Q=15744063`, `b=31`, `w=2`. Algorithm 8 (p.8) verifies over `R_(2Q)`. Theorem 1 (p.4), adapted from [26] for `FS[ellipsoid G+G,H]`, says its `q` is an **odd** modulus, uses `Z_(2q)` in the underlying identification scheme, and requires `q>max(2γ,s₁η_ε(Z^m))`. If this theorem is applied with the *same verifier modulus* as the original IBS, `2q=2Q` forces `q=Q`; this is a necessary direct mapping, with no convention choice. The literal gadget `q=961` gives `2q=1922`, not `2Q=31488126`. Taking `q=2Q` makes it even and gives the wrong `2q`.

Using exact decimal-to-rational `γ`, the first necessary inequality alone fails:

| Table 4 | `2γ` exactly | `Q` | `2γ−Q` exactly | least odd integer strictly above `2γ` |
|---|---:|---:|---:|---:|
| PARAM-I | `420864917/5` | `15744063` | `342144602/5` | `84172985` |
| PARAM-II | `127306344` | `15744063` | `111562281` | `127306345` |
| PARAM-III | `173147861` | `15744063` | `157403798` | `173147863` |

The `s₁η` gate need not be evaluated to show that this direct theorem application is unavailable. This is a *failure of the theorem's stated sufficient premise at the original rows*, not proof that every EUF attack succeeds. Changing `Q` to satisfy it would change the source scheme and is outside this reproduction.

## Formal `η` and printed `r`

The paper p.3 defines `ρ(x)=exp(−π||x||²)` and `η_ε(Λ)=min{s>0:ρ(sΛ*)≤1+ε}`. Table 3 sets `r=η_ε(Z^((2+w)(d+1)n))`; §5.1 chooses the maximum `d=4` dimension `10240`, `Q_s=2^40`, `ε=1/sqrt(Q_s·256)=2^-24`, and prints `r≈1.16`. The earlier [directed interval certificate](../2026-10-18-srgg-smoothing-eta/proof.md) brackets the formal width at `(2.9077794,2.9077796)` for dimension `10240`, while an **unstated physical-standard-deviation conversion** `η/sqrt(2π)` lies around `1.1600362`. This package recomputes directed strict theta comparisons at all Table 3 dimensions `6144,8192,10240`, with the *unmodified printed* rational `r=29/25`.

For all three dimensions, the formal density-width `θ_Z(r)^m−1` lower bound exceeds `2^-24`; thus `r=1.16` does not satisfy the explicit formal `η` definition. Under the separate hypothetical physical-SD conversion, upper bounds fall below `2^-24` at `d=2,3`, but the lower bound is above it at `d=4`. The paper's use of a common maximum-dimension width is therefore not justified by the exactly rounded `1.16` even under that conversion. This does not determine which units the authors intended, nor authorize a changed width.

## Theorem 2 premise, freshness, and one missing query case

Theorem 1 (p.4) concludes **EUF-CMA** for the FS signature under its conditions. Theorem 2 (p.8) assumes **sEUF-CMA** for SIG and states **sEUF-ID-CMA** for IBS. The former printed theorem does not itself establish the latter's stronger premise. Definition 3 (p.4) and Theorem 2's G0 (p.8) require the forged `(id*,μ*)` **not** to have been signed. An exact new `(id,μ,signature)` triple on an already signed pair is therefore excluded by those printed win conditions, although it is eligible under a native strong game. The [public Q-shift experiment](../2026-10-18-srgg-strong-game/README_zh-CN.md) gives authentic same-message replacements for five of six frozen one-signature rows; this package's symbolic trace checks only the game predicate and does not rerun or estimate that attack.

There are two further source-proof correspondence checks, both for a **fixed hypothetical valid-forgery trace**, not claims that an actual forger exists:

1. G1 (p.8) adds `id*∈X` and each explicitly extracted identity `id_i∉X`. For one extraction query on a *different* identity, no signing query (`qS=0`), and independent inclusion probability `δ=1/2`, the exact probability of G1's `X` condition is `δ(1−δ)=1/4`. The printed lower-bound factor is `δ(1−δ qS)=1/2`. The displayed `qS` cannot count the explicit extraction exclusion for this trace; `qE` would be the relevant count in this elementary fixed-trace calculation. This does not settle the full adaptive or quantum hybrid loss.
2. A signature query `(id*, μ_old)` followed by a valid forgery on fresh `μ_new` is allowed by the pair-freshness condition when there was **no explicit key-extraction query** for `id*`. If `id*∈X`, the G1 printed restrictions hold. The simulator on p.9 says it **aborts** if *any signing query* `id` has `O₂(id)=1`, so it cannot answer this allowed target-identity signing query. Its claimed equal-view statement needs an additional simulator or a different game restriction. Interpreting signing's internal key creation as an adversarial extraction would instead weaken the stated chosen-message game. A SIG signing-oracle simulation might be a possible new route, but is not given in the printed argument.

These finite counterexamples establish mismatches in the displayed premises/predicates. They do not prove that no repaired EUF reduction exists. Native strong remains separately contradicted on the actual signatures already documented, whereas the paper's fresh-message game and a repaired reduction require independent work. The one primary mapping and two alternative modulus mappings are recorded explicitly in the JSON; the game alternatives are similarly recorded, with no fourth route silently introduced.

## Reproduction and limits

`paper_source_symbol_mapping.py` computes all moduli and `γ` comparisons as integers or `Fraction`, calls the existing 512-bit directed `theta_bounds`, and evaluates finite byte-trace game predicates. `source-symbol-mapping.json` binds the reviewed PDF and the relevant source files; `verify_delivery.py` recomputes the report and checks package hashes under both normal Python and `python -O`.

There are no newly sampled Setup roots, user keys, signatures, messages, hashes, or fault histories. The symbolic query trace uses an assumed accepting verifier input and **is not** a signature forgery. No difficulty estimate, security reduction, NIST level, or HIBE compatibility is inferred. Original Table 4 rows stay research inputs: `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
