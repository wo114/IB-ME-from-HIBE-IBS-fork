> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# Random issued key to signing law: exact obstruction and conditional bridge

Primary source: Huiwen Jia, Ying Liu, Chunming Tang and Lin Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI 10.1049/ise2/6684889, frozen `papers/2025_efficient_ibs_jia.pdf`, SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`. Source anchors are Algorithms 2 and 7, Table 3 and Table 4. The ring/Fourier and HNF statements below are derived from the frozen implementation and [earlier issuance proof](../2026-10-18-srgg-paper-law/issuance-law.md); they are **not new claims by the paper**. No algorithm or original parameter was changed.

## 1. The exact support obstruction

Fix one of the six original Table 4 rows and one of its authenticated accepted Setup roots. Let `d` be the rank, `n=512`, `w=2`, `Q=15744063`, `A=[I_d | A_tail]`, and `h` a canonical identity target. The predecessor's mathematical issuance reference is the centered-HNF image of `U ~ D_(Z^N,Sigma,0) | S_h`, where

`S_h = {u in Z^N : h-Au mod Q has a centered representative e in E_c}`.

For **any** integer tail `t`, choose an integer head congruent to `h-A_tail t` modulo `Q`. Then `e=0` is in `E_c`, so `(head,t) in S_h`. The positive-definite joint discrete Gaussian gives every such integer point positive mass. The centered-HNF map preserves the tail exactly; hence every integer tail has positive mass in the mathematical key-vector reference. The synthetic tails below are also within the 256-bit coordinate guard and pass the current canonical key codec. This does **not** show that the finite source sampler emits them, nor estimate their probability.

For the unchanged factor-one Algorithm 7 signature geometry, let `v` be the reconstructed full user key and let `s1²`, `s2²`, `r²` be the exact implementation shape parameters for that row. In each negacyclic Fourier component, conditioning out the final scalar lower block gives the upper Schur matrix

`M = D - beta v v*`, where `D=diag(s1² (2d times), s2² (wd times))` and `beta = r² s2²/(s2²-r²)`.

Choose the first gadget tail row `j=2d` of the **full** key; it is row `d` of the stored tail. Put a constant polynomial `T` there and zero in every other tail row. The HNF-reconstructed head may take any values. Every Fourier embedding of that constant polynomial is `T`, so

`M[j,j] = s2² - beta T²`.

The program computes the smallest positive integer `T` with `beta T²>s2²` using exact rational arithmetic, not a floating approximation. The six-row results are:

| Original profile | Table standard deviation | Literal density width |
|---|---:|---:|
| PARAM-I | 268010 | 268010 |
| PARAM-II | 331565 | 331565 |
| PARAM-III | 386948 | 386948 |

The two interpretations share the threshold because they multiply both `s2²` and `r²` by the same density scale. For each row, `T-1` leaves this particular diagonal nonnegative and `T` makes it strictly negative. A Hermitian positive-semidefinite matrix cannot have a negative diagonal, so the signature Schur geometry is nonpositive for this canonical key, irrespective of the reconstructed head. Six actual fixed-root replays confirm that the unchanged `SourceSchurBackend._sign_plan` raises `WitnessGeometryError`; they do not sample the synthetic key from issuance. No private witness, key bytes or signature is exported.

This disproves a **uniform over every mathematical-reference key** signature-Schur certificate. It does not imply a material failure probability: each witness could have extremely small mass. It also does not by itself establish a native-strong forgery or a security level.

## 2. What a random-key coupling would require

Let `P_K` be the actual first-issuance key-plus-abort law and `Q_K` the predecessor mathematical key-plus-abort law on this fixed root and target. Suppose `TV(P_K,Q_K) <= delta_issue`. Let `G` be a set of issued keys on which each **matching-history** sign-call kernel, including all 64 norm retries, object guards and abort, differs from its declared mathematical sign reference by at most `epsilon_good`, uniformly over every valid adaptive message. Let `Q_K(G^c) <= beta_bad` (a shared abort may be included in `G`). For at most `s` sign calls after this one issuance, maximal-couple issuance, charge a mismatched key once, charge entry into `G^c` once, and couple each sign call while histories match. The full logical-transcript TV is then at most

`min(1, delta_issue + beta_bad + s epsilon_good)`.

This is a conditional *lemma*, not a current SRGG numeric result. The three standard-deviation rows have a nontrivial `delta_issue` in the authenticated predecessor; the three literal-density rows have `delta_issue=null`. All six rows still have `beta_bad=null` and `epsilon_good=null` for randomly issued keys. The previous `epsilon` covers exactly one frozen Alice key. Substituting it for a uniform good-key bound would be invalid. For multiple fresh identities, each first-touch key needs its own conditional bad-mass premise; a cached key should pay bad mass only once.

## 3. Bounded route ledger and remaining premise

1. **Main route, all-reference-key uniform certificate:** disproved constructively above for all six rows. A valid key object and ideal-reference positive mass coexist with a nonpositive sign geometry.
2. **First alternative, deterministic finite-output support envelope:** the authenticated source-issuance receipt only gives a maximum successful coordinate of roughly `1.7e10–9.4e10`, far above the `T=268010–386948` obstruction. That upper envelope neither excludes the obstruction nor proves that finite issuance reaches it. The object guard is not a signing-key norm guard.
3. **Second alternative, Gaussian bad-key concentration:** for any bad event `B_h` on the HNF output, the reference probability is exactly `P_D(B_h ∩ S_h)/P_D(S_h)`. An unconditional Gaussian tail estimate would need a quantitative, target-uniform lower bound for `P_D(S_h)`, plus a numerator bound that accounts for HNF head wrapping and **all** Fourier directions. No such bound is present in the predecessor certificates. Replacing the denominator with one, or using a single observed key, would be unsound. This route therefore stops with `beta_bad=null`.

The accepted-Setup-root distribution, external storage faults, native strong game and structural hardness remain separate. All statements above concern fixed roots, original Table 4 research parameters, the current exact-rational interpretation and a fault-free logical schedule. ROM is used for the identity target. Functional replays do not prove IBS security, and no NIST category is claimed.
