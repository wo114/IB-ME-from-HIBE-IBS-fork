> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# Fixed-root finite source-Schur comparison

This note describes the scope of `paper_schur_finite_chain.py`. The comparator is the mathematical control flow of the paper's Algorithms 3–4: an exact lower-block discrete Gaussian, descending exact ring-Schur stages, an exact continuous Gaussian at each stage, and an exact coefficientwise (D_{\mathbb Z,r^2,c}) rounding kernel. Abort is an extra output symbol. The parameters are the two **explicit rational interpretations in this repository** of the paper's rounded Table 4 numbers; this is not a claim that the authors used either interpretation internally.

The theorem is **conditional on a particular successfully prepared root and its fixed issued key**. `SchurNumericalAudit` independently rebuilds its ideal Schur pivots from the witness and checks every eigenvalue against 64, stored factor-square error against (2^{-128}), and same-successful-history center error against (2^{-96}). The finite-chain certificate replays that audit to bind mutable plans, checks its operational profile, integer witness, dyadic gains, factor range, rational-center denominator and all-path magnitude envelopes, and rejects a missing condition.

For each 512-bit midpoint Box–Muller ticket, couple an independent continuous uniform variable to the midpoint of its containing cell. Put (h=2^{-512}) and (	au=2^{-170}). In one pair, the event (U<\tau) has probability (	au). Otherwise the midpoint is at least (	au/2), and the radius difference is at most (sqrt{2h/\tau}<2^{-170}); the angle contribution is below (2^{-506}). Each exact midpoint normal coordinate differs from the continuous normal by less than (2^{-168}). We never compare their continuous laws in TV: a finite ticket law and a continuous law are mutually singular. Under correctly rounded, exception-free 768-bit MPFR real primitives, the computed midpoint normal differs from its exact value by less than (2^{-490}). This holds for all tickets, including extreme endpoints.

The finite radix-two forward/factor/inverse Fourier code has fewer than (2^{20}) relevant rounded operations. With normal coordinate magnitude below 32 and checked stored factor below (2^{32}), every intermediate stays below (2^{64}). A real/complex operation contributes less than (2^{132}2^{-768}) absolute local error; twiddle recurrence error is covered by the same envelope, and later operations amplify a local error by less than (2^{128}). Thus a final shift coefficient differs from ideal exact-trigonometric application of the *stored* factor by less than (2^{-400}). The MPFR premise concerns each constituent real operation, not a claim that a complex multiply is one correctly rounded primitive. Factor-square and pivot gates then bound the stored-to-ideal factor difference by (2^{-128}) per frequency.

Let (n\le512). On the good-ticket event, the resulting continuous shift difference from the ideal Schur shift is at most

\[
\delta_s=n2^{32}(2^{-168}+2^{-490})+2^{-400},\qquad
\delta_i=\delta_s+32n2^{-128}.
\]

Adding the independently audited adaptive-center discrepancy gives at most (2^{-96}+\delta_i) for each scalar rounding center while the two chains have the same successful integer history. For (1\le r^2\le16), the exact scalar (D_{\mathbb Z,r^2,c}) kernel is 4096-Lipschitz in TV with respect to (c): its normalizer exceeds (1/3), while the unnormalized first absolute moment is at most 128 by an annular geometric bound. Sequential maximal coupling and a union bound carry this to all leaves. The finite scalar kernel and aggregate-byte-cap TV terms are taken from the existing exact `batch_certificate` at the same admitted rational centers.

The 8192-bit rational-input gate is a separate abort event. For these checked integer witnesses, the initial exact center denominator divides the public noise/lower-width ratio; every later center is freshly rounded to the active dyadic grid. A nonzero 768-bit shift of magnitude at least (2^{-6000}) therefore yields a center rational within the bit budget. A gate failure requires a smaller shift. The checked stored factor exceeds 2, so each coordinate of the corresponding continuous Gaussian has variance above 4 and density below (1/4). Anti-concentration and the same coupling bound the bit-gate event by (2n(2^{-6000}+\delta_s)) per leaf. The normal-ticket, noise, scalar-magnitude and final-object guards are deterministic zero-abort events under the verified envelopes. External runtime faults are outside this mathematical byte-stream model.

With (L) upper leaves and the two existing batch terms (\epsilon_{\mathrm{low}},\epsilon_{\mathrm{round}}), the finite integer-output comparison including abort is

\[
\epsilon_{\mathrm{finite}}
\le \epsilon_{\mathrm{low}}+\epsilon_{\mathrm{round}}
 + L(n/2)2^{-170}
 + 2Ln(2^{-6000}+\delta_s)
 + 4096Ln(2^{-96}+\delta_i).
\]

This statement assumes independent uniform bytes. A deterministic fixture establishes repeatability of the audit, not that premise. It gives neither an accepted-Setup-root probability bound nor a whole-service/history law. It also does not by itself compare the mathematical Algorithm 4 leaf to an ideal discrete Gaussian or establish HNF, native strong security, hardness, or a NIST category.

For the additional **mathematical** convolution comparison, write (A=f-r^2 I\succ0). The unnormalized identity

\[
\int_{\mathbb R^n}\rho_A(y)\rho_{r^2 I}(k-c-y)\,dy
 = C\rho_f(k-c)
\]

holds for a (k)-independent constant (C). If the all-center rounding normalizer obeys (Z_{r^2I}(z)/r^n\in[1-\epsilon,1+\epsilon]) with (\epsilon<1), the actual continuous-then-normalized-discrete leaf is a bounded tilt of (D_{\mathbb Z^n,f,c}), with TV at most (\epsilon/(1-\epsilon)). This bridge must be established *before* adding the separate ideal sequential-Schur-vs-joint normalizer bound. An inconclusive (\epsilon) leaves that joint comparison null; it cannot be replaced by the prior joint-sampler certificate.

For the paper's **literal-density** reading, the 512-coordinate all-center relative bound above is inconclusive. The first bounded alternative uses the scalar Poisson tail

\[
t(s)=\frac{2e^{-\pi s}}{1-e^{-3\pi s}},\qquad
(1-t(r^2))^n\le Z_{r^2 I}(z)/r^n\le(1+t(r^2))^n.
\]

The resulting likelihood-ratio bound for one exact Algorithm 4 leaf is
(1-((1-t)/(1+t))^n), where (t=t(r^2)). At literal (r^2=841/625,n=512), this is very close to one; the adaptive chain upper bound is exactly the trivial value one for all original Table 4 leaf counts. This is a failure of that sufficient bound, not evidence that the underlying laws have TV one.

The second and final alternative uses the *continuous Gaussian law actually sampled by Algorithm 4* instead of a worst-case value of its normalizer. For a fixed audited pivot (F\succeq64I), put (R=r^2I), (C=F-R\succeq\lambda I), (\lambda=64-r^2), (Y\sim D_{\mathbb R^n,C}) and (W(Y)=Z_R(c+Y)/r^n). Poisson summation gives

\[
W(y)=\sum_{k\in\mathbb Z^n} e^{-\pi r^2\lVert k\rVert^2}
  e^{2\pi i k\cdot(c+y)}.
\]

The Fourier transform of (Y) and the pivot floor imply

\[
|\mathbb E W-1|\le\delta=(1+t(64))^n-1,
\]

and, splitting the second moment into (k+\ell=0) and (k+\ell\ne0),

\[
\mathbb E(W-1)^2\le M=(1+t(2r^2))^n-1
 +e^{-\pi\lambda}\big((1+t(r^2))^n-1\big)^2.
\]

The exact continuous-plus-discrete joint law and the unnormalized Gaussian-convolution joint law differ only by the tilt (W/\mathbb E W). Marginalizing to integer output cannot increase TV. Cauchy–Schwarz therefore gives a uniform one-leaf bound

\[
\epsilon_{\rm leaf}\le \frac{\sqrt M}{2(1-\delta)}.
\]

Because this bound is independent of the adaptive center, sequential maximal coupling bounds an (L)-leaf chain by (1-(1-\epsilon_{\rm leaf})^L). The numerical certificate computes (t), (\delta), and (M) with outward Sage interval endpoints and rounds the final upper bounds upward to exact dyadic rationals. It is conditional on the audited fixed-root pivot floor for every leaf. It does not establish any distribution over accepted Setup roots or a full IBS history law. Even where nontrivial, the bound is far too large for formal security admission.
