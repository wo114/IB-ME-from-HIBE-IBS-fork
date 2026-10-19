# Mathematical Setup positive-definiteness bound

This note treats the paper's Algorithm 1 retry predicate on a *raw* Table 4
CBD1 witness. It is independent of HIBE and does not analyze finite Fourier
preparation, a successful implementation root, or the IBS security game.
The frozen primary source is `papers/2025_efficient_ibs_jia.pdf` (SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`).

Let (R) be the paper's ((2d)\times(wd)) negacyclic matrix with (n=512,w=2)
and independent CBD1 coefficients (\chi=B_1-B_2). Algebraic Schur
complement of the paper's Gaussian shape matrix gives the strict gate

\[
\Sigma_p-r^2I\succ0\quad\Longleftrightarrow\quad
\|M(R)\|_2^2<T,
\qquad
T=\frac{(s_1^2-r^2)(s_2^2-r^2-b^2r^2)}
        {b^2r^2(s_2^2-r^2)}.
\]

The implementation recomputes (T) from the two explicit Gaussian
interpretations and requires exact equality. All squared widths acquire the
same positive scale under the standard-deviation reading, which cancels in
(T). The source gives rounded widths, so this binds the two explicit current
interpretations; it does not discover unpublished author precision.

The unitary negacyclic Fourier transform diagonalizes (M(R)) into 512 complex
matrices of shape ((2d)\times(wd)). Its eigenvalue is the polynomial
evaluation (\sum_h\chi_h\zeta^h), with **no extra (1/\sqrt n) divisor**.
Real coefficients pair conjugate frequencies, leaving 256 distinct blocks.
If every block has operator norm squared below (T), the strict gate holds.

For one Fourier entry (Z=\sum_h\chi_h\zeta^h), a signed cyclic shift of the
iid symmetric CBD1 coefficients multiplies (Z) by the primitive 1024th root
(\zeta). Thus mixed moments of total degree less than 512 vanish unless
their powers balance. The scalar moment generating function obeys

\[
\mathbb E e^{t\chi}=(1+\cosh t)/2
\preceq_{\mathrm{coeff}} e^{t^2/4},
\]

because (2(2m)!\ge4^m m!) for every (m\ge1). Multiplying the coefficientwise
inequalities for the independent coefficients and using
(\sum_h\cos^2(h\arg\zeta)=n/2) bounds real-projection moments by those of
a Gaussian of variance (n/4). Rotational invariance then gives

\[
\mathbb E|Z|^{2m}\le m!(n/2)^m\qquad(m<512).
\]

Independent entries and balanced mixed moments dominate every term in
(\mathbb E\operatorname{Tr}((R_jR_j^*)^k)) by the corresponding complex
Wishart term with entry second moment (v=n/2=256). For rows (a), columns
(b) and integer (k), the exact hook-character identity used by the certificate
is

\[
M_k=\frac{v^k}{k!}\sum_{h=0}^{\min(a,b,k)-1}
 (-1)^h\binom{k-1}{h}H_a(k,h)H_b(k,h),
\]

where
(H_x(k,h)=\prod_{j=0}^{k-h-1}(x+j)\prod_{j=1}^{h}(x-j)). The code sums
signed integer terms before exact division by (k!); small (k) values are
checked independently by the permutation formula. Markov and a union over
256 conjugate-paired blocks give the one-attempt rejection bound

\[
q_{\rm true}:=\Pr[\Sigma_p-r^2I\not\succ0]
 \le q_{\rm bound}=256M_k/T^k.
\]

For ranks (d=2,3,4), the selected orders (k=17,22,28) give respectively
(q_{\rm bound}<0.205519,0.095133,0.046674). Under independent identical
CBD1 retries, the mathematical predicate still fails after 64 tries with
probability at most (q_{\rm bound}^{64}), respectively strictly below
(2^{-146},2^{-217},2^{-282}). These are *upper bounds*, not measurements of
the exact acceptance probability.

Let (\mu) be the raw witness law and (A) the strict mathematical positivity
event. Ideal unbounded Algorithm 1 outputs (\mu_A=\mu(\cdot\mid A)), and
(\operatorname{TV}(\mu_A,\mu)=q_{\rm true}\le q_{\rm bound}). With 64 retries
and a distinct abort atom, its output law is
((1-q_{\rm true}^{64})\mu_A+q_{\rm true}^{64}\delta_{\rm abort}). The current
backend also prepares intervals, series and other finite objects. If their
success set is (B\subseteq A), the unknown mass (\mu(A\setminus B)) may
further condition the actual successful-root law and cause a fault rather
than the paper's next retry. No bound on that mass is supplied here.

The certificate therefore leaves actual finite-backend abort/fault bounds,
actual successful-root distribution, every accepted-root finite sampler
bound, full issuance/signature histories, native strong security, structural
hardness and formal parameter admission unresolved.
