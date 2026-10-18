# SRGG distribution chain: good-root implication, accepted-root bound, and guarded composition

Scope: the standalone identity-based signature of Jia, Liu, Tang and Wang,
*Constructing Efficient Identity-Based Signatures on Lattices*, IET Information
Security (2025), DOI [10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889).
The frozen local source is `papers/2025_efficient_ibs_jia.pdf`, SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.
This note has no HIBE content.  It does not change the paper's parameters,
Table 4 widths, algorithms, Gaussian interpretations or signature equations.
All fields remain `security_claim=none`, `backend_admitted=false`,
`parameters_are_formal=false`, `nist_security_category=null`.

The note contains four results.

1.  A **good-root implication**: the completed-square gate `C > 64 I` implies
    the paper's mathematical positivity gate `A` and gives a uniform master
    Schur pivot lower bound `L2` between `4.0e5` and `7.4e5`.  It also gives
    uniform gain, factor, center, entropy and object bounds, so every root in
    the good set is accepted by the unchanged source-Schur backend.
2.  A **bad-root mass bound**: the existing exact complex-Wishart trace moment
    is evaluated at the `C`-gate threshold.  This bounds `P(A \ B)` and the
    total variation distance between the paper's accepted-root law `mu(.|A)`
    and the backend's accepted-root law `mu(.|B)`, for all six
    parameter/interpretation combinations.
3.  A **guarded random-key signing theorem**.  The deterministic signing-plan
    gate is applied to both the actual key law and the ideal reference.  By
    data processing the bad-key mass is absorbed into the first-issuance TV,
    so the guarded issue-plus-sign bound is
    `min(1, delta_issue + s * epsilon_good)` without a separate `beta_bad`.
4.  A **fault-free history bound** for the guarded service, with the faulty
    history left explicitly null because the paper and the implementation
    define no disk/process fault probability model.

The unguarded `beta_bad`, the unguarded 64-attempt abort, the literal-density
first-issuance bridge, the author's omitted sampler, native strong security,
structural hardness and faults remain null.  Those nulls are listed in
Section 7; none is silently set to zero.

## 1. Shapes, thresholds and the two Gaussian readings

Let

```text
n = 512, p = 16383, b = 31, w = 2, q = b^w = 961, Q = p q = 15744063,
d in {2,3,4},  H = d n,  M = w d n,  N = 2H + M.
```

`R` is the `2d x wd` negacyclic matrix of independent CBD1 coefficients
`chi = B_1 - B_2`, with `P(-1)=P(1)=1/4`, `P(0)=1/2`.  Set

```text
T = [R; I_M],
kappa = r^2,  nu = b^2 kappa,
Sigma = diag(a1 I_{2H}, a2 I_M),
Sigma_p = Sigma - nu T T^*,
C = (nu^{-1} I_M + T^* Sigma_p^{-1} T)^{-1}
  = nu I_M - nu^2 T^* Sigma^{-1} T,
C_schur = a1 I - (nu a2/(a2-nu)) R R^*.
```

`a1 = master_first_squared`, `a2 = master_second_squared` are the exact
rational shapes of `paper_parameters.PaperParams`.  The two explicit readings
of the paper's rounded Gaussian notation are unchanged:

* `table-standard-deviation`: all squared widths are multiplied by the exact
  512-bit rational enclosure of `pi` (endpoint sum, not `QQ(RealNumber)`);
* `literal-density-width`: the printed decimals are the density widths
  directly.

The mathematical Setup gate is

```text
A = {Sigma_p - kappa I > 0}
  = { ||M(R)||_2^2 < T_A },
T_A = (a1-kappa)(a2-nu-kappa) / (nu (a2-kappa)).
```

The last identity is the exact Schur-complement computation of
`paper_setup_conditioning.residual_threshold_squared`; `M(R)` is the real
coefficient operator of the ring matrix `R`, and its norm is the maximum over
the `n/2` conjugate-paired Fourier blocks.

The new good set is

```text
G = { C > 64 I } = { lambda_max(R^* R) < T_C },
T_C = a1 (nu - 64 - nu^2/a2) / nu^2.
```

`R` is square in all three rows (`2d = wd` because `w=2`), so `R^*R` and
`R R^*` have the same nonzero eigenvalues.  Define also

```text
scale = nu a2/(a2-nu),   T_schur = (a1-64)/scale,
L2 = a1 - scale T_C.
```

`L2` is exactly the uniform lower bound on `C_schur` on `G`; it is not an
observed pivot value.

| row | reading | `T_A` | `T_C` | `T_schur` | `L2` |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | 6246.722948 | 6197.457690 | 6246.716130 | 400780.155 |
| PARAM-I | literal | 6246.722948 | 5937.174656 | 6246.674566 | 400780.155 |
| PARAM-II | std | 8926.269269 | 8855.877898 | 8926.262453 | 572585.423 |
| PARAM-II | literal | 8926.269269 | 8483.981684 | 8926.220885 | 572585.423 |
| PARAM-III | std | 11555.616682 | 11464.494961 | 11555.609867 | 741172.329 |
| PARAM-III | literal | 11555.616682 | 10983.076458 | 11555.568297 | 741172.329 |

The exact rational values, not these decimals, are used by the code and the
JSON.  The table already shows the two strict implications checked below.

## 2. Good-root implication

### Lemma 2.1 (`G` implies `A`)

For every row, `T_C < T_A`.  Suppose `C > 64 I`.  Then
`lambda_max(R^*R) < T_C < T_A`, hence `Sigma_p - kappa I > 0`.  Therefore
`G` is a subset of the paper's mathematical positivity event `A`.

This is the key structural point.  The gate `C > 64 I` is *stronger* than
`A`, not merely a numerical restatement of it.  The gap is about 0.79% of
`T_A` in the standard-deviation reading and about 4.96% in the literal
reading.  The interval margin is enormous relative to the 768-bit directed
error in both cases.

### Lemma 2.2 (`G` implies the master Schur floor)

On `G`,

```text
C_schur = a1 I - scale R R^*
        >= (a1 - scale T_C) I
        = L2 I,
```

and `L2 > 64`.  The ideal descending ring-Schur pivots of `C_schur` are
Schur complements of a positive-definite matrix; every such pivot is at least
`lambda_min(C_schur)`.  Hence every ideal master pivot on `G` is at least
`L2`, uniformly, with `L2` about `4.0e5`, `5.7e5`, `7.4e5` for `d=2,3,4`.
This is far stronger than the audit floor `64`.

### Lemma 2.3 (the remaining master gates on `G`)

The following uniform constants are checked exactly in
`good_root_constants` for all six rows.

1. **Full residual interval positivity.**  `A` has a threshold margin
   `T_A - T_C` of about 0.79% of `T_A` (standard-deviation reading) or 4.96%
   (literal reading).  The directed 768-bit interval LDL of
   `FourierSchurPlan` has an error many orders of magnitude below this
   margin, so it certifies the exact positive definiteness of the full
   residual on `G`.  (A root with a certified negative direction is the
   paper's geometric rejection; an inconclusive interval is an abort.)
2. **Stored gain.**  In a Fourier block,
   `|gain(zeta)| = |C_schur(i,j)(zeta)/pivot(zeta)|`
   `<= (a1 + scale lambda_max(R R^*))/L2`
   `<= (a1 + scale T_C)/L2 < 512`.
   The ring gain polynomial has Fourier values bounded by 512.  By
   Plancherel and Cauchy--Schwarz, its coefficient `l1` norm is at most
   `sqrt(512)*512 < 2^14`.  The stored dyadic gain is rounded to the
   `2^-256` grid; the directed interval error is far below `2^-256`.
   Therefore the audit gain error is at most `2^-256`, well inside its
   `2^-128` gate.
3. **Stored factor.**  Every ideal pivot lies between `L2` and `2 a1`
   (Schur-complement eigenvalues interlace the original matrix spectrum).
   Hence
   `factor^2 = (pivot-kappa)/(2 pi)` lies between `(L2-kappa)/(2 pi)` and
   `(2 a1-kappa)/(2 pi)`.  The exact checks give
   `250 < factor < 8192` for all rows, inside the `(2, 2^32)` envelope.
4. **Adaptive center recurrence.**  The audit recurrence is
   `E_{j+1} <= n * epsilon * B + G * E_j + 2^-257`, where `epsilon <= 2^-256`
   is the gain error, `B <= 2^35` bounds the successful-residual envelope,
   and `G <= 2^14` is the gain `l1` bound.  Starting at zero and applying
   `2d` stages gives `E < 2^-96` for all rows (the worst case is `2d=8`,
   where the recurrence gives about `2^-114`).  This is the `2^-96` gate used
   by `SchurNumericalAudit` and by the finite-chain certificate.
5. **Entropy, output and object caps.**  The lower/rounding scalar batches,
   the whole-attempt byte cap and the dimension cap are root-independent and
   are the same frozen `B=512`/`P=768`/dyadic `<=384` profile used by the
   existing finite-chain receipts.  The all-path output envelope is at most
   `2^64` bits; the `PaperSchurSampleF` 240-bit and the 256-bit object gates
   both hold.  The finite-key object/service envelope of
   `paper_source_issuance_bridge._source_key_guard_envelope` is therefore
   within its 256-bit bound.

### Corollary 2.4 (`G` is contained in the backend accept set `B`)

Let `B` be the event that the unchanged `SourceSchurBackend.setup` returns a
public key on one attempt.  On `G`, the mathematical gate `A` holds, the
master pivots are at least `L2`, the gain/factor/center gates hold, and all
resource/object checks hold.  A sound directed-interval implementation
therefore certifies every `FourierSchurPlan` check, and the backend returns.
Thus

```text
G  subset  B.
```

Assuming the interval routines are sound, a certified positive residual also
implies exact positive definiteness, so

```text
B  subset  A.
```

The first inclusion uses the unchanged backend, not the guard.  The boundary
probe in Section 8 exercises roots with `C` just above `64` and confirms
Setup, the C gate, the master/sign audits, the object envelope and a full
Extract/Sign/Verify lifecycle on all three profiles.

The `G subset B` statement is analytic; the boundary probe is functional
evidence for the implementation.  It is not a proof that every line of the
Python/Sage interval code is correct.  The directed-interval soundness
premise is stated explicitly in Section 7.

The implemented `fixed_root_c_gate` checks `C > 64 I` with 192-bit directed
intervals.  If it rejects an exact `G` root because the interval is
inconclusive, that only shrinks the guarded accept set.  The unchanged-backend
bound `P(A \ B) <= q_C` does not depend on the guard at all.  For a guarded
reference, define the reference with the same implemented gate; data
processing applies to that common predicate.  The mass of an
interval-inconclusive shell is charged by moving `T_C` outward by the
192-bit width; the shift is far below the displayed precision and the same
`q_C` table applies at that precision.  This is an implementation-shell
remark, not a hidden exact-arithmetic assumption.

## 3. Accepted-root distribution over all six rows

Let `mu` be the raw CBD1 witness law and let `B` be the backend's one-attempt
accept set.  From Section 2,

```text
G subset B subset A,      A \ B subset A \ G.
```

Therefore

```text
P(A \ B) <= P(A \ G) <= P(C <= 64 I) = P(lambda_max(R^*R) >= T_C).
```

The right-hand side is bounded by the same exact complex-Wishart trace-moment
certificate already used for `A` in the frozen Setup-acceptance package.
For a Fourier block `G` of shape `2d x 2d` with independent complex Gaussian
entries of second moment `n/2=256`, the trace moment is

```text
E Tr((G G^*)^k)
 = (n/2)^k/k! * sum_{h=0}^{min(a,b,k)-1} (-1)^h C(k-1,h)
       H_a(k,h) H_b(k,h),
H_x(k,h) = prod_{j=0}^{k-h-1}(x+j) prod_{j=1}^{h}(x-j).
```

Markov and a union over the `n/2=256` conjugate-paired blocks give

```text
P(lambda_max(R^*R) >= T) <= q(T)
 = 256 * E Tr((G G^*)^k) / T^k.
```

The same orders `k=17,22,28` as the frozen certificate are used.  Let
`q_A = q(T_A)` and `q_C = q(T_C)`.  Then

```text
P(A \ B) <= q_C,
TV(mu(.|A), mu(.|B)) = P(A \ B)/P(A) <= q_C/(1-q_A).
```

The denominator uses `P(A) >= 1-q_A`, which follows from the same
`A`-rejection bound.  No density estimate, seed replay or fixed-root
extrapolation is used.

| row | reading | `q_A` | `q_C` | `TV(mu(.|A),mu(.|B))` | `q_C^64` |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | 0.205519 | 0.235130 | 0.295954 | `2^-133` |
| PARAM-I | literal | 0.205519 | 0.487621 | 0.613760 | `2^-66` |
| PARAM-II | std | 0.095133 | 0.113233 | 0.125138 | `2^-201` |
| PARAM-II | literal | 0.095133 | 0.290989 | 0.321582 | `2^-113` |
| PARAM-III | std | 0.046673 | 0.058256 | 0.061108 | `2^-262` |
| PARAM-III | literal | 0.046673 | 0.193644 | 0.203125 | `2^-151` |

The values are exact rationals in `distribution-chain.json`; the decimals are
outward-safe displays.  The last column is the 64-retry exhaustion bound for
a **guarded retry model** that treats every `G`-failure as a retryable root
rejection.

### Retry-model caveat

The unchanged backend retries only `WitnessGeometryError` (a certified
negative full-residual direction, i.e. a geometric `A`-failure).  Interval
inconclusive, gain, factor, center and resource failures raise `ValueError`
and terminate the Setup call.  Therefore:

* for the **guarded retry model** (all `G`-failures retried), the 64-attempt
  abort is at most `q_C^64`;
* for the **unchanged backend**, the non-retryable failure mass is at most
  `q_C` on one attempt; raising it to the 64th power would be unsound.

The accepted-root **distribution** bound is the same in both models: every
accepted root is in `B subset A`, and the only part of `A` missing from `B`
is contained in `A \ G`, whose mass is at most `q_C`.

## 4. Guarded random-issued-key signing

The previous random-key package left `beta_bad` and `epsilon_good` null and
used the conditional formula

```text
TV <= min(1, delta_issue + beta_bad + s * epsilon_good).
```

The following observation removes `beta_bad` for the guarded service.

### Lemma 4.1 (deterministic guard data processing)

Let `P` and `Q` be two laws on a key space `K` with `TV(P,Q) <= delta`.
Let `g: K -> {good, bad}` be a deterministic predicate.  Define the guarded
laws `g#P`, `g#Q` by mapping every bad key to the common abort atom `abort`.
Then

```text
TV(g#P, g#Q) <= TV(P,Q) <= delta.
```

This is the data-processing inequality for the deterministic map `g`.

Let `P_K` be the actual first-issuance key-plus-abort law on a root in `G`,
and `Q_K` the ideal centered-HNF first-issuance reference.  The frozen
source-issuance bridge gives

```text
TV(P_K, Q_K) <= delta_issue
```

on every root passing the complete master gate set; `G` implies that set.
Let `g` be the signing-plan audit predicate (`SchurNumericalAudit` plus
`_source_gates`).  Apply `g` to both sides.  On `g=good`, the one-sign-call
finite kernel is within `epsilon_good` of the ideal mathematical signing
kernel, uniformly over all adaptive messages, by the gate-uniform
finite-chain certificate.  On `g=bad`, both sides abort with the same atom.
The maximal-coupling hybrid therefore gives, for one issuance and `s`
adaptive sign calls,

```text
TV(guarded issue + s signs) <= min(1, delta_issue + s * epsilon_good).
```

The term `beta_bad` is not needed because the bad-key mass difference between
`P_K` and `Q_K` is already bounded by the pushforward TV, which is at most
`delta_issue`.  This is a theorem about the **guarded service**, which
executes the signing-plan audit before signing.  The unguarded service may
still work on most keys, but it has no uniform `epsilon_good` and no
`beta_bad` bound.

The unguarded `beta_bad` remains strictly positive and unquantified: the
canonical large-tail key lies in the mathematical reference support, survives
the key codec, and makes a Fourier diagonal of the signing Schur form strictly
negative.  Its mass is not bounded here.  The guarded formula does not
pretend to bound it.

### Numeric guarded values

The one-root lifecycle probes reproduce the frozen gate-uniform values:

| row | reading | `delta_issue` | `epsilon_good` | guarded issue+1 sign | guarded issue+2 signs |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | `2^-25` | `2^-19` | `2^-19` | `2^-18` |
| PARAM-II | std | `2^-25` | `2^-18` | `2^-18` | `2^-17` |
| PARAM-III | std | `2^-24` | `2^-18` | `2^-18` | `2^-17` |
| PARAM-I/II/III | literal | null | `1` | null | null |

The literal-density rows have `delta_issue=null`: the centered gadget
digit-normalizer sufficient gate fails, so the first-issuance bridge is not
available.  Their one-sign-call *kernel* bound is the trivial `1`, but the
combined guarded issue-plus-sign TV remains `null` because the issuance term
is missing.  They are not silently given the standard-deviation values.

`epsilon_good` includes the paper's 64 norm retries and an abort atom.  The
standalone norm-exhaustion probability is still not bounded; only the
one-call kernel distance is.

## 5. Fault-free complete history

The state includes the root, every issued key, pending/failed entries,
durable bytes and markers, backend/runtime state, caches, and the adversary's
state and view.  The observation map includes returned key/signature bytes,
canonical snapshots if exposed, distinct errors/aborts, and any timing or lock
outcome the game elects to reveal.  The observation map is identical on both
sides.

For the guarded service, the actual and reference Setup both condition on the
same good-root set `G`; the root/initial-state term is therefore `0`, not an
unknown `alpha_root`.  If one insists on comparing to the paper's `mu(.|A)`
instead, add the accepted-root term `q_C/(1-q_A)` from Section 3.

For one first issuance and at most `s` adaptive sign calls, the guarded
fault-free history bound is

```text
TV(history) <= min(1, delta_issue + s * epsilon_good)
```

for the same guarded reference, or

```text
TV(history) <= min(1, q_C/(1-q_A) + delta_issue + s * epsilon_good)
```

when the reference root law is the paper's `mu(.|A)`.  Repeated cached
identities cost nothing extra; a new identity pays its own first-issuance
term; keys are cached, so a bad key is charged at most once.

This is a logical, fault-free schedule.  External disk, process, lock,
rollback and power faults have no probability model in the paper or in the
implementation.  Two worlds with identical fault-free laws and an injected
read fault of probability `p` have complete-history TV exactly `p`; with
`p=1` the TV is `1`.  Therefore the faulty-history TV is `null`, not a small
number inferred from the fault-free bound.

## 6. What is actually closed

**Closed for the unchanged backend root distribution.**

* `G subset B subset A` and `A \ B subset A \ G` (Section 2).
* `P(A \ B) <= q_C` and `TV(mu(.|A), mu(.|B)) <= q_C/(1-q_A)` for all six
  rows, with exact rational certificates (Section 3).
* The unchanged backend accepts every `G` root; the boundary probe exercises
  `C` just above `64` on all three profiles.

**Closed for the guarded service.**

* The good-key one-call bound `epsilon_good` is gate-uniform, not a
  one-fixture-key statement.
* The guarded issue-plus-sign bound `delta_issue + s epsilon_good` follows by
  data processing; `beta_bad` is absorbed, not set to zero.
* The fault-free guarded history bound follows for the same reason.
* The guarded 64-retry Setup abort is at most `q_C^64` if all `G`-failures are
  retried.

**Not closed.**

* The unguarded `beta_bad` mass.
* The unchanged backend's non-retryable 64-attempt abort (only the one-attempt
  `q_C` bound is available).
* Literal-density first issuance (`delta_issue=null`) and literal one-sign
  bound (trivial `1`).
* The exact author sampler, C program and omitted `SampleZ` table
  implementation.
* Native strong security, structural hardness, formal parameter admission,
  NIST category.
* Fault probabilities and faulty complete histories.
* The paper's unresolved source ambiguities (`r`/`sigma` units, Algorithm 4
  `d`/`f`, the `zeta` factor, `q>2 gamma`).

## 7. Premises

1. **CBD1 source.**  The raw witness coefficients are independent CBD1 with
   `P(-1)=P(1)=1/4`, `P(0)=1/2`, from independent uniform bytes.  A
   deterministic seed is a test fixture, not a proof of this premise.
2. **Exact shapes.**  The two Gaussian readings are the exact rational shapes
   of `PaperParams`, including the 512-bit endpoint rational for `pi` in the
   standard-deviation reading.  No unpublished author precision is inferred.
3. **Interval soundness.**  The directed `ComplexIntervalField(768)` Fourier
   computations, the dyadic gains and the Sage interval `LDL` are assumed
   sound.  The analytic gate implications show the margins are many orders of
   magnitude larger than the interval errors; the boundary probe confirms the
   implementation on worst-case `C`-boundary roots.  This is an implementation
   premise, not a proved property of every Python/Sage operation.
4. **MPFR.**  The finite sampler's floating-point primitives are the stated
   exception-free correctly rounded MPFR/MPFI operations.  No external
   runtime fault is included.
5. **Trace moment.**  The complex-Wishart moment computation is exact rational
   arithmetic; the Markov/union bound is the frozen Setup-acceptance method.
   It bounds the mathematical CBD1 witness law, not a fixed seed or a measured
   frequency.
6. **Guard service.**  The signing guard is a deterministic predicate on the
   key.  The guarded theorem is about the service that executes it; it is not
   a theorem about the unchanged service.
7. **No fault model.**  Disk, process, lock, rollback and power faults are
   outside the model.

## 8. Source and code correspondence

| paper object | code |
|---|---|
| Algorithm 1 CBD1 witness and `Sigma_p` retry | `paper_backend.Backend.setup`, `paper_schur_backend.SourceSchurBackend.setup` |
| `C` completed-square center | `paper_algebra`, `paper_issuance_bridge.fixed_root_c_gate` |
| Algorithms 3-4 master/sign perturbation | `paper_schur_samplef.PaperSchurSampleF`, `paper_schur_fourier.FourierSchurPlan` |
| finite-chain and normalizer gates | `paper_schur_finite_chain`, `paper_schur_convolution`, `paper_schur_normalizer`, `paper_schur_numerical.SchurNumericalAudit` |
| first issuance / centered HNF | `paper_source_issuance_bridge`, `paper_issuance_bridge.combine_issuance_tv` |
| random-key signing audit | `paper_random_key_sign_law`, `paper_distribution_chain.require_gates` |
| history model | `paper_fault_history_law`, `paper_history_law_followup` |
| Setup positivity threshold | `paper_setup_conditioning.residual_threshold_squared` |
| exact trace moment | `paper_setup_acceptance.wishart_trace_moment` |

The new module `paper_distribution_chain.py` does not modify any of those
files.  It imports them, recomputes the exact thresholds and moments, and runs
the guard probes.

## 9. Reproduction

From the worktree root, under the prescribed WSL Sage environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
    tests/test_srgg_paper_distribution_chain.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_distribution_chain \
    --output build/distribution-chain.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_distribution_chain \
    --lifecycle --output build/distribution-chain-lifecycle.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
    docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/boundary_probe.py \
    --profile PARAM-I --output \
    docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/boundary-PARAM-I-new.json
/usr/bin/python3 docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/verify_delivery.py
```

The first report is the exact math certificate.  The second adds one
deterministic Setup/Extract/Sign replay per row and the guarded composition
numbers.  `boundary_probe.py` searches a deterministic worst-case witness with
`C` just above `64 I` and runs the complete gate/lifecycle; its three frozen
receipts are `boundary-PARAM-I/II/III.json`.  Output paths must not already
exist.  The boundary-witness search and lifecycle probe are recorded in
`validation.json`; they are functional evidence, not a probability or a
security proof.

Environment: WSL2, Sage 10.9, Python 3.13.15; see `distribution-chain.json`
for the exact platform string and dependency SHA-256 values.

## 10. Security statement

This is a distribution and acceptance-set audit of the standalone SRGG IBS.
It is not an IBS security proof, not a reduction, not a NIST category and not
a formal parameter admission.  Functional tests, fixed-root probes, the
boundary probe and exact finite TV bounds do not replace a proof of the
underlying lattice assumptions or of the strong/ROM security game.  The
project flags remain:

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```
