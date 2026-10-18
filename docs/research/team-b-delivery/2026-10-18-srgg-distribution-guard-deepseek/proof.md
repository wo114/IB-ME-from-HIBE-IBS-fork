> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# SRGG distribution chain: gate-uniform bounds, an explicit accept-set guard, and the remaining nulls

Primary source: Huiwen Jia, Ying Liu, Chunming Tang and Lin Wang,
*Constructing Efficient Identity-Based Signatures on Lattices*, IET Information
Security (2025), DOI [10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889).
Frozen local PDF `papers/2025_efficient_ibs_jia.pdf`, SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.
Original Table 4 inputs: `n=512`, `p=16383`, `b=31`, `w=2`, `q=961`,
`Q=15744063`, `d=2/3/4`; the two explicitly labelled Gaussian interpretations
(`table-standard-deviation`, `literal-density-width`) are unchanged.

This note is derived from the frozen implementation, not from new claims by the
paper. It is an independent audit of the distribution chain from finite
samplers to random-key issuance, signing and complete histories. There is no
HIBE content. Every field remains `security_claim=none`,
`backend_admitted=false`, `parameters_are_formal=false`,
`nist_security_category=null`.

## 1. The scope label that hid the theorem

The predecessor receipts ([finite chain](../2026-10-18-srgg-finite-chain/README_zh-CN.md),
[source issuance](../2026-10-18-srgg-source-issuance/README_zh-CN.md),
[history](../2026-10-18-srgg-history-law-followup/README_zh-CN.md),
[random key](../2026-10-18-srgg-random-key-sign-law/README_zh-CN.md)) all carry a
`old fixed-root label` flag and say that the six deterministic roots are witnesses,
not the accepted-root population. That flag is true about the *stored receipt*
(the six roots were the ones actually replayed), but it is not the theorem's
domain. Every numerical term in the chain is one of:

1. the audit gate floor `64` (all ideal Schur pivots at least 64),
2. the gate error constants `2^-128` (gain / stored-factor covariance) and
   `2^-96` (adaptive-center recurrence),
3. the factor envelope `2 < factor < 2^32` and the center envelope `< 2^240`,
4. root/leaf-independent scalar-batch certificates (`lower_batch`,
   `rounding_batch`) and the fixed `B=512`/`P=768`/dyadic windows,
5. the original parameters `r^2`, `degree`, `upper_polynomials`.

The actual pivot *values*, gain *values* and adaptive centers enter only through
the booleans checked by `SchurNumericalAudit` and `_source_gates`. The formulas
are therefore identical for every plan that passes the gates; replacing a real
pivot by its gate floor can only weaken the bound, never change the root-specific
constants. The six-root receipts are witnesses of a nonempty gate set.

Concretely:

- `fixed_root_finite_chain_certificate` computes
  `finite = lower_batch + rounding_batch + leaves*(n/2)*2^-170 +
   leaves*2*n*(2^-6000+delta_stored) + leaves*4096*n*(2^-96+delta_ideal)`,
  with `delta_stored = n*2^32*(2^-168+2^-490)+2^-400` and
  `delta_ideal = delta_stored + n*32*2^-128`. No witness value appears.
- `chain_convolution_certificate` / `moment_chain_certificate` receive
  `ideal_pivot_lower = 64` from the joint audit, not the actual minimum pivot.
- `ideal_normalizer_bias` uses
  `theta_certificate(dimension=degree, density_shape=64)`; again the gate floor.
- The source-issuance combination adds only root-independent gadget terms
  (`gadget.batch`, digit `theta` at `r^2`, completed-square `theta` at 64) to the
  joint perturbation bound.
- The sign-call bound adds the root-independent `u`-batch certificate to the
  same joint bound and multiplies by the fixed 64-attempt cap.

**Verified numerically.** Recomputing the master and signature joint values from
the gate floor reproduces the frozen `joint-fixed-root.json` entries exactly;
recombining the master value with the frozen gadget / digit / center terms
reproduces `source-issuance.json` exactly. The test suite asserts these equalities
for PARAM-I and the uniformity across a second, different accepted root.

## 2. Exact Setup acceptance / abort model

Let `mu` be the law of the raw Table 4 CBD1 witness. Define:

| symbol | event |
|---|---|
| `A` | the paper's strict mathematical positivity gate `Sigma_p - r^2 I > 0` holds |
| `B` | the actual `SourceSchurBackend.setup` returns a public key (plan construction, entropy and output guards) |
| `G` | the independent `SchurNumericalAudit` + `_source_gates` gates hold |
| `G'` | the guarded accept set `B ∩ G` (the original backend does not run `G`) |

`B ⊆ A` is the only inclusion supported by the code: the backend's interval LDL
rejects a certified negative full residual (the paper's retry) and aborts on an
inconclusive one. The converse is not established. `B \ G` can be nonempty
because the backend never executes the audit gates: its `FourierSchurPlan`
checks only the leaf rounding floor `pivot > r^2`, the gain coefficient error
`<= 2^-128`, real/Hermitian invariants and the entropy/output envelopes; it does
not check the `>= 64` pivot floor, the stored-factor covariance gate or the
`2^-96` center recurrence.

Consequences:

- The paper's Algorithm 1 retry bound applies to `A` only:
  `Pr[A^c after 64 retries] <= q_bound^64` with
  `q_bound < 0.205519 / 0.095133 / 0.046674`, i.e. `< 2^-146, 2^-217, 2^-282`.
- The actual backend retries only on the `WitnessGeometryError` branch and aborts
  on numeric/inconclusive failures (`ValueError`); the geometric 64-retry bound
  cannot be transferred to `B`.
- Let `e = mu(A \ (B ∩ G)) = mu(A \ B) + mu(B \ G)` (disjoint because `B ⊆ A`).
  The accepted-root law in the guarded service is `mu(· | B ∩ G)`. Taking the
  test set `B ∩ G` gives `TV(mu(·|B∩G), mu(·|A)) <= e / mu(A)`. The missing
  quantity is exactly `e`; no such bound is available from the existing moments.
- Why `e` is genuinely open: the moment bound controls `A`, while `B` and `G`
  add interval, leaf, gain, center, entropy and output checks that are not
  monotone consequences of strict positivity. A root can satisfy `A` and still
  fail a numeric gate or the `>= 64` / `2^-96` gates. A uniform anti-concentration
  or conditioning bound for those failures has not been established. A small
  deterministic search for a `B \ G` witness is included in the JSON probe; a
  miss is not a proof that the set is empty.

The guard (section 4) replaces the accept set by `B ∩ G`, making the gate set
explicit. It does not bound `mu(B \ G)`; that mass becomes an operational abort
mass, not a cryptographic bound.

## 3. Uniform conditional bounds (the closed part)

For every signed key or Setup root whose plan passes `G`, the following numbers
are root/key-independent. The six fixed-row values are:

| profile | interpretation | master joint | signature joint | first issuance | capacity history | one sign call |
|---|---|---:|---:|---:|---:|---:|
| PARAM-I | table-standard-deviation | `2^-26` | `2^-25` | `2^-25` | `2^-24` (3 ids) | `2^-19` |
| PARAM-II | table-standard-deviation | `2^-25` | `2^-24` | `2^-25` | `2^-24` (2 ids) | `2^-18` |
| PARAM-III | table-standard-deviation | `2^-25` | `2^-24` | `2^-24` | `2^-24` (1 id) | `2^-18` |
| PARAM-I | literal-density-width | exact `0.6781…` | exact `0.8964…` | `null` | `null` | `1` (trivial) |
| PARAM-II | literal-density-width | exact `0.8173…` | exact `0.9666…` | `null` | `null` | `1` (trivial) |
| PARAM-III | literal-density-width | exact `0.8964…` | exact `0.9893…` | `null` | `null` | `1` (trivial) |

The table-standard-deviation rows are nontrivial and closed; the literal rows are
nontrivial for the mathematical comparison but far too weak for a composition.
The literal first-issuance null is not caused by the Schur perturbation: the
gadget digit-normalizer / completed-square sufficient gate fails (the same
finding as the predecessor receipt).

Precision / rounding / randomness / abort premises:

- all probability arithmetic is exact rational; final readable exponents are
  outward dyadic roundings, never inward;
- the finite sampler bound assumes independent uniform bytes and the stated
  exception-free 768-bit MPFR real-primitive model, with `B=512`, `P=768`,
  dyadic window `<=384` and `n <= 512`;
- abort is an extra output symbol in the finite comparison;
- the mathematical convolution / normalizer comparisons are all-center and
  uniform in every adaptive center;
- external runtime / storage faults are outside this model;
- the values are conditional on the gate set `G`, not on all of `A`.

## 4. The guard that makes the conditional theorem an accept-set theorem

New code: `experiments/research/candidates/srgg/paper_distribution_guard.py`.

```
class SourceSchurBackend(SourceSchurBackend):
    _master_plan: construct the unchanged master plan, then require_gates(plan)
    _sign_plan:   construct the unchanged signature plan, then require_gates(plan)
```

- `require_gates` runs the complete gate set: `SchurNumericalAudit` (pivot floor
  64, gain and stored-factor covariance errors `2^-128`, adaptive-center
  recurrence `2^-96`), `_source_gates` (factor range `(2,2^32)`, center
  envelope `<2^240`, scalar/entropy caps, finite leaf/output 256-bit object
  guard), the issuance centered-gadget C gate `C > 64 I`, and the successful
  finite-key object/service byte envelope (`raw` and HNF key within 256 bits).
  A signing plan runs the Schur/audit layer only.
- In Setup, `GateFailure` is wrapped as `RootGateRejection`, a subclass of the
  original `WitnessGeometryError`; the unchanged Setup loop retries it. The
  accepted-root law becomes `mu(· | B ∩ G)`.
- Before signing, a gate failure is wrapped as `SigningKeyGateRejection`; the
  service aborts for that fixed key. No retry is attempted.
- The original `SourceSchurBackend` is untouched and remains the frozen
  reference; the guard is an explicitly labelled service variant, not a claim
  about the paper's own algorithm. It proves the modified protected accept set,
  not the original unguarded algorithm.

What this closes: every accepted root/key now satisfies the premises of the
finite/convolution/normalizer/issuance/sign formulas, so the bounds of section 3
apply uniformly. What it does not close: the probability of the guard rejection
(equivalently `mu(B \ G)`), the mathematical `A \ B` mass, and the object/service
envelope's probability under the original setup law.

## 5. Random-issued key to signing law

Let `Q_K` be the predecessor's centered-HNF pushforward of
`D_(Z^N,Sigma,0)` conditioned on `S_h`, and `P_K` the actual first-issuance law.
`delta_issue` is the uniform first-issuance TV of section 3 (table-standard
rows; `null` for literal rows).

Let `G_sign` be the set of issued keys whose signature plan passes the signing
audit gates. On `G_sign` the one-sign-call bound is the uniform value of section
3: `2^-19` (PARAM-I), `2^-18` (PARAM-II/III) under the standard-deviation
reading, and `1` under the literal reading. This is a genuine closure of the
good-key signing bound: it is no longer the one-fixture-key value standing in for
all keys; it is the same formula for every gated key.

The missing mass is

```
beta_bad = Q_K(G_sign^c).
```

It is strictly positive: the canonical large-tail witness (first tail row
coefficient `268010 / 331565 / 386948`, depending on the row) lies in the
mathematical reference's support, survives the canonical key codec and makes a
Fourier diagonal of the signing Schur form strictly negative; the unchanged
`_sign_plan` rejects it. But its *mass* is not bounded:

- the conditional tail law is `rho(t) * P_D(S_h | t) / P_D(S_h)`;
- `S_h` depends on the target `h` through `h - A_tail t mod Q`;
- the master widths (second block about 1023–1090; first block about 2844–3868)
  are far below `Q = 15744063`, so the Gaussian modulo `Q` is not smoothing;
  `P_D(S_h)` is a narrow, target-dependent bump and lacks a target-uniform lower
  bound;
- the numerator needs HNF head wrapping and all Fourier directions;
- an unconditional Gaussian tail estimate (or one observed key) would be
  unsound.

Hence `beta_bad = null` for all six rows, with `beta_bad > 0` established. The
conditional coupling lemma is:

```
TV(one issuance then s adaptive signs) <= min(1, delta_issue + beta_bad + s * epsilon_good).
```

It is a lemma, not a current numeric result: `beta_bad` is null. In the guarded
service the `beta_bad` event is an explicit aborted issuance/signing pair, not a
forgery; the security game is unchanged and still unproven.

## 6. Complete histories: fault-free and faulty

Fault-free logical history, with a shared adaptive schedule:

```
TV(full history) <= min(1, alpha_root + delta_issue + beta_bad + s * epsilon_good)
```

- `alpha_root`: `TV(accepted-root law, guarded reference law)`; null because
  `e` and `mu(B \ G)` are null.
- `delta_issue`: uniform first-issuance bound (section 3).
- `beta_bad`: null (section 5), charged once.
- `epsilon_good`: uniform one-sign-call bound (section 3), `s` adaptive calls.
- State includes root, issued keys, pending/failed entries, durable bytes, cache,
  backend state, adversary state and view; observations include returned key and
  signature bytes, snapshots, distinct errors/aborts and any timing/lock outcome.
- Norm exhaustion is included as an abort outcome in the one-call bound, but its
  standalone probability is not bounded.

With external faults there is no specified probability model. Two worlds with
identical fault-free laws and an injected read fault of probability `p` have
complete-history TV exactly `p`; with `p=1` the bound is 1. Therefore the faulty
history TV is `null`, not a small number.

## 7. Independent assessment of the predecessor route

**Correct in the predecessor.** The uniform-over-every-mathematical-reference-key
signature certificate is impossible (the canonical tail obstruction is a valid
counterexample); `beta_bad` and `A \ B` are not bounded by the frozen moments;
the conditional issuance denominator is the real obstruction; no security claim
may be made.

**Too conservative in one structural respect.** The `old fixed-root label` label
understates the theorem: all numeric terms are gate-floor constants, so the
bounds are already uniform over every gate-passing root and key. The remaining
work is not a new distributional theorem over all accepted roots; it is
(i) an accept-set guard that actually executes the audit gates and (ii) the
probability of the gated events. The predecessor's "two alternative routes" rule
stopped before this third route. The guard is a service/accept-set change, not a
proof of the original algorithm, but it is a legitimate and cheap way to make
the conditional theorem apply to every accepted root/key.

**Still genuinely open (and not made easier by the guard).**

- `P(A \ B)`: finite numeric/interval acceptance on the mathematical positivity
  event; no anti-concentration/conditioning bound.
- `P(B \ G)`: a root accepted by the original backend but failing the audit
  gates; the deterministic search in the JSON is only a witness search.
- `beta_bad`: random-issued-key bad mass under the ideal centered-HNF reference;
  the paper's widths are not smoothing modulo `Q`.
- Faulty histories: no fault law.
- Norm-exhaustion probability, native strong security, structural hardness,
  formal parameters, NIST category.

## 8. Null ledger

| quantity | status | why |
|---|---|---|
| finite-vs-mathematical Algorithm 3–4 TV on `G` | **closed** | gate constants only |
| mathematical Algorithm 3–4 vs ideal sequential TV on `G` | **closed** | pivot floor 64 |
| ideal sequential vs joint normalizer on `G` | **closed** | shape 64 |
| first-issuance TV on `G` (standard-deviation rows) | **closed** | section 3 |
| one-sign-call TV on `G_sign` (standard-deviation rows) | **closed** | section 3 |
| literal-density first issuance / one sign call | `null` / `1` | gadget digit-normalizer gate; weak moment chain |
| `P(A \ B)` | `null` | numeric/interval acceptance not implied by positivity |
| `P(B \ G)` | `null` | audit gates not executed by the original backend |
| accepted-root distribution on `A` | `null` | requires the two masses above |
| `beta_bad` | `null` (strictly positive) | conditional HNF denominator / wrapping |
| full fault-free random-issuance/signature history | `null` | `alpha_root`, `beta_bad` |
| faulty history | `null` | no fault probability model |
| norm-exhaustion probability | `null` | outcome bounded, probability not |
| native strong / hardness / NIST | `null` / `false` | separate obligations |

## 9. Reproduction

Worktree: independent branch based on `cd31389f91e5` (not the predecessor's
`srgg-fixed-service` worktree).

```bash
cd IB-ME-from-HIBE-IBS
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
    tests/test_srgg_paper_distribution_guard.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_distribution_guard \
    --output build/deepseek-distribution-guard.json
```

Environment: WSL `~/miniconda3/envs/sage`, Sage 10.9, Python 3.13.15,
Linux 6.18.33.2, Intel Core Ultra 9 275HX, OMP 4 / OpenBLAS 1 (the same
environment recorded by the predecessor). The JSON records the exact values and
the deterministic fixture hashes. Functional tests and these finite bounds are
not a security proof.
