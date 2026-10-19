# SRGG distribution chain: mathematical events and conditional implemented gates

Revision: 2026-10-19. This revision corrects the interpretation of existing
results; it adds no security proof, sampling method or parameter change.

Primary source: Jia, Liu, Tang and Wang, *Constructing Efficient Identity-Based
Signatures on Lattices*, IET Information Security (2025),
[DOI 10.1049/ise2/6684889](https://doi.org/10.1049/ise2/6684889).
The frozen PDF is `papers/2025_efficient_ibs_jia.pdf`, SHA-256
`258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.
This package concerns standalone SRGG IBS, with no HIBE content. The paper's
Table 4 parameters, Gaussian interpretations and signature equations remain
unchanged. Project working assumptions about the paper's security are not new
verification results. Safety metadata remains `security_claim=none`,
`backend_admitted=false`, `parameters_are_formal=false`,
`nist_security_category=null`.

## 1. Versions and events

Let `mu` be the raw independent CBD1 witness law. Use distinct events:

| Symbol | Meaning |
|---|---|
| `A` | mathematical positivity `Sigma_p-r^2 I > 0` |
| `G_C` | mathematical completed-square condition `C > 64 I` |
| `B_legacy` | one-attempt preparation success of the historical unguarded backend |
| `H_setup` | current implemented complete Setup predicate: plan construction, Schur audit, source gates, directed C gate and finite-key object envelope |
| `H_sign` | current implemented signing-plan construction and complete signing audit/source gates |

The historical `B` in earlier versions means `B_legacy`, not the current
`SourceSchurBackend` default. The current default executes the complete gates;
`GuardedSourceSchurBackend` is a compatibility alias to that default, not a
second audit layer. Gate checks do not change the paper's widths or equations.
Setup rejection/retry and fixed-key signing abort are explicit service policy.
The separately named public/service wrappers do not revive an unguarded route.

Sound directed intervals give `B_legacy subset A` and
`H_setup subset G_C subset A`. Soundness excludes false acceptance; it alone
provides no converse or completeness statement. A deterministic witness that
passes `H_setup` shows nonemptiness, not the mass of this event.

## 2. Existing exact algebra and original shapes

```text
n=512, p=16383, b=31, w=2, q=961, Q=15744063, d in {2,3,4},
H=d n, M=w d n, N=2H+M,
T=[R;I_M], kappa=r^2, nu=b^2 kappa,
Sigma=diag(a1 I_(2H),a2 I_M), Sigma_p=Sigma-nu T T*,
C=nu I_M-nu^2 T*Sigma^(-1)T,
C_schur=a1 I-(nu a2/(a2-nu)) R R*.
```

`R` is a `2d x wd` negacyclic matrix of independent CBD1 coefficients, with
probabilities `1/4,1/2,1/4` on `-1,0,1`. Exact rational shapes come from
`paper_parameters.PaperParams`. The unchanged readings are
`table-standard-deviation` (common squared-width scale from the 512-bit pi
endpoint rational) and `literal-density-width` (the printed density widths).
The source gives rounded decimal widths; no unpublished author precision is
inferred.

The existing Schur-complement identities are:

```text
A = { ||M(R)||_2^2 < T_A },
T_A = (a1-kappa)(a2-nu-kappa)/(nu(a2-kappa)),
G_C = { lambda_max(R*R) < T_C },
T_C = a1(nu-64-nu^2/a2)/nu^2,
scale = nu a2/(a2-nu), T_schur=(a1-64)/scale,
L2 = a1-scale T_C.
```

For the six parameter/interpretation rows, exact rational checks retain
`T_C<T_A`, `T_C<T_schur` and `L2>64`. Thus `G_C subset A` and the **ideal**
master Schur pivots have the uniform lower floor `L2`. These are mathematical
comparisons, independent of a stored root.

| Row | Reading | `T_A` | `T_C` | `T_schur` | `L2` |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | 6246.722948 | 6197.457690 | 6246.716130 | 400780.155 |
| PARAM-I | literal | 6246.722948 | 5937.174656 | 6246.674566 | 400780.155 |
| PARAM-II | std | 8926.269269 | 8855.877898 | 8926.262453 | 572585.423 |
| PARAM-II | literal | 8926.269269 | 8483.981684 | 8926.220885 | 572585.423 |
| PARAM-III | std | 11555.616682 | 11464.494961 | 11555.609867 | 741172.329 |
| PARAM-III | literal | 11555.616682 | 10983.076458 | 11555.568297 | 741172.329 |

Decimals here and below are approximate displays. Exact fractions and outward
power-of-two bounds are in the JSON.

### Numerical completeness is not established

The ideal positivity margins are about 0.79% (std) and 4.96% (literal).
Candidate gain/factor/center/output envelope constants are also retained by
`good_root_constants`. In particular, it checks rational inequalities after
assigning `gain_error_upper=2^-256`, `noise_cap_upper=2^35` and
`object_cap_bits=64`. This does not derive a uniform error enclosure for every
operation in the finite FFT/LDL/preparation code. The prior statement
"sound intervals therefore certify every G_C root" was too strong.

Separately, the implemented C gate uses 192-bit directed intervals. The exact
condition `C>64I` permits arbitrarily small mathematical margin above 64;
no uniform enclosure or probability bound for its inconclusive shell is given
here. The former assertion that a threshold shift leaves the *exact* `q_C`
unchanged is withdrawn. Any transfer to an implemented accept set would require
an explicit enclosing threshold or additional completeness premise. This task
records that limit and does not add a new proof project.

## 3. Retained trace-moment calculation: mathematical scope

The existing Setup-acceptance package supplies the CBD1 moment comparison:
negacyclic Fourier entries have independent CBD1 coefficients; primitive
1024th-root rotation cancels unbalanced mixed moments at these orders; the
coefficientwise mgf comparison bounds balanced moments by circular-Gaussian
moments. Independence of entries permits the trace-moment comparison.

For an `a x b` Gaussian block with entry second moment `n/2`, the retained
exact hook identity is:

```text
E Tr((GG*)^k) = (n/2)^k/k! * sum_h (-1)^h binom(k-1,h) H_a(k,h)H_b(k,h),
H_x(k,h) = prod_(j=0)^(k-h-1)(x+j) prod_(j=1)^h(x-j),
0 <= h < min(a,b,k),
q(T) = 256 E Tr((GG*)^k)/T^k.
```

The unchanged orders are `k=17,22,28`. Define `q_A=q(T_A)` and `q_C=q(T_C)`.
The valid mathematical statements are

```text
mu(A^c) <= q_A, mu(G_C^c) <= q_C,
TV(mu(.|A),mu(.|G_C)) <= q_C/(1-q_A),
Pr[64 independent mathematical G_C rejections] <= q_C^64.
```

| Row | Reading | `q_A` | `q_C` | mathematical root-law TV bound | ideal `G_C` retry bound |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | 0.205519 | 0.235130 | 0.295954 | `2^-133` |
| PARAM-I | literal | 0.205519 | 0.487621 | 0.613760 | `2^-66` |
| PARAM-II | std | 0.095133 | 0.113233 | 0.125138 | `2^-201` |
| PARAM-II | literal | 0.095133 | 0.290989 | 0.321582 | `2^-113` |
| PARAM-III | std | 0.046673 | 0.058256 | 0.061108 | `2^-262` |
| PARAM-III | literal | 0.046673 | 0.193644 | 0.203125 | `2^-151` |

These are not actual-service acceptance or abort budgets. If the additional
premise `G_C subset B_legacy subset A` were established, the same arithmetic
would bound `mu(A minus B_legacy)` and the corresponding root-law TV; this
package no longer asserts that premise. The implemented `H_setup` law, its
64-attempt abort probability, the legacy acceptance law and the numerical
shell mass remain explicitly null. Retrying operational gate failures fixes
control flow but does not establish their probability.

## 4. Conditional issuance and signing on implemented gates

The six replayed roots and the boundary probes are functional witnesses.
Their actual pivots are not substituted into the probability formulas:
finite-chain, convolution and normalizer terms use the audit floor 64,
error gates, fixed numerical windows and root-independent scalar budgets.
On a plan that actually passes the complete applicable gates, the retained
bounds therefore have the gate-uniform conditional scope.

Use the same deterministic signing guard in the actual key law `P_K` and
reference `Q_K`, and the same abort semantics. Both bad-key branches abort;
the data-processing comparison gives the existing conditional formula

```text
TV(guarded issue + s adaptive signs) <= min(1,delta_issue+s epsilon_good).
```

This retains the existing result; it neither estimates nor sets to zero the
unguarded bad-key mass `beta_bad`. The canonical large-tail obstruction remains
in the unguarded ideal reference support, with unquantified strictly positive
mass. If key bytes are exposed at issuance, the reference keeps the same key
output and applies the same subsequent guard; the guard does not erase an
already exposed key from either history.

| Row | Reading | `delta_issue` | `epsilon_good` | issue + 1 sign | issue + 2 signs |
|---|---|---:|---:|---:|---:|
| PARAM-I | std | `2^-25` | `2^-19` | `2^-19` | `2^-18` |
| PARAM-II | std | `2^-25` | `2^-18` | `2^-18` | `2^-17` |
| PARAM-III | std | `2^-24` | `2^-18` | `2^-18` | `2^-17` |
| I/II/III | literal | null | `1` (trivial) | null | null |

The literal-density first-issuance bridge remains null because its gadget
normalizer sufficient gate fails. The one-call signing comparison includes
the same 64 norm attempts and abort symbol on both sides. It does not bound
the separate norm-exhaustion probability. No conditioning on successful
signatures or unbounded-retry comparison is silently performed.

## 5. History scope

Only **logical API outputs and deterministic persistent state** are covered:
returned keys/signatures, canonical persisted state, cached results and common
logical error/abort outcomes. Use fresh iid bytes, matching logical schedules,
matching Setup/abort semantics (or explicitly condition both sides on the same
successful Setup/root), and no unmodeled infrastructure faults. Then the
conditional per-root comparison uses the formula in section 4; each newly
issued identity pays its issuance term and cached repeats add none.

Wall-clock timing, lock scheduling, entropy consumption, internal sampler
traces and general runtime state are excluded. The retained output-kernel
bounds do not establish joint bounds for those observables. The actual-service
full history including its unboundedly unspecified Setup-law comparison stays
null. In particular the mathematical `q_C/(1-q_A)` cannot be added as if it
were a certified implemented `H_setup` root-law cost.

Disk/process/rollback/power failures have no probability model here. An
external read fault injected with probability `p` can create transcript TV `p`
while fault-free output laws agree. Faulty-history TV therefore remains null.

## 6. Evidence, reproduction and unresolved items

The earlier exact `RingSchurPlan` route hit the 16384-bit rational resource
cap on a Table 4 root. Its failure remains recorded and is not used. The
three `boundary-PARAM-I/II/III.json` files retain the observed positive-C
boundary lifecycles; a successful probe does not establish interval
completeness or an acceptance probability. No probe is an attack proof.

Other remaining items include literal-density issuance, author SampleZ/C
bitwise correspondence, source ambiguities (`r/sigma`, Algorithm 4 `d/f`,
zeta factor, `q>2 gamma`), native strong observations, structural hardness,
formal parameter admission and NIST categories. This revision does not schedule
new proofs or change project working assumptions. The earlier compact-codec
sizes/timings/RSS were measured on their frozen backend; they do not transfer
to the guarded default without new measurements.

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_paper_distribution_chain.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
  experiments.research.candidates.srgg.paper_distribution_chain \
  --output build/distribution-chain-new.json
```

`--lifecycle` adds six deterministic replays; output must not exist. See
[validation.json](validation.json), [distribution-chain.json](distribution-chain.json)
and [verify_delivery.py](verify_delivery.py) for the fixed evidence, source
bindings and reproduction environment. Frozen runs used WSL Sage 10.9 and
Python 3.13.15. Functional tests, numerical bounds and source hashes do not
establish an IBS security reduction.
