# SRGG scalar batches: explicit aggregate entropy cap

Date: 2026-10-16. Implementation: `experiments/research/candidates/srgg/aggregate_budget.py`.
This is an opt-in research helper. It retains every original scalar finite
weight and original Gaussian/uniform trial limit and adds an explicit batch
budget abort. That extra abort changes the extended output law, by at most the
certified probability under independent uniform bytes. It does not establish
unchanged output distribution conditional on successful completion.

## Scope and API

The runtime entry points are:

```python
batch_certificate(sampler, count, *, error_bits=128, max_bytes=256*1024*1024)
AggregateByteSource(source, maximum)
sample_batch(sampler, width_squared, centers, *, rng=None,
             error_bits=128, max_bytes=256*1024*1024)
```

`batch_certificate` accepts an already validated `WideScalarGaussian` and
returns exact rational error bounds. It permits at most 2^20 scalar calls.
`sample_batch` preflights every center, including the last, before consuming
entropy. It rejects an unaffordable cap before sampling. It returns a complete
tuple or raises; it does not return a partial batch. `AggregateByteSource`
checks the remaining cap before every underlying read. Entropy failures,
malformed byte counts and scalar sampling aborts propagate without retries or
fallback. The maximum allowed cap is 268,435,456 bytes (256 MiB).

The scalar reference is the sequence of ideal `D_Z` kernels at the same
admitted exact centers. The centers may depend on earlier outputs because the
scalar acceptance bounds are uniform over the public width class and admitted
centers. Continuous Gaussian tickets, a Gaussian factor, convolution,
smoothing, gadget fiber normalizers, HNF pushforward, strong security and the
complete IBS distribution are separate obligations.

## Conditional success-count lemma

Let `X_i` be a success indicator and `F_(i-1)` the full past. Assume
`Pr[X_i=1 | F_(i-1)] >= p > 0`, with no independence assumption on the indicators.
For `S_t = sum X_i`,

```text
E[2^(-X_i) | F_(i-1)] <= 1 - p/2,
E[2^(-S_t)] <= (1-p/2)^t <= exp(-p*t/2)
             <= 2^(-floor(p*t/2)).
```

The first line follows by expanding the expectation of a binary variable; the
second follows by iterated conditional expectation and `1-x <= exp(-x)`.
The final inequality follows from `ln(2)*floor(x) <= x` for `x >= 0`.
Markov's inequality on `S_t < N`, using integer-valued `S_t <= N-1`, gives

```text
Pr[S_t < N] <= 2^(N-1-floor(p*t/2)).
t = ceil(2*(N+K)/p)  =>  Pr[S_t < N] <= 2^(-K-1).
```

The implementation performs these operations on exact rational numbers and
returns the dyadic bound; it does not round a floating approximation to `p`.
The history-dependent finite-state test checks this bound by exact dynamic
programming in addition to exact binomial tests. These tests support the code
mapping; the derivation above is the general argument.

## Applying the lemma twice

First take `p` to be the sampler's certified
`acceptance_probability_lower`. The lemma bounds the Gaussian proposal count
needed for `N` scalar acceptances by `t` except with probability at most
`2^(-K-1)`.

Each proposal uses rejection-based uniform integer sampling. Write `M` for
the sampler's `max_support_count`. An integer center has `M-1` support points;
a noninteger center has `M`. The conditional success probability of one
uniform candidate is therefore at least

```text
q = min(n / 2^bit_length(n-1) for n in (M-1, M)).
```

Apply the lemma to `t` uniform acceptances with lower bound `q`. It returns a
candidate count `L` with overflow probability at most `2^(-K-1)`. The byte cap is

```text
L*candidate_bytes + t*bernoulli_bytes.
```

The sum of the two overflow bounds is at most `2^-K`. For the probability
argument only, extend both rejection loops without their old limits and
couple the extension to the actual scalar calls until the first original
abort. Overflow before an original abort is contained in an overflow of this
extension, so the union bound applies. The implementation never runs that
extension and never retries an original abort. Its existing Gaussian and
uniform limits remain enforced.

If the original all-path bound `N*random_tape_bytes` is smaller, it is selected
instead and the additional abort bound is zero. Otherwise, coupling the old
and new actual samplers on identical bytes shows that they agree until the
new cap aborts. Their extended-law TV distance is at most the new abort bound.
Adding the old per-scalar TV bounds gives the reported union bound relative to
the sequential ideal scalar kernels. Existing scalar aborts are separately
reported and also included in the old scalar TV bounds; callers must not add
them twice to that TV figure. Deterministic test seeds do not establish the
independent-uniform-byte assumption.

## n512 scalar execution evidence

The input arithmetic points come from `formal_candidates.conditional_candidate`
with `n=512`, `d=2,3,4`, `w=8`; they remain conditional candidates, not admitted
security parameters. Width classes are `r^2`,
`master_second_squared - b^2*r^2`, and
`signature_second_squared - 2*r^2`. The `r^2` row combines one master and one
signature's required call counts. Each executed batch uses the prescribed
public center sequence `((i % 11)-5)/3`, with no identity or message.

| d | Scalar class | N | Old all-path bytes | Selected cap bytes | Actual bytes |
|---:|---|---:|---:|---:|---:|
| 2 | r^2 | 12,800 | 2,640,384,000 | 7,508,387 | 3,460,886 |
| 2 | master lower | 8,192 | 4,920,115,200 | 6,149,217 | 2,611,167 |
| 2 | signature lower | 512 | 637,636,608 | 594,894 | 197,358 |
| 3 | r^2 | 18,944 | 3,907,768,320 | 11,076,533 | 5,144,194 |
| 3 | master lower | 12,288 | 9,761,292,288 | 11,104,312 | 4,400,040 |
| 3 | signature lower | 512 | 639,442,944 | 616,152 | 191,502 |
| 4 | r^2 | 25,088 | 5,175,152,640 | 14,644,679 | 6,910,750 |
| 4 | master lower | 16,384 | 13,028,032,512 | 13,324,760 | 5,549,316 |
| 4 | signature lower | 512 | 640,647,168 | 691,368 | 215,418 |

The first runs execute 95,232 actual scalar draws and use 28,680,631 bytes.
An additional 95,232 draws replay the identical streams with the original
scalar sampler and no aggregate cap. All outputs match item by item; no
sampling abort occurred. Each of the nine aggregate scalar TV bounds is at
most `2^-96`, including the additional budget-abort contribution at most
`2^-128`. Exact fractions, stream labels and output hashes are in
`build/outputs/srgg-bridge-2026-10-16/aggregate-budget.json`.

Single first-run durations range from 0.110 to 5.490 seconds. These times are
scalar batch measurements; they exclude a Gaussian factor, key generation,
Extract, Sign, and Verify. The verified environment is WSL2 Ubuntu 24.04,
SageMath 10.9, Python 3.13.15 on Intel Core Ultra 7 255HX. There is one fixed
stream per row and one exact replay; this is not a statistical distribution
test or a throughput benchmark for a full IBS.

## Phase byte accounting, without phase execution

`phase_certificate` records all scalar calls and the current explicit 128-bit
midpoint continuous ticket profile. The master count is `2*d*n` rounding
calls, `w*d*n` lower calls and `w*d*n` original gadget CDF calls. A signature
attempt uses `(columns+1)*n` calls at `r^2`, `n` lower calls and `columns*n*16`
fixed continuous-ticket bytes. It multiplies these by the declared maximum
signature attempts. The master fixed ticket count is `2*d*n*16` bytes. These
ticket counts do not certify continuous numerical correctness or TV.

Each of at most three scalar groups receives `K+2` additional-budget bits;
their sum is at most `2^-K`. Gadget sampling keeps the original `TableOptions`
(tail 80, mass 128, precision 192, max trials 128) and all exact CDF masses.
Only its uniform-ticket count receives the success-count bound. There is no
silent change to a higher-precision gadget distribution.

| d | Phase | Old all-path bytes | Selected total bytes | Scalar-kernel TV upper, approximate |
|---:|---|---:|---:|---:|
| 2 | master | 5,360,435,200 | 8,014,657 | 3.84866e-21 |
| 2 | signature, 1 attempt | 2,855,723,008 | 7,080,803 | 4.30467e-35 |
| 2 | signature, 16 attempts | 45,691,568,128 | 110,317,817 | 6.88725e-34 |
| 3 | master | 10,421,772,288 | 13,859,696 | 5.77298e-21 |
| 3 | signature, 1 attempt | 3,913,764,864 | 10,157,502 | 6.21115e-35 |
| 3 | signature, 16 attempts | 62,620,237,824 | 159,478,456 | 9.93761e-34 |
| 4 | master | 13,908,672,512 | 16,969,506 | 7.69731e-21 |
| 4 | signature, 1 attempt | 4,971,204,608 | 13,288,285 | 8.11762e-35 |
| 4 | signature, 16 attempts | 79,539,273,728 | 209,334,771 | 1.29880e-33 |

All selected totals fit within 256 MiB. The master scalar error is dominated
by the retained old gadget tail bound; it does not meet the nine wide-scalar
batches' `2^-96` bound. These rows are accounting certificates, not executed
n512 phases. `implemented_n512_phase=false` and
`full_n512_sampler_implemented=false` describe this helper's scope.

## Reproduction and acceptance

From the repository in the specified WSL environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_aggregate_budget.py \
  --junitxml=build/outputs/srgg-bridge-2026-10-16/aggregate-budget-tests.junit.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.srgg.aggregate_budget --draw \
  --output build/outputs/srgg-bridge-2026-10-16/aggregate-budget.json
```

Result: **25 passed, 0 failed, 0 skipped**. Coverage includes exact iid and
history-dependent probability calculations, all nine actual width classes,
all phase counts, matching capped/plain scalar draws, input preflight, and
fail-closed byte reads. A forced nonuniform stream additionally drives each
scalar toward its 500th proposal, within the old Gaussian limit, until the
new batch cap aborts. That forced path verifies code behavior only and does
not instantiate the probability assumptions.

There is no identity, message, H1/H2 or random-oracle experiment in these
helpers. The scalar mechanism itself does not use a ROM. It neither proves
IBS security nor imports Kyber/ML-KEM security levels. Security flags remain
`security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`.
