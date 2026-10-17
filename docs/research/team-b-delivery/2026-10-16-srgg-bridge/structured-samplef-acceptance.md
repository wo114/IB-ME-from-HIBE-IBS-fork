# Independent structured SampleF acceptance

Date: 2026-10-16. This record concerns the opt-in perturbation component in
`structured_samplef.py` and its independent tests. A working perturbation
sampler is distinct from a complete n512 Extract/Sign/Verify lifecycle.

## Checks performed

`tests/test_srgg_structured_samplef.py` contains **39 passing tests, no failures
or skips**, run in the specified WSL Sage environment. The independent checks
include:

- Every basis vector of the exact `H = nu*T*T*/a` action against an independently
  constructed negacyclic coefficient matrix, for both public witness classes.
- The square-root series action against Sage's independently computed
  generalized-binomial dense polynomial. Its rounding discrepancy fits the
  reported bound. The polynomial's squared residual fits the truncation bound.
- A zero-witness analytic square-root check using real intervals.
- Actual deterministic SampleF draws, exact integer translation under the same
  byte stream, and a system-random draw without persisting its output.
- Equal public certificates across distinct private witnesses in the same
  support class and across private centers; redacted repr and defensive copies.
- Exact public support/norm-cap validation, contraction and dimension limits,
  term/product/entropy budgets, scalar rational reserves, malformed centers,
  malformed entropy and absence of fallback.
- A real small signature-perturbation fixture whose receipt explicitly says
  that no IBS lifecycle or sampled user key is involved.

These are implementation and algebra-mapping checks, not a cryptographic
security proof. The root's separate numerical/theorem review owns the general
series and integer-TV argument.

## Actual public fixtures

The public master fixtures use the sampler module's fixed deterministic CBD1
witness. The signature fixture uses coefficients `((11*i+7*j)%3)-1`. It is a
bounded public input, not an issued key. The signature plan is parameterized by
the candidate's already declared `user_norm_squared_cap` and `noise_factor=2`;
it does not publish a private norm or tune the certificate to the actual input.

The arithmetic inputs are `conditional_candidate(n,d,w)`, retaining `b=31`,
`r^2=64`, and the existing isotropic candidate target widths. They are not
formally admitted parameters. Every row below is one actual integer-vector
draw, not a throughput average or a norm-acceptance estimate.

| Fixture | n,d,w | Output dimension | Terms | Prepare s | Draw s | Entropy cap B | Process peak RSS KiB |
|---|---|---:|---:|---:|---:|---:|---:|
| master | 16,1,3 | 80 | 197 | 0.10203 | 0.12239 | 126,330 | 213,340 |
| master | 32,1,3 | 160 | 197 | 0.10152 | 0.20814 | 177,910 | 213,608 |
| master | 512,2,8 | 10,240 | 197 | 0.26476 | 9.03995 | 6,677,020 | 231,752 |
| signature perturbation | 512,2,8 | 10,752 | 257 | 0.25145 | 9.62128 | 7,007,133 | 230,492 |

The two n512 peak values are from `/usr/bin/time -v`, including Sage startup
and process teardown. The n16/n32 values use `resource.getrusage` at receipt
creation. The signature runner measured 229,708 KiB before final serialization;
the outer tool measured the larger 230,492 KiB in the table. Total process wall
times for n512 master/signature were 10.61/15.60 s. The signature process ran
while the small fixtures were also running, so this record does not claim an
isolated benchmark or use the numbers to rank full schemes.

All rows include the explicit initial dyadic-normal quantization introduced by
the numerical review. The master and signature n512 certificates' conditional
integer-target TV bounds, including scalar and budget aborts, are approximately
`3.81333088e-35` and `4.26325594e-35`. Exact fractions and stated MPFR,
independent-uniform-byte, spectral and smoothing assumptions remain in the
JSON certificates. A fixed deterministic stream verifies execution and replay
properties; it does not satisfy or test the independent-uniform-byte premise.

The n512 vector digests are:

```text
master:    c5fef7536134ae9d38c020b64cbb21922f57d97fbb2fd524e77201773d4d833f
signature: d5360df0599e026a085c3ceb782ed3a4346e98c3bc0bd4ba653d47300bf490b9
```

No complete output vector, live service root, identity, message, key or
signature is published. There was no H1/H2 or random-oracle experiment.

## Receipts and source version

Output directory: `build/outputs/srgg-bridge-2026-10-16/`.

```text
structured-samplef-tests.junit.xml
structured-samplef-n16-current.json
structured-samplef-n32-current.json
structured-samplef-n512.json
structured-samplef-n512.time.txt
structured-samplef-signature-n512.json
structured-samplef-signature-n512.time.txt
```

The `-current` small receipts and signature receipt were made with
`experiments/research/srgg_structured_samplef_execution.py`. They contain the
environment, loaded project-source hashes, unchanged-source check, dimensions,
public cap, output digest and the full public conditional certificate. Their
recorded `structured_samplef.py` SHA-256 is
`8a4a82baea93b62a13f215d53d866eff5f6d083563a81dc9b21b51999931c10a`.
The initial master n512 run used the module CLI rather than this runner; its
receipt confirms the updated dyadic-normal profile, and the same source hash
was observed immediately afterwards. It has no independent pre-run source-hash
snapshot. No old receipt was edited to add one. Earlier small receipts without
the `-current` suffix were superseded by these current-profile executions.

Environment: WSL2 Ubuntu 24.04, SageMath 10.9, Python 3.13.15, Intel Core Ultra
7 255HX. No new dependencies or network installation were used.

## Reproduction

From the repository in WSL, using `~/miniconda3/envs/sage`:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_structured_samplef.py \
  --junitxml=build/outputs/srgg-bridge-2026-10-16/structured-samplef-tests.junit.xml
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.srgg_structured_samplef_execution \
  --mode master --degree 16 --rank 1 --digits 3 \
  --output build/outputs/srgg-bridge-2026-10-16/structured-samplef-n16-current.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.srgg_structured_samplef_execution \
  --mode master --degree 32 --rank 1 --digits 3 \
  --output build/outputs/srgg-bridge-2026-10-16/structured-samplef-n32-current.json
/usr/bin/time -v -o build/outputs/srgg-bridge-2026-10-16/structured-samplef-n512.time.txt \
  timeout 240s env PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.srgg.structured_samplef \
  --degree 512 --rank 2 --digits 8 --draws 1 \
  --output build/outputs/srgg-bridge-2026-10-16/structured-samplef-n512.json
/usr/bin/time -v -o build/outputs/srgg-bridge-2026-10-16/structured-samplef-signature-n512.time.txt \
  timeout 240s env PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.srgg_structured_samplef_execution \
  --mode signature --degree 512 --rank 2 --digits 8 \
  --output build/outputs/srgg-bridge-2026-10-16/structured-samplef-signature-n512.json
```

This sampler evaluates a joint perturbation distribution. It does not preserve
the legacy sequential Schur finite law, and does not silently replace that
backend. Completing gadget sampling, matrix relations, HNF recovery and all
norm/failure gates into a full n512 IBS remains separate work. Source PSF and
strong-security correspondence, final service budgets and formal attack-cost
estimation also remain independent obligations. All security flags retain
`none/false/false`; no NIST or Kyber/ML-KEM level is claimed.
