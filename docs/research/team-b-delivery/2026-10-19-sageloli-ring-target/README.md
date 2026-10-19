# Shorter and Faster Identity-Based Signatures with Tight Security in the (Q)ROM from Lattices

Éric Sageloli, Pierre Pébereau, Pierrick Méaux, Céline Chevalier. Frozen source: HAL v1, DOI `10.1007/978-3-031-33488-7_24`. Team B engineering delivery, 2026-10-19. See the [source and implementation map](SOURCE_MAP.md) and [Chinese README](README_zh-CN.md).

Both complete Table 6 RSIS profiles were actually executed: Setup, every identity-key column, two signatures and verification, ten negative controls, and independent-process recovery followed by a new signature. Recovery of the issued key consumed zero entropy for both profiles. This is an independent IBS delivery; default registry/CLI selection and a real HIBE composition remain integration work.

## Implementation

The explicit [v3 structured ring backend](../../../../experiments/research/candidates/sageloli/ring/) stores polynomial coefficients instead of expanded rotation matrices. Its canonical big-integer codec supports 104/243-bit public coefficients. A Fourier low-rank SampleF implementation avoids the full coefficient-space covariance; its largest eigendecomposition is k by k. It retains correlated perturbations, genuine arbitrary-center discrete Gaussian rounding, all ternary coset Gaussian digits, and exact output equations.

Public large-integer products use FLINT; small signed polynomial matrix products use range-checked two-prime NTT/CRT. The scheme modulus remains `3^k`. Fixed issuance uses a durable pending marker, atomic state publication and context/parameter pins. Recovery verifies the root and every column of every issued key. The original v2 SIS/RSIS engines and states remain separate; this implementation does not add another literature route.

## Actual measurements

Each profile used one independent operating-system random state. Identity: 21 B; first message: 33 B; second message: 34 B; new message after recovery: 42 B. Fresh and recovery runs used distinct processes. MiB/GiB below use powers of two; receipts contain exact byte counts.

| Measurement | Param I | Param II |
|---|---:|---:|
| `(d,k,l)` | `(2048,65,132)` | `(2048,153,308)` |
| Setup | 4.993 s | 43.554 s |
| Full Extract | 85.135 s / 65 columns | 520.232 s / 153 columns |
| First Sign, including plan preparation | 9.285 s | 38.611 s |
| Second Sign with cached key plan | 2.016 s | 5.017 s |
| First Verify | 0.517 s | 1.362 s |
| Fresh process peak RSS | 1.361 GiB | 6.194 GiB |
| Recovery process peak RSS | 1.366 GiB | 6.262 GiB |
| Public wire | 3.352 MiB | 18.649 MiB |
| Signature wire | 3.078 MiB | 7.203 MiB |
| Identity-key wire, including public key | 137.415 MiB | 754.961 MiB |
| Master state, including one issued key | 149.272 MiB | 819.929 MiB |
| Honest signatures / ten negative controls | all passed | all passed |
| Recovery / new signature | passed, zero recovery entropy | passed, zero recovery entropy |

Negative controls cover identity, message, response, both salts, public context, zero response, truncation, append and duplicate fields. The persistent master state includes the identity ledger; it is not the paper's root-only msk. Signatures use int64 slots and public coefficients use byte-aligned slots, not entropy-optimal compression. These wire sizes are not direct reproductions of the paper's Table 7 counting model.

These are single-run engineering feasibility measurements, not an isolated fair benchmark. Other research processes were active. Host: Intel Core Ultra 7 255HX; WSL Ubuntu 24.04 with about 15 GiB RAM; Sage 10.9 / Python 3.13.15, NumPy 2.5.3, g++ 13.3.0; OpenBLAS and OMP each set to four threads. Fresh runs took about 106.29/620.23 s overall and consumed 13.03/69.78 GB of random-source bytes.

Fresh I/II used frozen source `78f3267`/`03b0e5e`. Final guard fixes are in `c29b45d`: extreme input ranges, actual entropy-byte counts, checks under optimized Python, and removal of private spectral statistics from public certificates. Both profiles were restored and signed again with that final computation version and its rebuilt native library. The first-run timing rows remain tied to their original commits. Public [receipts and historical source snapshots](evidence/) preserve this distinction.

## Reproduction

Run in the repository root with the prescribed WSL Sage environment, existing g++, and FLINT/GMP development files from the Sage prefix:

```bash
export PYTHONPATH=src:. PYTHONDONTWRITEBYTECODE=1
export OPENBLAS_NUM_THREADS=4 OMP_NUM_THREADS=4
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.native \
  --directory ~/.cache/ibme-native-tools/sageloli-ring-v3
```

Use its returned path as `NATIVE_SO` and the actual source commit as `SOURCE_COMMIT`. Use new private and output paths, retaining failed state and pending markers:

```bash
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.run \
  --profile I --mode fresh --native NATIVE_SO --source-commit SOURCE_COMMIT \
  --private-directory ~/.cache/ibme/sageloli-v3/new-I-01 \
  --output test-results/sageloli-new-I-fresh.json
~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.sageloli.ring.run \
  --profile I --mode recover --native NATIVE_SO --source-commit SOURCE_COMMIT \
  --private-directory ~/.cache/ibme/sageloli-v3/new-I-01 \
  --output test-results/sageloli-new-I-recover.json
```

For Param II, change the profile, private directory and output names. Default guards are four hours, 12 GiB peak process RSS and a 256 GiB entropy-byte budget. Time/RSS guards run at stage callbacks, not at every OS instruction. Private states, keys, signature samples and sampling plans are excluded from this delivery.

```bash
python docs/research/team-b-delivery/2026-10-19-sageloli-ring-target/verify.py
python -O docs/research/team-b-delivery/2026-10-19-sageloli-ring-target/verify.py
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ~/miniconda3/envs/sage/bin/python -m pytest -q \
  -p no:cacheprovider tests/test_sageloli_*.py tests/sageloli_native
```

The completed regression is **180 passed, zero failed/error/skipped, 218.66 s**. It covers legacy and new implementations, strict encoding, independent exact-ring comparisons, Gaussian math checks, actual signing, fixed issuance and damaged/faulted recovery. The [JUnit report](evidence/tests.xml) lists individual results. An earlier invocation was interrupted by a BrokenPipe output error and is retained locally, not counted as passing; these are the complete rerun results. Small-profile fresh and independent recovery runs also passed under `python -O`.

Default CI selects v2 and the new structured-math tests. Native compilation, `tests/sageloli_native`, and full parameter runs are explicitly executed with the commands above; a CI plan is not a large-parameter execution receipt.

Changed files comprise the `ring/` implementation, `tests/test_sageloli_ring_structured.py` and `tests/sageloli_native/`, the public evidence exporter, this directory's bilingual README/source map/verifier/receipts, and the v2 contract's new-version link. Upstream `b92967b` was merged before publication; other algorithms and the default registry were not changed.

## Claims and scope

Paper security is the project's working premise. Table 6/Appendix E widths are evaluated with outward-rounded integer squares. The combined error of floating eigendecomposition, FFT and the finite continuous grid is uncertified. Metadata remains `none/false/false`; this delivery does not assign NIST categories or re-estimate security bits. The paper's two profiles are not equivalent security targets.

The missing target-size encoding and runnable sampler are now implemented and measured. Default public integration, actual HIBE pairings and common-condition system comparisons remain separate acceptance work.
