# SRGG Table 4 compact encoding and measured memory/time

Source: Jia, Liu, Tang and Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI `10.1049/ise2/6684889`. This package adds lossless transport/snapshot encoding and measures the existing implementation; it is not a new signature scheme or reproduction of the author's C/rANS performance. [Chinese report](README_zh-CN.md).

## Implementation

The optional [compact v1 format](../../../specs/srgg-paper-compact.md) covers public keys, masters with issuance state, user keys and signatures. Decoders return the existing object classes. Original JSON bytes, public context, H1/H2 inputs, sampler sources, parameters, norm gates and default FixedIssuer storage are unchanged.

Fields use 24-bit public residues, 2-bit CBD1 witnesses, exact signed zigzag vectors and 1-bit challenges. No response reduction, tail truncation, quantization or resampling occurs. The parser checks version/type/source/profile/context, canonical widths and padding, identity ordering, pending/failed/issued state, truncation/appending and the 2 MiB wire limit. The Python codec is not constant-time and does not encrypt snapshots.

## Paired object sizes

Medians across three independent SecureRandom roots per profile, in **bytes**. Both formats encode exactly the same objects. User keys include public keys; masters include public data, witness and one issued-key cache. These complete envelopes are not ranked against the paper's isolated compressed components.

| Profile | Public JSON → compact | Master JSON → compact | User key JSON → compact | Signature JSON → compact |
|---|---:|---:|---:|---:|
| PARAM-I | 34,463 → 12,374 | 102,606 → 20,306 | 84,165 → 18,256 | 35,368 → 13,400 |
| PARAM-II | 76,954 → 27,734 | 218,520 → 41,106 | 176,919 → 36,496 | 51,117 → 19,288 |
| PARAM-III | 136,433 → 49,238 | 377,344 → 69,074 | 303,453 → 60,880 | 67,076 → 26,264 |

Paired median size ratios are approximately 2.77–2.79 for public keys, 4.61–4.98 for user keys, 5.05–5.46 for masters and 2.55–2.65 for signatures. These are separate from the historical 512-fold ring-matrix slot ratio. Raw sizes are in [wire.csv](wire.csv) and [benchmark.json](benchmark.json).

## Latency and memory

The unchanged Table 4 profiles use `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`, the existing `table-standard-deviation` interpretation and default numerical precision. Identities are 64 bytes and messages are 32 bytes. Each of three roots performs Setup, Extract, an initial signature and three warm sign/verify pairs. Warm calls retain the existing component cache but rebuild Schur plans as the original backend does. Times below are **seconds**; warm values are per-root medians, then medians over roots.

| Profile | Setup | Extract | First sign | Warm sign | Warm verify |
|---|---:|---:|---:|---:|---:|
| PARAM-I | 0.522202 | 2.144220 | 2.490755 | 2.504978 | 0.009441 |
| PARAM-II | 1.389869 | 3.801864 | 4.864011 | 4.857877 | 0.020839 |
| PARAM-III | 3.174095 | 6.828144 | 8.965721 | 8.822885 | 0.034445 |

Each root also starts separate JSON and compact restore interpreters, reloads four objects, reuses the issued key without issuance entropy and signs again using fresh SecureRandom. Restore order alternates by root. Cold means a fresh interpreter with retained OS page cache; whole-process time includes imports, reads, validation and the new signature, rather than isolated decoding.

| Profile | Generation tree RSS median / max MiB | JSON restore median MiB | Compact restore median MiB |
|---|---:|---:|---:|
| PARAM-I | 238.055 / 238.121 | 234.750 | 234.637 |
| PARAM-II | 267.289 / 334.172 | 261.992 | 261.887 |
| PARAM-III | 307.320 / 307.691 | 299.680 | 299.156 |

An external observer samples the process tree through `/proc` every 10 ms. It may miss spikes or count shared pages twice; it is not a physical-RAM upper bound. Worker lifetime `ru_maxrss` is retained separately and is not subtracted to infer phase-local allocation. The PARAM-II 334 MiB observation occurred during imports with a transient child process and was retained. Generation includes both codecs, not only sampler work. See [memory.csv](memory.csv), [timings.csv](timings.csv), [tables.md](tables.md) and raw samples.

**Smaller wire objects did not yield a comparable algorithm-memory reduction.** Loading restores the same tuple/Sage objects. Complete compact APIs were also slower: PARAM-I user-key JSON/compact encoding took 0.462/14.169 ms and decoding 15.062/32.318 ms; PARAM-III took 2.283/59.507 ms and 68.102/151.939 ms. These include each API's actual validation and canonical re-encoding, rather than isolated bit-pack costs. Whole cold restoration did not show a consistent latency direction across profiles; no general speedup is claimed.

## Execution and evidence

- Intel Core Ultra 7 255HX, WSL2 Linux 6.18.33.2, Sage 10.9/Python 3.13.15, OMP/OpenBLAS one thread. Benchmark workers run serially; unrelated host work and CPU frequency are not isolated.
- Fixed schedule: nine roots, nine generation and eighteen restoration processes; **27/27 passed**. There were 54 successful signatures and 72 explicit verification calls, plus the original sign method's internal checks. The 495 functional checks include repeated codec roundtrips, not independent security trials.
- Codecs are warmed by one unmeasured roundtrip, followed by five alternating paired repetitions. SecureRandom calls are blocked during codec work. Original 64-attempt operational limits and actual attempt counts remain; external failures are not replaced or discarded.
- Runtime source commit `87f572a1a7636a8b83c9e693ebe359ef185d2d92`; 122 source/paper hashes are unchanged during measurement. Relevant new/legacy tests: **183 passed**. The development smoke is separate from the nine-root schedule.
- Public records contain configuration, booleans, lengths, timings/RSS, counters and source fingerprints only. Private objects, randomness, snapshot contents and their hashes remain unpublished. Default FixedIssuer locks/fsync/capacity/migration are unchanged and not benchmarked here.

[benchmark.json](benchmark.json), [provenance.json](provenance.json), [validation.json](validation.json) and [MANIFEST.json](MANIFEST.json) bind this delivery. Read-only verification needs the repository and Python's standard library, no Sage or entropy:

```text
python docs/research/team-b-delivery/2026-10-18-srgg-compact-benchmark/verify_delivery.py
python -O docs/research/team-b-delivery/2026-10-18-srgg-compact-benchmark/verify_delivery.py
```

For actual reruns, select fresh directories, with private output under ignored `build/outputs`:

```text
PYTHONPATH=src:. OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.compact_benchmark --private-directory build/outputs/srgg-compact-repeat/private --output build/outputs/srgg-compact-repeat/public/benchmark.json --source-commit <40-character-runtime-source-commit> --repetitions 3 --warm-repetitions 3 --codec-repetitions 5
```

`render_tables.py` regenerates summaries without sampling. HIBE, shared registry/CLI and default-service migration are outside this batch. Original Table 4 inputs, frozen sampler sources and JSON context remain unchanged. Security markers remain `none/false/false/null`; this delivery establishes lossless encoding and bounded-environment measurements, not a new security level, distribution theorem, author C/rANS reproduction or equal-security advantage.
