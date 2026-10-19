# Wang–PW numeric MP12 root-basis / block-delegation prototype

Status: **WIP research prototype**, not a security-admitted IBS and not a
128-bit parameter claim.  The exact toy source `src/ibme/ibs/wang_pw.py` is
not modified.

## What was reused

`src/ibme/lattice/chkp/root_basis.py::private_root_basis` is the deterministic
MP12 Lemma 5.3 full-basis conversion for

```
A = [Abar | G - Abar R],   T = [[I, R], [0, I]],   A T = [Abar, G].
```

It turns the gadget kernel columns into a complete short basis of
`ker(A mod q)` without LLL or AP09.  The prototype uses that formula directly
and then the block delegation

```
T_id = [[T_A, X], [0, I_w]],   A x_j = -H1 e_j.
```

`root_basis_numpy.py` is a dense float64 BLAS implementation of the same
formula.  For q=2^32 every intermediate is below 2^53, so the products are
exact.  It reproduces the Sage widths at n=64 (405.082, build 0.24 s) and n=128
(576.152, build 1.04 s); the n=16 regression is in
`tests/test_wang_pw_root_basis_numpy.py`.

The GS width of `T_id` is the same as that of `T_A` in the experiments below.

## Numeric sampler

`numeric_gpv_ibs.py` uses a float QR Gram–Schmidt of the basis and batched
rank-1 updates for GPV coset sampling.  This is a **numeric research sampler**,
not the exact finite discrete-Gaussian reference: coordinates are rounded
normal draws, and no distribution/security claim is made.

`numeric_gpv_mp.py` splits the independent `X` columns over 16 worker
processes.  On the 16-vCPU server the n=64 `X` phase took **572.93 s** wall
time (16 workers, ~100% each), versus roughly 59 min for one process.

`gpv_kernel.c` is a C/OpenMP implementation of the same column recurrence,
called through `gpv_kernel.py`.  It uses Fortran-order `B`, `star`, `P`, `X`
arrays and per-thread xorshift/Box-Muller normals.  On the same server the
n=64 `X` phase drops to **4.1 s** (16 threads), a ~140x speedup; n=16 is 0.19 s.
The n=512 phase is therefore expected in tens of minutes rather than days.
The `.so` is built on import if absent; it is not committed.

## Retained parameter profiles

Both n=512 profiles are kept and reproducible:

| profile | s0 | width | sign norm | SIS classical/quantum | relation to thesis |
|---|---:|---:|---:|---:|---|
| conservative | 4 | 1146.026 | 466193.54 | 127.02 / 115.28 | thesis-aligned asymptotic choice |
| narrow | 2 | 576.364 | 130978.66 | 169.36 / 153.70 | below asymptotic s0=4; finite study |

Commands:

```text
# conservative, s0=4
python -m experiments.research.wang_pw_numeric.numeric_gpv_np_mp 512 16 4

# narrow, s0=2
python -m experiments.research.wang_pw_numeric.numeric_gpv_np_mp 512 16 2
```

Evidence: `evidence/n512-s0-4-short.json` and `evidence/n512-s0-2.json`.
The numeric sampler, s0=2 caveat and the absence of a formal proof apply to
both; neither is a formal 123.5-bit admission.

## Measured runs

Parameters: `q = 4294967291` (32-bit prime), `s0 = 4`, `m_bar = w = n*32`,
`q`-bit gadget, `M = m + w`.  All equations checked; `eq=True` means
`F_id z = h2 mod q`.

| n | m | M | root basis width | sign norm | sign eq |
|---:|---:|---:|---:|---:|---|
| 4 | 128 | 192 | 23.5 | 1167 | True |
| 8 | 512 | 768 | 44.4 | 2186 | True |
| 16 | 1024 | 1536 | 204.2 | 3280 | True |
| 32 | 2048 | 3072 | 288.0 | 4717 | True |
| 64 | 4096 | 6144 | 405.1 | 7105 | True |

The n=64 run used the multiprocess path; n≤32 used a single process for `X`.

### Width scaling (root + QR only)

| n | m | M | width | root build | QR |
|---:|---:|---:|---:|---:|---:|
| 128 | 8192 | 12288 | 576.152 | 1.04 s | 12.2 s |
| 256 | 16384 | 24576 | 813.018 | 6.28 s | 45.1 s |

`root_width.py` measures this without the expensive `X` phase.  The n=256
width implies, if the n=512 width stays near 1150, a signature bound
β ≈ 1150·√49152 ≈ 2^18, which the SIS scan puts at about 130.9 quantum bits
for n=512/q32.  This is a projection, not a measurement or a security claim.

### s0 = 2 width scaling

The trapdoor width `s0=4` was the asymptotic conservative choice.  The finite
root basis is linear in `s0`:

| n | M | width (s0=2) | width (s0=4) |
|---:|---:|---:|---:|
| 64 | 6144 | 204.752 | 405.082 |
| 256 | 24576 | 410.607 | 813.018 |
| 512 | 49152 | 576.364 | 1146.026 |

n=64 full with `s0=2`: width 204.752, sign norm 16072.83, beta 2^13.97,
eq True.

### n=512/s0=2 final run

```text
setup_root    41.49 s
numeric_gs   715.43 s   width 576.364
particulars   17.91 s
X_c         3073.90 s   (16 OpenMP threads)
block_gs    1903.03 s   width 576.364
sign         130.50 s   sigma_sign=576.364
sign norm  130978.66    = 2^16.999
eq          True
```

The width bound is 576.364·sqrt(49152)=127730=2^17.96; the sampled norm is
2.5% above that bound.  At the **actual** norm the SIS scan gives
**169.36 classical / 153.70 quantum**, which is above the user's 123.5
threshold with margin.

`s0=2` is a research parameter below the thesis's asymptotic `s0=4`; the
result is a numeric-sampler measurement under the project's work assumption,
not a formal 123.5-bit proof.

### n=512/q32 measured width (s0=4)

```text
n=512  q=4294967291  m=32768  M=49152
root build (numpy)   123.89 s
QR mode='r'          759.54 s (4 threads)
width                1146.026
kernel check         ok
β = width·sqrt(M)    254076.83 = 2^17.955
SIS (ADPS16)         145.42 classical / 131.97 quantum
```

This is a **width/bound estimate**, not a security proof; the GPV smoothing
factor is not separately certified and the sampler is numeric.  The actual
full run shows that the sampled norm can exceed `width*sqrt(M)`, so the
131.97 figure is not the realized signature bound.

### Full n=512/q32 lifecycle (first run, old particular)

```text
setup_root    41.56 s
numeric_gs   699.30 s   width 1146.026
particulars   17.97 s   (gadget trapdoor P=[R D;D])
X_c         3065.23 s   (16 OpenMP threads)
block_gs    1863.19 s   width 1146.026
sign         127.80 s   sigma_sign=1146.026
sign norm  571750.69    eq True
```

The actual norm is 2.25x the width bound.  At β=571750.69=2^19.125 the same
SIS scan gives **121.47 classical / 110.24 quantum**, i.e. **below 123.5**.
The first run used the old `_gf_solve` particular; the short gadget particular
`[R d; d; 0]` is now implemented and a fresh n=512 run is in progress to see
whether the norm returns to the width bound.  No 123.5 claim is made from the
first run.

### Short-particular rerun (s0=4)

```text
sign norm  466193.54 = 2^18.83
eq         True
SIS        127.02 classical / 115.28 quantum
```

The short particular reduced the norm by 18.4% but did not reach the width
bound.  The user accepted this 115.28-quantum point as close enough for the
project, on the explicit understanding that it is a research measurement, not
a 123.5-bit proof.  The s0=2 full run below is the attempt to improve it.

n=256/q32 with the short particular: width 813.018, sign norm 130611.39
(beta 2^16.96), eq True; SIS 60.74/55.12, far below 128 because n=256/q32 is
too small.

`sis_scan.py` contains the surrounding n=256/512 q32/q64 scan.  The exact
β=254076.83 row gives 145.42/131.97 with `norm=2` and the minimum attack cost,
but that is a width-bound row, not the measured norm.

## Commands

```text
# single process, n=4..32
PYTHONPATH=src:. python -m experiments.research.wang_pw_numeric.numeric_gpv_ibs 16 4294967291

# multiprocess X sampling, n=64
PYTHONPATH=src:. python -m experiments.research.wang_pw_numeric.numeric_gpv_mp 64 16
```

## Open items

- n=128/256/512 scaling; n=512 needs int32/float32/block storage and a
  `q≈2^64` arithmetic path (NumPy int64 cannot hold q or `A@p`).
- Replace rounded normals with an admitted discrete Gaussian if distribution
  evidence is required.
- Measure `s1(T_id)`/β and run the SIS estimator before any parameter or
  security statement.
- The 64-bit gadget and `q=2^64` root-basis construction are not yet
  implemented in the numeric path.
