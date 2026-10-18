# SRGG Table 4 Setup backend gap: zero-atom diagnostic (WIP)

This is the **third and last bounded route** for comparing the paper's
mathematical positive-definiteness gate `A` with successful preparation by the
current source-Schur backend `B`. The direct `A ⇒ B` route lacks a uniform
finite-precision argument. A narrower spectral threshold would need a proved
margin-to-success lemma before its moment tail could bound backend failures.
This route instead certifies one accepted atom and stops; it makes no claim
that the remaining positive roots work.

For each original Table 4 row (`n=512`, `w=2`, `d=2/3/4`), all-zero CBD1
witness coefficients have exact probability `2^-M`, where
`M = (2d)(wd)n = 8192/18432/32768`. The zero witness has Fourier operator
norm zero and hence satisfies the strictly positive mathematical residual.
The [six-row receipt](setup-backend-gap.json) also replays the **complete**
`SourceSchurBackend.setup` with a zero 32-byte public seed and zero witness
bytes. One attempt succeeds and serializes a public key under both explicit
Gaussian-width interpretations. With independent uniform bytes and no external
machine fault, this yields

`Pr_R[A ∩ ¬B_plan] ≤ 1−2^-M`, and
`Pr_{seed,R}[A ∩ ¬B_full] ≤ 1−2^-(M+256)`.

These strict bounds are extremely close to one. They provide **no useful
64-attempt failure budget**. Setup samples its seed once, and non-geometry
preparation errors terminate the call; exponentiating the full first-attempt
bound by 64 would be invalid. Uniform backend acceptance for *all* positive
roots, numerical-fault probabilities, and the complete fault/history law
remain `null` in the receipt. This execution and probability argument do not
establish an IBS security claim, formal parameters, or a NIST category.

The frozen source is Jia–Liu–Tang–Wang, *Constructing Efficient Identity-Based
Signatures on Lattices*, Algorithm 1 and Table 4,
[`papers/2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf),
SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.
The original widths are unchanged. This standalone Setup check uses no HIBE,
identity, message, signing query, or ROM security reduction. It is a
deterministic one-atom diagnostic, not a performance measurement.

Run from the repository root using the prescribed WSL Sage environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_setup_backend_gap.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-setup-backend-gap/verify_delivery.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -O docs/research/team-b-delivery/2026-10-18-srgg-setup-backend-gap/verify_delivery.py
```

The [validation record](validation.json) and [manifest](MANIFEST.json) bind the
reported run and selected source bytes; the verifier also replays all six rows.
The manifest includes directly used SRGG modules and several cross-package
dependencies, but does not claim a complete Python/Sage import closure.
Security markers are `security_claim=none`,
`backend_admitted=false`, `parameters_are_formal=false`, and
`nist_security_category=null`.
