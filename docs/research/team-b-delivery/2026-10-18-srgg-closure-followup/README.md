# SRGG original-parameter closure follow-up (WIP)

Paper: Jia, Liu, Tang, and Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI `10.1049/ise2/6684889`; frozen [PDF](../../../../papers/2025_efficient_ibs_jia.pdf), SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`. Baseline commit: `e38b2ea`. The original Table 4 inputs remain `n=512,p=16383,b=31,w=2,q=961,Q=15744063,d=2/3/4`. This package concerns the standalone IBS, with no HIBE change.

The [six fixed-root numerical receipts](schur-fixed-root-numerical-normalizer.json) independently replay the ideal Schur pivots and certify local gain/covariance errors at most `2^-128` and same-successful-history center error at most `2^-96`. Every replayed ideal pivot eigenvalue exceeds the coarse density-shape floor 64. An all-center Poisson bound then limits the **ideal sequential discrete** versus **ideal joint discrete** normalizer bias to `2^-278/2^-277` (PARAM-I master/sign) and `2^-277/2^-276` (PARAM-II/III). The finite implementation's complete integer-output TV, accepted-root uniformity and full issuance/signature law remain unknown.

The [Setup preflight](setup-conditioning.json) derives the exact positive-definiteness threshold and a finite 64-attempt requested-byte envelope. Ordinary matrix Bernstein is vacuous on all three rows. One independent sparse event proves only minute one-attempt success floors, `2^-6371/2^-15031/2^-27375`; these do not close the actual abort budget or accepted-root distribution. The [prime-square CRT receipt](ring-crt-31sq.json) constructs all sixteen degree-32 Hensel factors and idempotents modulo `31²`, then checks projection and reconstruction. It does not infer structural attack work factors. The [history-law helper](../../../../experiments/research/candidates/srgg/paper_history_law.py) gives a conditional adaptive hybrid through `2^40` transitions, but its actual SRGG inputs are null.

[Resource observations](resource-observations.md) record all seven earlier real runs, object sizes and one-call hard entropy caps. [Source/security review](source-and-security-review.md) documents the original notation, smoothing issue, modulus and ζ mapping, and the native-strong same-message replacements. The seven original lifecycle receipts and earlier failures are preserved. Author C/ANS/1000-run performance, peak memory, lifetime entropy, full structural costs and formal parameter admission remain open.

Reproduce in the prescribed WSL Sage environment from the repository root:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_ring_crt_lift --output build/recheck-ring-crt.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_setup_conditioning > build/recheck-setup-conditioning.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_schur_numerical_audit --output build/recheck-schur-numerical.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py
```

Use fresh output paths; the commands do not overwrite existing receipts. The security markers remain `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, and `nist_security_category=null`. Tests and local bounds do not constitute a full security proof.

The full SRGG regression completed with **1714 passed, 0 failed in 375.37 seconds**; see [validation](validation.json). Run `python docs/research/team-b-delivery/2026-10-18-srgg-closure-followup/verify_followup.py` to check the receipt boundaries and [package hashes](MANIFEST.json).
