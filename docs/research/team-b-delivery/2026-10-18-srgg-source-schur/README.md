> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# SRGG paper-order standalone implementation; parameter closure remains WIP

Source: Jia, Liu, Tang, Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI `10.1049/ise2/6684889`. Frozen PDF SHA-256: `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`. This is a dated implementation increment to the existing reproduction, not a new paper edition. See the [Chinese report](README_zh-CN.md) and [source map](algorithm-map.md).

The new standalone path follows Algorithms 3--4: discrete lower block, descending ring Schur, conditional centers, per-ring continuous Gaussian displacement, and fixed-width discrete Gaussian rounding. It preserves all original Table 4 inputs, both declared Gaussian interpretations, factor1, and original norm retries. The prior joint sampler and its frozen evidence remain available.

An exact QQ ring reference passes independent small dense checks. One original-degree preparation reached its 45-second limit; its imported source snapshot and provenance remain recorded. The single numerical alternative uses directed interval Fourier Schur and explicit dyadic gains/centers. Its complete numerical/Schur-chain TV is **not certified**, and the prior joint-law certificate is not reused.

`SourceSchurBackend` reuses the original objects, setup, extraction, verification and fixed issuer, with a separate Algorithm 7 implementation installing a full attempt entropy cap over perturbation and all u draws. At most 64 attempts give a finite per-sign-call envelope. The extra cap abort is at most `2^-192` per attempt, conditional on the existing perturbation hard cap and iid uniform bytes. This is neither a lifetime service budget nor a complete signature-law error bound. The original backend file remains byte-identical.

Seven final lifecycle receipts (`*-bounded-final-lifecycle.json`) cover three original rows under two explicit width interpretations, plus one SecureRandom PARAM-I run. Each uses one root, 5-byte identity, 32-byte message, issuance, two successful signatures, strict objects, persistent restart, restored-key signing, and 37 passing functional checks. Public same-message Q-shift replacements succeed for default II/III and all literal-density rows. Default PARAM-I has no eligible candidate in these probes; this is not a security result. Raw prior and intermediate receipts are preserved separately.

The original-modulus CRT/HNF preflight actually factors the ring over each prime, distinguishes ideal uniform matrices, seeded matrices and unfiltered CBD1 roots, and leaves actual structural costs and setup acceptance conditioning unresolved. Public failure receipts omit arbitrary backend exception payloads and tracebacks. [Validation](validation.json), [test provenance](regression-provenance.json), [environment](environment.json), and [manifest](MANIFEST.json) record the final checks. Timings are overlapping Python/Sage single-run evidence, not a reproduction of the author's C/ANS/1000-run cycle benchmark.

From the repository root, use the prescribed WSL Sage environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_audit --sampler source-schur --profile PARAM-I --output build/source-schur-i.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py
python docs/research/team-b-delivery/2026-10-18-srgg-source-schur/verify_delivery.py
```

Use PARAM-II/PARAM-III, `--interpretation literal-density-width`, or `--production-random` for the other cases. Remaining standalone obligations include source notation conflicts, rounded r and failed necessary gates, all-root and complete issuance/signature/history/fault laws, native strong and ROM/QROM correspondence, actual structural hardness, author implementation/performance, and complete resource admission. HIBE work is outside this increment.

All markers remain `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`. Functional checks and unsuccessful finite attacks are not security proofs. Local commit only; no push.
