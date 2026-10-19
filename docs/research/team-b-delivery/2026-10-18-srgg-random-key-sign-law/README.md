> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# SRGG original-parameter random-key signing-law audit (WIP)

**Paper:** Huiwen Jia, Ying Liu, Chunming Tang and Lin Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI 10.1049/ise2/6684889. Frozen local PDF SHA-256: `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.

This package tests the gap between an issuance law for a **random** key and the previous signing law for **one frozen** Alice key. On all six original Table 4 rows, an exact, canonical tail witness lies in the mathematical issuance reference support yet makes the signature Schur geometry nonpositive. The unchanged backend rejects its signing plan. See [the derivation](proof.md) and [the six-row receipt](random-key-sign-law.json). This does not estimate that witness's probability under the finite issuer.

The generic one-key coupling is `TV <= min(1, delta_issue + beta_bad + s epsilon_good)` for at most `s` adaptive sign calls, provided `beta_bad` bounds bad-key mass under the **same ideal issuance reference** and `epsilon_good` uniformly bounds the complete sign call on good keys. Both are still null, so no random-key signing-history TV has been certified. The prior fixed-key epsilon is never reused as a random-key epsilon.

Parameters are the paper's `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4` with both explicit published-Gaussian interpretations; no widths, norms, algorithms or sampling distributions were changed. Each row replays one deterministic accepted root and one synthetic canonical Alice (5-byte) key, **not** an actual issuance draw. No message is signed. The receipt records Sage/Python/platform versions. ROM supplies the identity target. Test seeds are fixtures, not entropy evidence.

Run in the prescribed WSL Sage environment from repository root:

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_random_key_sign_law.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_random_key_sign_law --output build/new-random-key-sign-law.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/verify_delivery.py
```

Use a new output path; do not overwrite the frozen receipt. The manifest binds selected source, tests and evidence. Prior package verification is invoked before the six-row replay. The deterministic replay is implementation evidence only. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, and `nist_security_category=null`. All accepted Setup roots, fault history, formal proof assumptions, bad-key mass and actual structural attack costs remain open.
