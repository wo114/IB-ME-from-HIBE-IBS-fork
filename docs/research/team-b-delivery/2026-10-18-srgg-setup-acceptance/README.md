# SRGG Table 4 Setup positivity: mathematical bound (WIP)

This package derives an exact-moment upper bound for the original paper's
Algorithm 1 positive-definiteness retry gate with `n=512`, `w=2`, and
`d=2/3/4`. It uses the frozen Jia–Liu–Tang–Wang source
[`papers/2025_efficient_ibs_jia.pdf`](../../../../papers/2025_efficient_ibs_jia.pdf)
(SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`).
The two explicit Gaussian-width interpretations yield the same exact Schur
threshold because their common positive squared-width scale cancels.

The [exact certificate](setup-acceptance.json) proves one-attempt mathematical
rejection upper bounds of about `0.205519`, `0.095133`, and `0.046674` for
PARAM-I/II/III. For 64 iid retries, exhaustion is strictly below
`2^-146`, `2^-217`, and `2^-282`. The [proof](proof.md) uses CBD1 moment
domination, 256 conjugate-paired negacyclic Fourier blocks, an exact complex
Wishart hook moment, and Markov's inequality. The [Chinese README](README_zh-CN.md)
maps the construction to Algorithm 1 and Tables 3–4.

These figures bound the *mathematical* positivity event on raw CBD1 witnesses.
The current finite backend can additionally reject or fault on interval,
series, or resource preparation, and its actual successful-root law is not
certified here. The report leaves those probabilities and all-root sampler,
complete IBS-history, structural-hardness, native-strong, and formal-security
claims unresolved. The original parameters are research inputs rather than
admitted formal or NIST-category parameters. No HIBE is involved.

Recompute from the repository root in the prescribed WSL Sage environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_setup_acceptance.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_setup_acceptance > build/recheck-srgg-setup-acceptance.json
python docs/research/team-b-delivery/2026-10-18-srgg-setup-acceptance/verify_delivery.py
```

The test and package verification results are recorded in
[`validation.json`](validation.json), and package bytes in
[`MANIFEST.json`](MANIFEST.json). `security_claim=none`,
`backend_admitted=false`, `parameters_are_formal=false`, and
`nist_security_category=null`.
