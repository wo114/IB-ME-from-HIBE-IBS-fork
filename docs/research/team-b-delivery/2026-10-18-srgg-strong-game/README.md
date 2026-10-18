# SRGG native-strong game and public same-message replacement (WIP)

This focused audit uses the frozen Jia–Liu–Tang–Wang paper (`papers/2025_efficient_ibs_jia.pdf`, SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`). PDF p.4 Definition 3 and p.8 Theorem 2/G0 require a fresh `(identity,message)` despite Theorem 2's `sEUF-ID-CMA` wording. A different valid signature on a previously signed message belongs to a strict native-strong game, but does **not** win the paper's displayed G0.

Algorithm 8 has `[2I_d|…]` in its verification matrix modulo `2Q`. For any original valid response `z`, adding `sQ` to a coefficient in the first `d` polynomials preserves the recovered commitment, with `Q=15,744,063`. The exact norm gate is `||z||²+Q²+2sQt≤floor(γ²)`, where `t` is that coefficient. The implementation checks the matrix block, norm, commitment, original verifier, strict canonical codec and byte-distinctness using public inputs only. It searches one `±Q` basis shift, not all possible forgeries.

[`strong-game.json`](strong-game.json) replays one genuine source-Schur setup, extraction and signature for each of the three original Table 4 rows under both explicit Gaussian interpretations. Identity is `Alice` (5 B); message is 32 B. Five of six deterministic research runs had at least one accepted different same-message signature. The default PARAM-I sample had none among its 1024 tested basis positions. These are existence/finite-execution observations, not an attack probability estimate or a general proof. The recorded seed labels are test-only; the signature has no separate nonce field. The source parameters, original gamma, and protocol remain untouched.

See the [Chinese source mapping, exact conditions, row table and limits](README_zh-CN.md), [validation](validation.json), and [manifest](MANIFEST.json). Run from the repository root in the prescribed WSL Sage environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_strong_game --output build/strong-game-replay.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_strong_game.py
python docs/research/team-b-delivery/2026-10-18-srgg-strong-game/verify_delivery.py
```

The original strong reduction, random-key success probability, complete sampling correspondence, and formal hardness costs remain unresolved. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`. No HIBE work or formal parameter admission is claimed.
