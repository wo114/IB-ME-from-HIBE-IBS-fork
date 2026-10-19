# SRGG DeepSeek delivery engineering repairs (2026-10-19)

Source: Jia, Liu, Tang and Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI `10.1049/ise2/6684889`. [Chinese report](README_zh-CN.md).

This batch follows the current `AGENTS.md`: cite the source paper, retain project working assumptions and known issues, and repair implementation/evidence without commissioning another security proof. HIBE and remote publication are outside this batch.

Inputs are guarded-v3 commit `7131eaa60e874a1a48a355c6369de7efc3185873` and distribution-chain commit `9af579d32d574a4cf626ec40a258db721c89e105`, collected locally in `b544567`. Their original branches and history remain available. Original Table 4 profiles, widths, rounded `r=1.16`, norm gate and signature equations remain unchanged; both Gaussian readings remain explicit.

Repairs cover preparation-error classification and root retry/fixed-key abort; one canonical guarded backend; exact cached-key restoration boundaries; disabled obsolete unguarded-gap probing; complete phase-failure accounting; strict standard-library verifiers that survive `python -O`; current dependency hashes and the stale random-key receipt digest; and explicit mathematical-versus-implemented scopes. The existing conditional mathematical calculations are retained without turning an unbounded interval-rejection cost into an implemented guarantee. Histories cover logical API outputs and deterministic persistent state, excluding timing/internal traces and unmodelled faults. Old PR53 runtime measurements are not inherited by the new guard path.

Run under the designated WSL Sage installation:

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-independent-followup/verify_all.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/verify_delivery.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -O docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/verify_delivery.py
```

The two new-package verifiers and their negative fixtures need only standard Python:

```text
python -m pytest -q tests/test_srgg_deepseek_delivery_verifiers.py
python docs/research/team-b-delivery/2026-10-18-srgg-distribution-guard-deepseek/verify_delivery.py
python docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/verify_delivery.py
```

Also run both with `-O`. Final commands, counts, replay details and files are recorded in `validation.json` and `MANIFEST.json`. `refresh_bindings.py` maintains only current delivery envelopes, draws no entropy and supplies no proof; independent verifiers must run afterwards. Historical measurements and source commits retain their original scope.

Final regression: **2071 passed, zero failures/errors/skips, 808.14 seconds**. This includes the 86 verifier controls; overlapping counts are not added. All 18 nine-package normal/optimized checks and both random-key verifier modes pass. The 262 runtime source/test hashes are unchanged. Seven algorithm/parameter files, the signing method and 24 prior exact numerical fields remain unchanged; see `invariants.json`. Run `verify_repair.py`, also under `-O`, to check this final snapshot.

The distribution-chain replay has one lifecycle per original profile and Gaussian reading: six total, with the 5-byte identity `Alice` and an actual 31-byte message (the fixture text contains `32B`, but its length is 31). Guard fixture probes also include three issued-key/sign-plan preparations per profile/reading; JSON counts must not be summed as independent overlapping samples. Deterministic seeds are public test fixtures only. Identity targets use ROM. Injected failures test operational policy, rather than sampling probabilities or cryptographic security. Metadata stays `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
