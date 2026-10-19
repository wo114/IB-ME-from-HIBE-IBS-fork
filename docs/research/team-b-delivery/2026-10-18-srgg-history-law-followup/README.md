> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# SRGG fixed-root adaptive histories (WIP)

This HIBE-independent batch keeps the paper's original Table 4 n=512, p=16383, b=31, w=2, Q=15744063, d=2/3/4, with both explicit Gaussian-notation interpretations. The frozen primary source is papers/2025_efficient_ibs_jia.pdf (SHA-256 258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152). See [proof.md](proof.md), [history-law.json](history-law.json), and the [certificate code](../../../../experiments/research/candidates/srgg/paper_history_law_followup.py).

For each of six fixed accepted Setup roots, the package authenticates the prior finite-chain and source-issuance receipts, replays the same Alice key, and rechecks that key's signature Schur plan. The same-root first-issuance formula is uniform over canonical identity targets; an adaptive coupling therefore covers fault-free logical issuance-only histories up to the existing FixedIssuer's conservative capacities 3/2/1. In the standard-deviation interpretation, the capacity-history TV upper is 2^-24 for each Table 4 profile. The literal-density issuance bound remains null.

For the **one frozen Alice key only**, the standard-deviation rows' one-sign-call TV uppers are 2^-19, 2^-18, 2^-18; the two-adaptive-message uppers are 2^-18, 2^-17, 2^-17. These compare the full original Algorithm 7 operational retry/abort *outcome* to an ideal perturbation/u reference but do not bound the probability of norm exhaustion. Literal-density call bounds round to the trivial value 1. The receipt does not draw actual signatures; previous lifecycle receipts remain the functional evidence. The fixture identity is 5 bytes, and the analytical signing result ranges over all valid messages.

The issuance and signing claims are separate. The signature gate is not uniform over keys produced by a random first issuance, so the combined random-issuance-then-signature/fault history bound remains null. All accepted roots, infrastructure faults, malicious storage and timing, native strong, structural hardness and formal security parameters remain open. Conditions include independent uniform bytes, the stated MPFR arithmetic model, a common logical scheduler, and no external faults. All security markers stay none/false/false/null; this is not an IBS security proof or NIST category claim.

Use the designated WSL Sage environment from the repository root:

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_history_law_followup.py
    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_history_law_followup --output build/new-history-law.json
    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup/verify_delivery.py

Choose a new report path; the certificate command refuses to overwrite the frozen receipt.
