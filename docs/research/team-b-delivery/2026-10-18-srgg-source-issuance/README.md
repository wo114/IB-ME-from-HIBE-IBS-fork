> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# SRGG source-Schur: fixed-root first-issuance bridge

This HIBE-independent research batch keeps the paper's three Table 4 rows (`n=512`, `p=16383`, `b=31`, `w=2`, `Q=15744063`, `d=2/3/4`) and both explicit Gaussian-notation interpretations. It replays one accepted Setup root and one first issuance for the five-byte identity `Alice` per row. No message is signed. Deterministic seeds identify fixtures; the distribution bound separately assumes fresh independent uniform bytes, the stated MPFR/exact-arithmetic model, and no external faults.

[`paper_source_issuance_bridge.py`](../../../../experiments/research/candidates/srgg/paper_source_issuance_bridge.py) combines the authenticated fixed-root source-Schur master output-to-joint-Gaussian bound with the original centered gadget recursion and HNF pushforward. It independently checks the same root's `C≻64I` gate, original master shape, public/trapdoor relation, finite object guards, target identity, honest key equation, and canonical key encoding. With digit relative sum `x<1` and center error `ε_C<1`, the mathematical key-vector-plus-abort bound is `min(1, δ_source+δ_gadget+x/(2−x)+ε_C/(1−ε_C))`; the gadget normalization cost is charged once.

The three table-standard-deviation rows yield nontrivial **fixed-root first-issuance** bounds. All three literal-density-width rows retain a `null` complete issuance bound because the available digit-normalizer sufficient condition fails. Exact rational results and public checks are in [`source-issuance.json`](source-issuance.json). The certificate binds the committed finite-chain Manifest by its LF-normalized SHA-256 and verifies all 32 listed file sizes and digests, including finite/joint receipts, `proof.md`, and mathematical/source files. It also binds inherited Setup, gadget, HNF, object, and randomness sources to the previous source-Schur Manifest. The independent package verifier and validation record are [`verify_delivery.py`](verify_delivery.py) and [`validation.json`](validation.json).

Six fixtures do not establish a bound for all accepted Setup roots. This result does not cover complete issuance/signature/fault histories, ROM/QROM reduction, native strong security, structural hardness, formal security parameters, NIST categorization, or HIBE composition. The markers remain `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, and `nist_security_category=null`. Functional replay and a fixed-root TV bound are not a security proof.

Reproduce from the repository root with the designated WSL Sage environment; use a fresh output path:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_source_issuance_bridge.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_source_issuance_bridge --output build/recheck-source-issuance-new.json
python docs/research/team-b-delivery/2026-10-18-srgg-source-issuance/verify_delivery.py
```
