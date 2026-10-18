# SRGG Table 3 / Algorithm 7 covariance correspondence

Jia, Liu, Tang and Wang, *Constructing Efficient Identity-Based Signatures on Lattices*, DOI `10.1049/ise2/6684889`. This narrow package audits the frozen [paper PDF](../../../../papers/2025_efficient_ibs_jia.pdf) (SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`), specifically §2.2 p.3, Table 3 p.6, and Algorithm 7 p.8. It neither modifies the source backend nor proposes replacement parameters.

The printed perturbation shape subtracts `r²[y;1][yᵗ,1]`, while the printed scalar sampling and response multiply the scalar Gaussian by `ζ=1+X^(n/2)` with `ζζ*=2`. [Exact algebra and route ledger](proof.md) show that the transformed variable has **density shape `2r²`** on `c+ζR`. The original `n=512` coset has index `2^256` and a challenge-dependent exact normalizer. In the usual conditional independent-continuous convolution, the output shape is `Σ̄+r²[y;1][yᵗ,1]`, rather than the printed target `Σ̄`. Converting density shape to physical covariance or standard deviation preserves the relative factor two. The actual discrete signature covariance and complete signature law are not inferred from that continuous calculation.

[The standalone checker](../../../../experiments/research/candidates/srgg/paper_covariance_correspondence.py) uses exact integer/rational ring identities and emits [a JSON receipt](covariance-correspondence.json). [Focused tests](../../../../tests/test_srgg_paper_covariance_correspondence.py) compare it to independently constructed Sage coefficient matrices, exhaust small rings, and check sparse original-size cases. All three original Table 4 rows and both explicit code width interpretations remain unchanged. The source parser is not treated as mathematical evidence: the PDF pages were also rendered and inspected.

From the repository root in the prescribed WSL Sage environment:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_covariance_correspondence
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_covariance_correspondence.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-covariance-correspondence/verify_delivery.py
```

See [validation](validation.json) for the measured test result and exact scope. Main source route plus two alternatives did not reconcile the printed formulas; the alternatives and their limitations are preserved in `proof.md`. The author-intended correction and any full-law/security bound remain open. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
