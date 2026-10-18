# Exact image and kernel of the paper SRGG verification matrix

This package certifies only the full-modulus algebraic image and kernel of the linear map in Jia et al., Algorithms 7–8 (frozen PDF pages 7–8; SHA-256 258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152). It does not estimate a short-vector or forgery cost. Source: ../../../../experiments/research/candidates/srgg/paper_verification_image.py. Independent small-ring tests: ../../../../tests/test_srgg_paper_verification_image.py.

The paper has A=[I_d | Ahat | B] with (2+w)d columns, w=2. Its verification map is [2A | Q zeta_star e1 − 2h] modulo 2Q, where zeta_star=1−X^(n/2). Algorithm 7 line 5 defines b=Qj−2H(id); Algorithm 8 line 2 reuses b without restating its computation. We expand b using that earlier definition. The source parameters are n=512, p=16383, q=31²=961, Q=pq=15744063, 2Q=31488126, and d=2/3/4.

Because Q is odd, coefficient CRT gives R_(2Q) ≅ R_2 × R_Q. Modulo Q, 2 is invertible and A contains I_d, so the image is all R_Q^d for every Ahat, B, and h. Modulo 2, only zeta_star e1 survives. In R_2=F_2[X]/((X+1)^n), zeta_star=(X+1)^(n/2), whose principal ideal and annihilator both have F_2-dimension n/2=256.

| Paper row | d | A columns | Mod-2 image dimension | Image index in full codomain | Kernel cardinality |
| --- | ---: | ---: | ---: | ---: | --- |
| PARAM-I | 2 | 8 | 256 | 2^768 | Q^3584 × 2^4352 |
| PARAM-II | 3 | 12 | 256 | 2^1280 | Q^5120 × 2^6400 |
| PARAM-III | 4 | 16 | 256 | 2^1792 | Q^6656 × 2^8448 |

These counts refer to unrestricted responses modulo 2Q, without the signature norm gate. The receipt's modulo-Q coefficient_image_dimension and kernel exponent mean coefficient count or free-module rank over composite Q; they are not vector-space dimensions over a field. The mod-2 dimensions genuinely are over F_2. A large image index is neither an attack cost nor a security level.

From the repository root, reproduce with the prescribed WSL Sage environment:

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_verification_image
    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_verification_image.py
    python docs/research/team-b-delivery/2026-10-18-srgg-verification-image/verify_delivery.py

The focused suite passed 17 tests with no failures. It includes independent Sage Smith-invariant checks for n=4/8, d=1/2, and composite odd Q=15. Fresh source execution matched the packaged JSON byte-for-byte, SHA-256 be582a4920c703b3569f3e42349cd62f9e868acf80b244a80ef8fff9b5e3b17c. MANIFEST.json binds the receipt, documentation, verifier, source, tests, and paper; it does not hash itself.

Still open: the paper theorem's q/Q/2Q mapping, accepted Setup roots and actual seeded public-matrix law, short-kernel, forgery, ring-HNF/MSIS/CRT/subfield attack costs and formal hardness bits, full issuance/signature/fault histories, and known native-strong same-message replacements. No security admission follows: security_claim=none, backend_admitted=false, parameters_are_formal=false, nist_security_category=null. Functional tests are not a security reduction.
