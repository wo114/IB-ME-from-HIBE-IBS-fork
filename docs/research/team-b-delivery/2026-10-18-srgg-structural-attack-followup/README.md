# Original-parameter SRGG structural attack follow-up (WIP)

The frozen Jia et al. paper (`papers/2025_efficient_ibs_jia.pdf`, SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`) gives the Table 4 inputs. This package does not change them or use HIBE.

For the published verification matrix `[2A | Qζ*e₁−2h] mod 2Q`, `ζ*=1−X^256`, the last-column vector `Qζ*` is a kernel vector for every public matrix and identity target: `(ζ*)²=−2X^256`. Its squared norm is `2Q²=495751039495938`, within each original published signature-radius cap. No BKZ is needed to write it. Among nonzero last-column `Q·t` vectors preserving the commitment, that norm is minimal; this limited statement says nothing about the full matrix's shortest vector.

One deterministic test-only PARAM-I source signature was valid and the shifted canonical signature kept the recovered commitment, but its best scanned `±Qζ*X^i` candidate exceeded the norm cap and was rejected. This single run does not estimate a probability or override the separate successful first-block Q-shift evidence.

The exact coefficient CRT floor `Q/m` for a vector isolated to prime-power component `m` does not provide an actual polynomial-factor lift, short-solution distribution, or Ring-HNF/MSIS/CRT/subfield attack cost. Those costs remain null, as do formal hardness bits. The paper's Table 5 author estimates have not been reproduced here. Details and validation: [Chinese report](README_zh-CN.md), [proof and scope](proof.md), [receipt](structural-attack-followup.json), [validation](validation.json).

Security status: `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
