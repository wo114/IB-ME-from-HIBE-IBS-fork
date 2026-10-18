# SRGG source smoothing width: directed check (WIP)

For the largest original Table 4 row, `m=(2+w)(d+1)n=10240` and the visually checked source equation gives `epsilon=1/sqrt(2^40*256)=2^-24`. The paper **explicitly defines** `rho(x)=exp(-pi||x||²)` and `eta_epsilon(Lambda)=min{s>0:rho(s Lambda*)<=1+epsilon}` on PDF p.3. Under that formal definition, directed theta arithmetic gives `eta_epsilon(Z^m)` in `(2.9077794,2.9077796)`, inconsistent with the paper's printed `r=eta_epsilon(Z^m)≈1.16` on pp.6,9. An *unstated* conversion of eta to physical standard deviation by `1/sqrt(2*pi)` gives `(1.1600361,1.1600363)` and explains the two-decimal approximation; it does not follow from the printed eta definition. The implementation's exact rational `1.16` is slightly below even this converted threshold.

This identifies an internal source-unit discrepancy, without modifying any sampler or parameter, proving a finite output law, or establishing IBS security. In particular we do not silently replace the original `r=1.16` by `2.90778`. See [proof.md](proof.md), [smoothing-eta.json](smoothing-eta.json), and [README_zh-CN.md](README_zh-CN.md). The source is the frozen Jia–Liu–Tang–Wang PDF `papers/2025_efficient_ibs_jia.pdf` (SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`, pp. 3, 6, 9).

Recheck in the designated WSL Sage environment from the repository root:

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_smoothing_eta.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-smoothing-eta/verify_delivery.py
```

No identity/message/signature operation or ROM query is run here; repetition count is inapplicable. Windows 11/WSL2, Sage 10.9/Python 3.13.15, Intel Core Ultra 7 255HX/~31.4 GiB RAM. The original rows are research inputs, not admitted formal parameters; source C/ANS performance is unreproduced. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
