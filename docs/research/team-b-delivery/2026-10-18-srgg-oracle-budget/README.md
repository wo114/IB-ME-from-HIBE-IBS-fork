# SRGG finite H1 rejection budget (conditional)

For the original Table 4 `n=512, Q=15744063, d=2/3/4`, this package binds the standalone implementation's matrix and identity-target rejection code to an exact ideal-byte bound. A coefficient exhausts 256 trials with probability `(1033153/16777216)^256 < 2^-1024` **under independent uniform ideal XOF bytes**. One matrix expansion plus one distinct identity address is bounded by `<2^-1012`, `<2^-1011`, `<2^-1010` across the three rows. Each coefficient's 768-byte maximum precedes the configured 4096-byte stream cap. The message challenge directly takes 512 bits in a separate framed domain.

See the [Chinese summary](README_zh-CN.md), [proof and limitations](proof.md), [public receipt](oracle-budget.json), [tests](../../../../tests/test_srgg_paper_oracle_budget.py), [manifest](MANIFEST.json) and [verifier](verify_delivery.py). The source is the frozen Jia et al. [PDF](../../../../papers/2025_efficient_ibs_jia.pdf), SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`.

This does not prove SHAKE-256 is a random oracle, establish QROM programming, bound other sampler/fault aborts, or admit formal parameters. There is no HIBE work. `security_claim=none`, `backend_admitted=false`, `parameters_are_formal=false`, `nist_security_category=null`.
