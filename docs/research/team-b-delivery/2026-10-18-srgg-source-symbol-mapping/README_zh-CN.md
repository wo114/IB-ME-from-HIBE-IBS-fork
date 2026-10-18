# SRGG 原文符号与游戏对应审计（WIP）

本包对照仓库冻结的 [Jia 等论文 PDF](../../../../papers/2025_efficient_ibs_jia.pdf)（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`）及原 Table 4 三行，仅核独立 IBS，不改原后端、参数或协议。

可执行的[精确核验](../../../../experiments/research/candidates/srgg/paper_source_symbol_mapping.py)与[15 项定向测试](../../../../tests/test_srgg_paper_source_symbol_mapping.py)确认：若让论文 Theorem 1 的 `Z_(2q)` 对应算法 8 实际 `R_(2Q)`，必有 `q=Q=15744063`；三行都不满足必要的 `q>2γ`。字面 gadget `q=961` 和取 `q=2Q` 均不能保持模数条件。原文形式定义的 `η` 与印出的 `r≈1.16` 在三档 Table 3 维度均不一致；仅另加未写明的物理标准差换算时，原值在 `d=2,3` 通过这项平滑门，`d=4` 仍略低于严格阈值。

原文第 4 页 Theorem 1 只给 EUF-CMA，第 8 页 Theorem 2 以 sEUF-CMA 为前提却在 G0 使用新身份／消息对条件。第 8–9 页的有限游戏轨迹还显示两个需要修订或澄清的地方：G1 的独立集合下界用签名查询数 `qS`，但明示排除的是发钥身份；且第 9 页模拟器在目标身份签名查询时中止，尽管这种旧消息签名后伪造新消息的查询形态按 G1 文字允许。轨迹**假设**最终验签成功，只证明所写事件与模拟器覆盖不一致，不构造真实新消息伪造。具体等式、来源页码、适用边界与换路记录见[证明说明](proof.md)和[可重算 JSON](source-symbol-mapping.json)。

规定环境为 WSL2 Ubuntu 的 Sage 10.9／Python 3.13.15；无身份、消息、随机抽样或 ROM 查询的实际执行，重复次数不适用。复跑：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_source_symbol_mapping.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-source-symbol-mapping/verify_delivery.py
```

这次发现的是原文声明、必要条件与当前实现的对应缺口，不能升级为新消息安全性反例或完整安全证明。仍保留 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。无 HIBE、正式参数准入或作者性能复现。
