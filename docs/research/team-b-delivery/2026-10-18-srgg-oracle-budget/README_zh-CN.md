# SRGG 原表 H1 有限拒绝预算（条件式）

本包核查独立 SRGG IBS 的真实 SHAKE／拒绝取样代码，保持论文 Table 4 的 `n=512,Q=15744063,d=2/3/4` 不变；不涉及 HIBE。冻结来源为 Jia 等的[论文 PDF](../../../../papers/2025_efficient_ibs_jia.pdf)，SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。

**在每个不同域分隔地址输出独立均匀 XOF 字节的条件下**，每个模 `Q` 系数耗尽 256 次拒绝试验的概率严格小于 `2^-1024`；一次公开矩阵扩展与一次不同身份目标合计，原三档分别严格小于 `2^-1012`、`2^-1011`、`2^-1010`。实际每系数最多读 `768 B`，小于配置的 `4096 B` 流上限。消息挑战直接取 512 位，另有长度前缀和域分隔。精确算式和前提见[证明](proof.md)，三档与源码绑定见[机器回执](oracle-budget.json)。

这是有限哈希拒绝概率的条件式，不是把 SHAKE-256 证明为随机预言机，也不覆盖 Setup、发钥、签名采样中止、QROM 归约或服务终身故障。真实 SHAKE 到理想随机预言机的距离与完整安全游戏界均保持 `null`。没有改动论文参数、协议或既有后端。

在仓库根目录按规定 WSL Sage 环境复核：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_oracle_budget.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_oracle_budget --output /tmp/srgg-oracle-budget-new.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-oracle-budget/verify_delivery.py
```

本轮定向 **10 passed、0 failed/skipped**；本包数学审计未调用 Setup／签名，身份和消息字节长度不适用，使用 ROM 作为**明确前提**而非已证明实现属性。见[验证记录](validation.json)及[清单](MANIFEST.json)。安全标记保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。
