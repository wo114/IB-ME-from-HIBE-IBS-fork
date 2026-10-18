> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# SRGG 原文逐环采样：固定根首发钥分布桥

本批只处理独立 IBS。沿用仓库冻结论文的 Table 4 三行：`n=512`、`p=16383`、`b=31`、`w=2`、`Q=15744063`、`d=2/3/4`，保留表格“标准差”和字面 density-width 两种解释。每行以可重放的测试种子生成一个成功 Setup 根，给 5 字节身份 `Alice` 首次发钥一次；本批没有签名消息。固定种子的诚实执行只核验代码路径，分布界另以新鲜独立均匀字节、证书列明的 MPFR/精确算术语义和无外部故障为前提。原参数尚未正式安全准入。

新增 [`paper_source_issuance_bridge.py`](../../../../experiments/research/candidates/srgg/paper_source_issuance_bridge.py) 将已认证的 source-Schur master 有限输出至理想联合整数 Gaussian 的固定根 TV 上界，接入原有居中 gadget 递归、全中心 `C≻64I` 门、完成平方、tail 与 centered-HNF 的确定性推前。若 digit-normalizer 相对和 `x<1` 且中心误差 `ε_C<1`，含中止的首发钥数学向量界为

```text
δ_key ≤ min(1, δ_source + δ_gadget + x/(2−x) + ε_C/(1−ε_C)).
```

Gadget fiber 的归一化费用只计一次；成功的有限输出须通过 256-bit 坐标、规范对象与一身份状态字节包络。真实重放核对同一根、参数、Alice 的目标、公钥/陷门关系、发钥方程和规范密钥往返。回执不输出陷门或用户私钥。原文采样器、后端语义和参数均未修改。

| 原 Table 4 行 | 表格标准差解释 | 字面 density-width 解释 |
|---|---|---|
| PARAM-I | 固定根首发钥界非平凡，含中止 | gadget digit-normalizer 充分条件未通过，完整发钥界 `null` |
| PARAM-II | 固定根首发钥界非平凡，含中止 | 完整发钥界 `null` |
| PARAM-III | 固定根首发钥界非平凡，含中止 | 完整发钥界 `null` |

精确有理界、每行 C 门和功能核验在 [`source-issuance.json`](source-issuance.json)。本批严格绑定已提交的 finite-chain Manifest **规范化 LF 字节 SHA-256**，并核对其中全部 32 个文件条目的字节数与 SHA-256，特别包括有限/联合回执、`proof.md` 和其采样/数学源文件；上批已提交 source-Schur Manifest 还绑定继承的 Setup、gadget、HNF、对象和随机源代码。每行回执记录 Manifest 摘要与依赖文件摘要。新目录自身的清单与验证结果见 [`MANIFEST.json`](MANIFEST.json)、[`validation.json`](validation.json)。

边界：六个测试根不代表全部可接受 Setup 根；本界只对应一次首次发钥的数学密钥向量加中止，不覆盖签名 law、缓存/并发/磁盘/崩溃故障历史、ROM/QROM 安全归约、native strong 或困难性。字面解释的固定根 source-Schur 扰动界小于 1，不能据此填补完整 gadget 界。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；不声称 NIST 等级，也没有 HIBE 组合。

复核须在仓库根目录使用指定 WSL Sage 环境；输出文件必须尚不存在：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_source_issuance_bridge.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_source_issuance_bridge --output build/recheck-source-issuance-new.json
python docs/research/team-b-delivery/2026-10-18-srgg-source-issuance/verify_delivery.py
```
