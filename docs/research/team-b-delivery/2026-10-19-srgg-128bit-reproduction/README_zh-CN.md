# SRGG 128-bit 经典伪造目标：论文 Table 5 复现与 PARAM-II 决策（2026-10-19）

范围：Jia–Liu–Tang–Wang 独立 IBS 的 concrete-security 估计复现，不涉及 HIBE、组合或正式 NIST 准入。Table 4 原值未改。

## 结论

**`PARAM-II` 在论文的 Core-SVP concrete-security 模型下达到 128-bit 经典伪造目标。**

复现值：

```text
PARAM-II key recovery:      beta=614, classical=179 bit, quantum=163 bit
PARAM-II forgery:           beta=584, classical=171 bit, quantum=155 bit
论文 Table 5:               beta=608/586, classical=178/171, quantum=161/155
```

所以按论文模型：

- 经典伪造 **171 bit ≥ 128**；
- 量子伪造 **155 bit ≥ 128**；
- key recovery **179/163 bit**，也高于 128；
- 最终配置仍选 `PARAM-II`，解释为 `table-standard-deviation`。

## 论文确实给了公式

之前说“论文没给推导”不准确。Section 5.2（pp.9–10）给了：

1. **Key recovery**：primal attack，
   `||(s,e,-1)|| sqrt(β/d) ≤ δ_β^{2β-d-1} Q^{m/d}`，`d=2m+1`；
2. **Forgery**：nearest-colattice approximate-CVP，
   `β ≥ min_{k≤d-m} (δ_β^{d-k} M^{m/(d-k)} - k)`；
3. **Core-SVP**：`0.292β` / `0.265β`。

复现的关键映射：

```text
key recovery:  m = rank*n, d = 2m+1, modulus = Q
forgery:       m = rank*n, d = ((2+w)rank+1)*n, modulus = 2Q, target = gamma
```

之前 forgery 复现失败，是因为用了错误的 plain-SIS/Q 模型；论文的 forgery 是 2Q 上的 approximate-CVP/nearest-colattice，不是自然 SIS 短向量。

## 复现对比

| 配置 | key β 作者/复现 | key classical 作者/复现 | key quantum 作者/复现 | forgery β 作者/复现 | forgery classical 作者/复现 | forgery quantum 作者/复现 |
|---|---:|---:|---:|---:|---:|---:|
| PARAM-I | 358 / 360 | 105 / 105 | 95 / 95 | 352 / 350 | 103 / 102 | 93 / 93 |
| **PARAM-II** | 608 / 614 | 178 / 179 | 161 / 163 | 586 / **584** | 171 / **171** | 155 / **155** |
| PARAM-III | 874 / 882 | 255 / 258 | 232 / 234 | 828 / 824 | 242 / 241 | 219 / 218 |

误差：key β ≤8，forgery β ≤4；PARAM-II 的 forgery bits 与作者完全一致。
这支持“论文 Table 5 的 concrete-security 数字是可复现的”，但仍不是逐位一致；小差异来自 δ_β 近似、取整和维度/范数约定。

## 为什么这算达到 128-bit

- IBS 的关键是 **forgery**，不是 key recovery；
- PARAM-II forgery 复现为 **171-bit 经典 / 155-bit 量子**；
- 因此按论文的 Core-SVP concrete-security 模型，`PARAM-II` 达到 **128-bit 经典伪造目标**，并有一定余量；
- `PARAM-I` forgery 102/93，低于 128，不选；
- `PARAM-III` forgery 241/218，是更高安全选项，但更重。

## 必须保留的边界

这是 **concrete-security 研究级 128-bit**，不是正式安全准入：

- 目标限定 **EUF-CMA**，不是 strong unforgeability；native strong 同消息 `±Q` 替换反例仍在；
- Theorem 1 的 `q>2γ` 与 `Q/2Q` 映射仍是来源/定理缺口；本复现只覆盖论文 Section 5.2 的 concrete-security 估计；
- ring-HNF/CRT/子域结构攻击成本没有在本模块估计；
- 作者 C/ANS 采样器和 Table 6–7 性能没有复现；
- 没有 NIST 类别，没有正式归约/证明；
- 因此：

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

准确表述：

> **按论文 Section 5.2 的 Core-SVP concrete-security 模型，PARAM-II 的 forgery 估计复现为 171-bit 经典 / 155-bit 量子，达到 128-bit 经典 EUF-CMA 目标；这不是 strong 安全或 NIST 正式等级。**

## 最终配置

```text
profile: PARAM-II
interpretation: table-standard-deviation
n=512, p=16383, b=31, w=2, q=961, Q=15744063, d=3
target: 128-bit classical EUF-CMA (concrete-security reproduction)
```

Table 4 三行原值不变；本包只做复现和选择。

## 参数/结构审计结论

- **q/Q/2Q**：key recovery 用 `Q`，forgery 用 `2Q`；Table 5 concrete-security 可复现。但 Theorem 1 的 `q>2γ` 在 `Q` 和 `2Q` 下都不成立，仍是单独的定理级缺口。
- **ζ**：论文 `ζζ*=2`、Algorithm 7 暗示 factor2；当前 source-Schur 默认按字面 factor1。两条路径的等价响应 law 未证明，保持 `null`。
- **r/σ**：默认按 `table-standard-deviation`；字面 density 是另一分支。精确 `r=1.16` 在来源 `m=10240` 的平滑必要条件失败，作者值只是两位小数近似；有限采样到 HNF/签名 law 的桥保持 `null`。
- **结构攻击**：`Q=3·31²·43·127`，存在 `2A(Qe_i)=0 mod 2Q` 的零 BKZ 成本受限核见证；ring-HNF/MSIS、CRT、子域的实际攻击成本均为 `null`，没有 128-bit 结构成本保证。
- **native strong**：之前的回执对 default II/III 和字面 density 行记录过同消息 `±Q` 替换；default I 的本次抽样没有 eligible 对，但不构成普遍安全证明。本报告的目标限定 **EUF-CMA**，不是 strong。

因此最终决策是：

> **PARAM-II 可作为 128-bit 经典 EUF-CMA 的 concrete-security 研究配置；不能作为 strong、NIST 或结构攻击成本已闭合的正式配置。**

完整审计字段见 [`audit.json`](audit.json)。

## 文件与复核

- [`core-svp-reproduction.json`](core-svp-reproduction.json)：公式、维度映射、作者/复现值、误差和 null。
- [`audit.json`](audit.json)：q/Q/2Q、ζ、r/σ、结构攻击、native strong 和最终决策。
- 代码：`experiments/research/candidates/srgg/paper_core_svp_reproduction.py`
- 测试：`tests/test_srgg_paper_core_svp_reproduction.py`、`tests/test_srgg_paper_128bit_audit.py`

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
    tests/test_srgg_paper_core_svp_reproduction.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_core_svp_reproduction \
    --output build/core-svp-reproduction-new.json
```

测试结果见 `validation.json`；功能与数值复现不是安全证明。
