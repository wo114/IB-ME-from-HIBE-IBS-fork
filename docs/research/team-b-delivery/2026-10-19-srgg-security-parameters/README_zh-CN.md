# SRGG 安全参数候选与最终配置（2026-10-19）

范围：Jia–Liu–Tang–Wang 独立 IBS 的**参数层**，不涉及 HIBE、组合或共享协议。
Table 4 三行原值保持不动；本包只在原表三行中做候选比较与最终选择，并把不能执行的新参数候选明确列为拒绝/不可执行。

## 结论

- 当前 `srgg2025` 默认 `Config`（degree 8、p=257、zeta2/factor2）是**研究参数**，不是安全参数。
- 论文 Table 4 三行带作者报告的目标/伪造位数，但仓库未复现这些估计，也没有正式准入；它们仍是**作者目标级研究参数**，不是 NIST 等级。
- 在已实现的 Table 4 三行中，本包选择：

```text
最终配置：PARAM-II
解释：table-standard-deviation
作者目标：180 bit；作者报告伪造 171/155 bit；密钥恢复 178/161 bit
```

选择准则：**最小的、已实现且作者报告伪造位数高于 128-bit 经典基线的 Table 4 行**。PARAM-I 的 103/93 bit 低于基线；PARAM-III 是 192-bit 以上目标的高安全选项，但更重。

## 候选表

| 候选 | 状态 | 作者目标 | 作者报告伪造（经典/量子） | 密钥恢复（经典/量子） | 结论 |
|---|---|---:|---:|---:|---|
| PARAM-I | 已实现 | 100 | 103 / 93 | 105 / 95 | 低于 128-bit 基线，不选 |
| **PARAM-II** | 已实现 | 180 | **171 / 155** | **178 / 161** | **最终 128-bit 基线配置** |
| PARAM-III | 已实现 | 256 | 242 / 219 | 255 / 232 | 高安全选项（≥192-bit 基线） |
| STATIC-N1024-D4 | 不可执行 | — | — | — | 当前 Fourier/Schur 资源门限 `n<=512`，无后端与安全估计 |
| STATIC-P-INCREASE | 拒绝 | — | — | — | 只增大 p 会破坏 HNF/签名 Schur 几何；`Q>2γ` 与宽度/γ 分配存在结构性冲突 |

所有已实现候选共用原 Table 4：

```text
n=512, p=16383, b=31, w=2, q=961, Q=15744063
d=2 / 3 / 4
factor1；两种 Gaussian 解释分开
```

## 为什么最终选 PARAM-II

1. **满足 128-bit 经典基线（按作者报告）**：PARAM-II 的伪造 171 bit、密钥恢复 178 bit，高于 128；PARAM-I 低于基线。
2. **比 PARAM-III 轻**：d=3、签名约 17.8 KB，而 PARAM-III 是 d=4、约 23.5 KB；Python/Sage 路径的 setup/sign 代价更低。
3. **标准差异解释有非空首发钥桥**：仓库已有该解释下固定根首发钥/历史 TV 证据；字面 density 解释的 `δ_issue` 为 `null`，因此最终解释选 `table-standard-deviation`。
4. **保留升级路径**：如果项目目标提高到 ≥192-bit，选 PARAM-III（作者报告伪造 242/219）；PARAM-III 的 242 仍低于 256-bit 经典伪造基线，所以**不能**把 PARAM-III 写成 256-bit 伪造安全。

## 为什么没有选“更大的新参数”

- `STATIC-N1024-D4`：当前 `FourierSchurPlan`、`PaperSchurSampleF` 和资源门限都要求 `n<=512`；n=1024 需要新的维度/资源/采样实现，不能只改配置。没有可执行后端和安全估计，不能作为最终配置。
- `STATIC-P-INCREASE`：把 p 从 16383 提高可以让 `Q>2γ` 在数值上成立，但 HNF 头部和签名 Schur 几何随 Q 增长；固定 Table 4 签名宽度/γ 不再覆盖用户密钥类。要同时保持正确性，需要重新分配宽度和 γ，而这又会改变 `Q>2γ` 关系。因此这不是一个保持原算法语义的安全参数扩展。
- 结论：在**不改论文算法/宽度族**的前提下，已实现的 Table 4 三行就是可用的安全目标候选；更大的 n 或不同 p/宽度族属于新参数设计，必须另立任务。

## 这个选择意味着什么、不意味着什么

**意味着**：

- 可以从默认 degree-8 研究 profile 切换到 `PaperParams("PARAM-II", "table-standard-deviation")`；
- 该配置有真实的 Table 4 Setup/Extract/Sign/Verify 生命周期、对象/服务/guarded 路径和现有测试；
- 有一个明确的“128-bit 经典基线（作者报告）”研究与演示配置。

**不意味着**：

- 不是正式安全参数准入；`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；
- 作者报告的 171/155 bit 没有在本地复现；不是 NIST 类别 1 的正式声明；
- 论文 `q>2γ` 与 `Q` 的自然映射仍不成立（Q=15,744,063 < 2γ）；
- `Q/2Q`、ζ factor1/factor2、`r/σ` 单位、Algorithm 4 `d/f` 仍有来源歧义；
- native strong 的同消息 `±Q` 替换反例仍在（原参数多行可构造）；
- ring-HNF/CRT/子域攻击成本、完整 ROM/QROM 映射、NIST 等级仍未闭合。

## 使用

```python
from experiments.research.candidates.srgg.paper_parameters import PaperParams

params = PaperParams("PARAM-II", "table-standard-deviation")
```

如果项目目标变为 ≥192-bit，把选择改为 `PaperParams("PARAM-III", "table-standard-deviation")`；如果目标严格达到 256-bit 经典伪造安全，当前 Table 4 没有满足项，需要新参数设计，不能把 PARAM-III 直接标成 256-bit。

## 文件与复核

- [`security-parameters.json`](security-parameters.json)：候选、选择、已知缺口和 Table 4 不变声明。
- 代码：`experiments/research/candidates/srgg/paper_security_profiles.py`。
- 测试：`tests/test_srgg_paper_security_profiles.py`。

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
    tests/test_srgg_paper_security_profiles.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m \
    experiments.research.candidates.srgg.paper_security_profiles \
    --output build/security-parameters-new.json
```

测试结果见最终交付信息；参数选择不是安全证明。

始终：`security_claim=none`、`backend_admitted=false`、
`parameters_are_formal=false`、`nist_security_category=null`。
