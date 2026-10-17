# 《Shorter and Faster Identity-Based Signatures with Tight Security in the (Q)ROM from Lattices》

**作者：** Éric Sageloli、Pierre Pébereau、Pierrick Méaux、Céline Chevalier
**机构：** Thales SIX；Sorbonne Université、CNRS、LIP6、PolSys；University of Luxembourg；DIENS、École Normale Supérieure、CNRS、Inria、PSL University；CRED、Université Paris-Panthéon-Assas。
**DOI：** `10.1007/978-3-031-33488-7_24`
**冻结来源：** HAL v1，`papers/2023_shorter_faster_ibs_sageloli.pdf`
**来源 SHA-256：** `0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e`

## 摘要

我们给出了在（经典或量子）随机预言机模型（ROM 或 QROM）中，针对自适应攻击者具有紧安全性的基于身份签名（IBS）方案，覆盖非结构化格和结构化格，并分别基于 SIS 或 RSIS 假设。这些签名长度与消息长度无关。我们的方案建立在 Pan 和 Wagner（PQCrypto 2021）的工作之上，并从多个方面进行了改进。首先，我们在 QROM 中证明了从非自适应 IBS 到自适应 IBS 的转换。然后，我们简化了所用参数并给出具体取值。最后，我们采用非齐次关系简化签名方案，从而减小签名长度并去除一次代价较高的陷门委派。总体上，我们得到更好的安全界、更短的签名和更快的算法。

---

本目录记录 B 组两条 Sageloli 路线的完整独立研究实现：

- 矩阵 SIS（`SISBackend`）；
- 结构化 Ring-SIS（`RSISBackend`）。

实现提供 `setup`、`key_extract`、`sign`、`verify`、`load_signature` 五方法，严格 v2 对象、固定持久发钥、重启恢复、有界失败处理，以及两条数学路线的真实全维委派／签名采样。这是可执行研究基线，**没有安全准入**：`security_claim="none"`、`backend_admitted=false`、`parameters_are_formal=false`。

## 冻结实现契约

完整契约见 [`docs/specs/sageloli-ibs.md`](../../../specs/sageloli-ibs.md)，论文—代码来源映射见 [`SOURCE_MAP.md`](SOURCE_MAP.md)。v2 wire 魔数为 `IBME:SAGELOLI-IBS:v2`。v1 状态会被拒绝，绝不会自动迁移、重抽或重新发钥。

默认可执行教学点如下：

| 路线 | 维度 | 模数 | 身份宽度平方 | 签名宽度平方 |
|---|---|---:|---:|---:|
| SIS | `n=2,k=4,m=16` | `3^4=81` | `2^28` | `2^56` |
| RSIS | `d=4,k=9,l=22` | `3^9=19683` | `2^36` | `2^66` |

宽度采用论文的密度约定 `exp(-π||x||²/s²)`，固定舍入宽度为 `r²=16`。这些点刻意很小：公开范数检查是空泛的，公开线性求解可以生成被接受的签名；相关证据必须保留，因此不宣称任何安全类别。论文的两组大 RSIS 点 `(k,d,l)=(65,2048,132)` 和 `(153,2048,308)` 只作记录，未在本实现运行。论文没有给出具体发表的 SIS 点，因此不虚构。

只有默认 RSIS 点按论文 Table 4 的形状不等式核验。参数类仍允许研究探索用的其它尺寸；构造其它实例不代表其满足论文条件或获得安全准入。

## 论文对应与工程选择

根公钥构造为 `[Abar | G-Abar R]`。矩阵路线使用 CBD1，环路线使用论文的四分块 `4P_(1/2) × P_(1/2) × 4P_(1/2)` 根分布。由于论文同时打印负号构造和 `A[-T;I]=G`，v2 存储 `R`，向根采样器传 `T=-R`；委派身份钥满足 `A*T_id=H1-G`，签名时把正的 `T_id` 传给同一采样器接口。

SIS 委派进行 `nk` 次全维调用。RSIS 进行 `k` 次系数级调用，再通过反循环旋转展开。当前数值实现对 SIS 使用全局 `SampleF`，对 RSIS 使用块大小为 `d` 的 block-Schur `SampleP` 风格组合。论文没有独立的 `SampleP` 伪代码；这里是接口层面的忠实解释，不声称逐比特复现 MP12 的连续内部采样器。

所有有限拒绝预算均显式执行。模 q 无偏映射每个系数最多192次尝试，总字节预算64 MiB。完整采样器在取熵前执行精确 raw PSD 准入。连续数值 tickets、有限精度、截断和总统计距离尚未认证，因此不把论文的 `gamma^Sample` 直接写成实现误差证书。

## 持久发钥服务

`FixedIssuer` 默认32个身份账本、16 MiB 对象／状态包络和300秒锁获取预算。它创建并同步 pending 标记，持久化 pending 身份，执行真实采样，原子发布 issued 状态，并在同步后删除标记。重启后重复请求同一身份返回同一把钥。pending、failed、损坏、参数不匹配、路线不匹配、错误 wire、采样失败和持久化失败都会阻断自动重发。可选的预期公钥／参数 pin 会拒绝来自另一上下文但自身一致的状态。

服务策略固定一把身份钥和对应盐。论文 Figure 1 的 `OSign` 每次调用 KeyExt 并生成新的身份盐；因此这是有明确记录的服务模型差异。Proposition 5 的多次签名分布陈述本身不能闭合这个持久服务的 ROM／QROM 证明。

## 重放命令

最终测试和运行收据已在仓库的 WSL Sage 环境中核验：

```text
`PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_sageloli_ibs.py tests/test_sageloli_sampling.py tests/test_sageloli_uniform.py tests/test_sageloli_service_recovery.py tests/test_sageloli_probe.py` → **145 passed, 0 failed, 0 skipped in 233.16 s** (WSL Ubuntu-24.04, Sage 10.9, Python 3.13.15). JUnit: `build/outputs/sageloli-complete-2026-10-16/sageloli-all.xml`。
```

该命令在 WSL Ubuntu-24.04、Sage 10.9、Python 3.13.15 中运行 1 次。不要把种子、主陷门、身份钥、签名或随机带写入本目录或 Git。

## 范围与剩余缺口

生命周期和攻击测试只是实现证据，不能证明 SIS／RSIS 困难性、论文 ROM／QROM 归约、固定服务归约、有限采样总变差、正式参数安全、NIST 等价性或任何 HIBE 组合。统一登记／CLI 和组合由统筹负责。来源映射记录论文中每处有意保留的歧义及工程差异。
