# SRGG DeepSeek 交付工程修复（2026-10-19）

论文：Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*，DOI `10.1049/ise2/6684889`。[English](README.md)。

本批按新 `AGENTS.md` 的研发前提推进：引用原文、保留工作假设与已知问题，不重新安排安全证明。只修异常、门控入口、验证器、版本说明与当前交付指纹，不处理 HIBE、不推送远端。

## 版本与边界

- 统一 guard 输入：`7131eaa60e874a1a48a355c6369de7efc3185873`。
- 分布链与注册输入：`9af579d32d574a4cf626ec40a258db721c89e105`。
- 两者汇集于本地 `b544567`，原分支与历史提交保留。
- 原 Table 4 三组 `n=512,p=16383,b=31,w=2,q=961,Q=15744063,d=2/3/4`、原宽度、`r=1.16`、范数门和签名方程均保持；两种 Gaussian 解释仍分开。

## 修复内容

1. master/sign plan 的准备与审计在同一异常边界：可预见的数值准备失败进入根重试或固定密钥中止；外部 I/O、内存和进程异常不伪装成新的根。
2. `GuardedSourceSchurBackend` 与异常旧名指向统一实现，不再重复审计。旧快照恢复保持原密钥；规范解析不被表述为追认数值门，实际签名仍须过门。
3. 失效的“未门控接受集差异”探针明确停用；签名门探针完整列出阶段失败，不静默丢弃尝试。
4. 两个新验证器采用显式检查，读取当前源码、文档、前置回执的固定指纹；普通 Python 与 `-O` 都必须拒绝篡改、重复字段、错误参数和越界声明。
5. 修复 random-key 回执的过期摘要，按依赖顺序重新绑定当前 v3 交付。保留旧数值、旧参数与原始 Git 来源；刷新指纹不被当作重新证明原文或重跑旧性能实验。
6. 明确数学事件 `G_C`、历史接受集 `B_legacy` 和当前实现门控集合；精确数学数值保留在显式条件字段。实际区间拒绝费用与接受律没有依据的部分保持 `null`，本批不为补证明而阻塞工程。
7. 历史比较仅指逻辑 API 输出与确定性持久状态，排除时间、内部采样轨迹和未建模故障。原 PR53 的旧后端时间/内存实测不自动归到新增 guard 路径。

## 复核

最终全量 **2071 passed，0 failed/error/skipped，808.14 秒**；其中已包含 86 项验证器正负控，不重复相加。九分包普通／`-O` 校验 18/18 通过，random-key 的两种模式也通过。262 个源码与测试指纹在最终回归前后一致；7 个原算法／参数文件及签名主体保持不变，24 个已有精确数值字段保持不变，见 [invariants.json](invariants.json)。

指定 WSL Sage 环境：

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-independent-followup/verify_all.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/verify_delivery.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -O docs/research/team-b-delivery/2026-10-18-srgg-random-key-sign-law/verify_delivery.py
```

两个新包支持标准库离线校验及同样的 `-O` 命令；负向验证测试不需要 Sage：

```text
python -m pytest -q tests/test_srgg_deepseek_delivery_verifiers.py
python docs/research/team-b-delivery/2026-10-18-srgg-distribution-guard-deepseek/verify_delivery.py
python docs/research/team-b-delivery/2026-10-18-srgg-distribution-chain/verify_delivery.py
```

最终测试命令、计数、回执重放与文件清单记录于本包 `validation.json`、`MANIFEST.json`。`refresh_bindings.py` 只维护当前交付的依赖指纹；运行后必须执行独立验证器，不能把刷新成功当作验收。

本包最终快照可用 `python verify_repair.py` 或 `python -O verify_repair.py` 校验；从仓库根目录调用时加上本包完整相对路径。

本次分布链诚实重放为两种解释 × 三组原参数各一轮，身份 `Alice` 为 5 B，消息实际为 31 B（测试字符串含“32B”字样，其真实长度为 31 B），不将它误报成 32 B。guard 见证还包括每组 3 个发钥／签名计划探针；实际次数以 JSON 为准，不将重叠检查相加成独立样本。固定种子只用于测试。身份目标使用 ROM。注入的错误仅测试实现策略，不是采样或安全实验。始终保留 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；功能与有限攻击测试不构成安全证明。
