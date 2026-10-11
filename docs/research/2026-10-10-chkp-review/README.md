# CHKP PR #6 审阅、合并与首套接入门槛

日期：2026-10-10。用户要求先看队友的新工作再继续主线。[PR #6](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/6) 已审阅、复跑并合并，合并提交 `0acd43ebd2a8f73a0268d7a7ebe5874f6793181f`，说明 `merge(chkp): integrate PR 6 research samplers and fixed leaf cache`。它交付了真实研究组件，完整 CHKP HIBE 和安全组合仍是 WIP。

## 实际收到的成果

70 个差异文件包含 T01 背景、完整整数格基与 ExtBasis、有限 AP09 GenBasis、一般列基 GPV SampleD、有限 RandBasis/ToBasis、可选精确 LLL、最大深度叶节点原像、固定容量缓存及恢复、参数预筛、证据、17 个测试文件和三份来源 PDF。所有新增算法都在研究目录；没有新增 `src/ibme/hibe/chkp.py`，没有改变运行时 HIBE 后端。

队友的[交付入口](../../deliveries/2026-10-10/README.md)和[CHKP 研究入口](../team-chkp/README.md)准确保留了 `none/false`、LLL 的额外后处理性质、当前小参数及参数阻塞。审阅重点为列基方向/核格完整性、采样和 ABORT 语义、资源与误差声明、私有缓存边界、规范恢复、以及是否误称完整原语。合并认可的是研究交付；并未认证其全部理论或授予安全等级。

## 跨组件核验新增的结果

新增主 AI 的[联合交接筛查器](../../../experiments/research/ibme_handoff_screen.py)和[机器结果](handoff.json)。它复用队友的论文关系预筛，从源码读取 GPV 维度、缓存容量、叶批容量和 Hybrid 种子常量，记录规范 LF 源码指纹；不会加载秘密状态、执行 Sage 代码或自动注册后端。

| 门槛 | 结果 | 含义 |
|---|---|---|
| 候选 v1：`n=2,m=64,q=65537,s1=16,s2=64` | 原静态预筛通过，但当前 AP09 路线不适配 | 静态通过与真实 GenBasis 可运行须分开 |
| 当前有限 AP09 最小尺寸 | `d=m1=35,m2=138`，根 173、一级 346、叶 519 | `d>n·ceil(log2 q)`、`m1>=d`、`m2>=2n·ceil(log2 q)+2d` 给出的算法内必要尺寸；根 64 不够，叶超过 GPV 上限 192 |
| 上述最小布局的质量条件 | 最小 Hadamard scale 为 18；GS² 证书上界 15440 | 该参数构造器已在 Sage 接受；没有生成实际基或抽样 |
| 无额外 LLL 的充分宽度传递 | `epsilon_bits=16` 时，证书路线需 `s1²=1605760,s2²=60004039680` | 按当前 C1-exec 和 RandBasis 成功时 GS 上界传递；相同 q 不满足该路线的叶正确性关系 |
| 固定 bit 地址 | 当前单缓存/单批各最多 32 个原像；Hybrid 种子 32 B，至少 256 bit | 缓存的 32 是原像数，不是字节容量；内层 framing 可继续增加 bit 需求 |

**充分宽度不是实际最小宽度，更不是 CHKP 不可实现的证明。** 实际 GS 或不同的合格 GenBasis 可改变结果；LLL 的当前上限也须计入。上述计算说明：仅把 192 上限改成 519，不足以据此宣称候选 v1 的真实采样和解密已经闭合。AP09 最小布局没有保证公开分布距均匀足够小，公开分布误差必须另算。

## 本轮作出的接入决定及下一步

现有 AP09/GPV 保留为可复核参考路线。`n=2,m=64,q=65537,s1=16,s2=64` 保留为论文关系演示和实现不适配对照，暂不作为真实组件运行配置。下一轮先完成一组诊断参数的联合可行性核验，再确定资源上限；实际安全参数另行估计。单独增大 q 或单独放宽维度不构成验收。

队友的下一项是把 **根生成尺寸与近均匀误差、各级实际/证书 GS、采样宽度、随机带/内存、alpha/噪声和正确性关系** 放入同一记录。若当前有限 AP09 的尺寸/资源仍不适配，再独立选择一套已有文献支持的 GenBasis 实现；保持 CHKP 框架与已引用定理的前提，不重新写整套基础证明。

T3/T4 同时须给 256 或更多固定 bit 地址确定公开容量、分批采样与完整私有 wire 预算。现有同一 child 的缓存禁止换 plan，不能通过对同一地址切换批次来拼接种子，也不能在解密时重抽已有原像。主 AI 负责磁盘事务和协议接入，已经在[接收状态修复报告](../2026-10-10-receiver-persistence/README.md)推进；队友负责真实 H/G、bit Encaps/Decaps、字节适配及原语契约。

## 本轮验证

合并前差异检查通过；GitHub 已确认 PR 状态为 MERGED。相关批次有重叠，不相加为独立检查总数。

```text
wsl bash -lc 'cd /mnt/d/zcode_projects/ibme && PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_chkp*.py tests/test_hybrid_key_binding.py tests/test_research_state_integrity.py --tb=short --junitxml=test-results/pr6-sage-review.xml'
541 passed in 88.44s

python -B -m pytest -q -p no:cacheprovider tests/test_chkp_paper_preflight.py tests/test_chkp_t2_conditions.py tests/test_cli_state_lock.py --tb=short --junitxml=test-results/pr6-native-review.xml
68 passed in 0.31s

python -B -m pytest -q -p no:cacheprovider tests/test_ibme_handoff_screen.py --tb=short --junitxml=test-results/handoff-screen-native.xml
7 passed, 2 skipped in 0.17s

PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -B -m pytest -q -p no:cacheprovider tests/test_ibme_handoff_screen.py --tb=short --junitxml=test-results/handoff-screen-sage.xml
9 passed in 2.09s
```

541 项包含队友 495 项和原密钥绑定/状态 46 项。筛查器首轮曾因常量的元组赋值漏读而有 2 项失败；修正只读 AST 解析后，上列最终结果通过。Windows 的两个 skip 是 AP09 构造器核对，Sage 已执行通过。硬件 Intel Core Ultra9 275HX；Windows Python 3.14.6、WSL Sage 10.9/Python 3.13.14，pytest 9.1.1。本轮是静态整合与构造器检查，不是性能实验；输入是上述两个教学/诊断元组，身份/消息/重复次数不适用于此计算。

## 文件与安全口径

本项我方新增文件为 `experiments/research/ibme_handoff_screen.py`、`tests/test_ibme_handoff_screen.py`、本 README 和 `handoff.json`；PR 的 70 个合并文件可在 PR 差异中逐一审查。跨范围原因是主 AI 核对已交付原语研究与冻结载荷契约；没有修改队友算法文件。

全部 `backend_admitted=false`、`parameters_are_formal=false`、`security_claim=none`。模型保留经典 ROM；没有完整 HIBE、正式参数、QROM 或安全位数结论。测试及静态预筛不能替代安全证明，也没有给出端到端性能或 A+B<C。
