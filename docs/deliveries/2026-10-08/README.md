# 2026-10-08 整合交付：参数预筛、三组候选与组合优化

本轮完成远端队友研究的整合和复核，落实老师确认的多困难假设/多算法要求，交付有限参数预筛、具体三组优先候选，以及一个保持完整输入的组合上下文优化实现。正式安全参数、完整 HIBE/IBS 后端和整套 IBME 仍为 WIP，`security_claim: none`。

## 先看三份结果

1. [三组优先组合](../../research/2026-10-08-integration/三组优先组合与联合优化路线.md)：ABB10 §4 分别搭配原生 Foo–Li、认证型 ML-DSA-65、认证型 Falcon-1024 IBS。优势和具体转换、容量、模型及代码准入门槛分别列出；不是全局最优或三个已完成后端。
2. [参数预筛与成本](../../research/2026-10-06-parameters/FooLi有限参数预筛与成本审计.md)：36 个点、13 个解析通过，6 个通过点有 LLL 多项式排除界；9 个公开 SIS 对照找到短关系。所有点超出当前至少一项实现上限，不能直接放行安全参数。
3. [组合优化与公平基线](../../research/2026-10-08-integration/组合上下文复用优化与公平基线.md)：Core SHAKE 前缀准备和研究流逐字节等价；1 MiB 合成双组件上下文、128 块子环节最大中位加速 12.73 倍。不是完整 IBME 加速；联合编码及完整绑定混合包装尚为设计。

## 已整合及核验的队友工作

远端基线为 [PR #3](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/3)，合并头 `35fb11a`。读取了总交付、Lean 关键条件类型、采样契约和实际生命周期；复跑 195 项相关测试，检查 95 个交付文件及 34 个复用源码指纹，均一致。

队友实际研究发钥、签验和恢复已有证据，Lean 总包仍为 `partial_formal_closure`。本机没有指定 Lean 工具链，未重跑 Lean，未声称解除 `hMP12`、实际随机程序精化或 SHAKE 差值。组会冲突解决同时保留队友最新结果和老师确认的范围。

## 本轮提交与文件边界

| 提交 | 范围 |
|---|---|
| `50f8ac3` `chore(sync): integrate teammate Foo-Li correctness research` | 整合远端既有提交，手工解决组会文档冲突，保留两方内容 |
| `485b981` `docs(scope): require both assumption and algorithm instances` | AGENTS、架构、规范、工作流、README、进度、组会及多实例口径 |
| `5f88a77` `feat(research): audit finite Foo-Li parameters and SIS exclusions` | `foo_li_parameter_screen.py`、对应测试、参数报告/原始结果/验证记录，共 5 个文件 |
| `6c913d8` `perf(research): reuse complete SHAKE context prefixes` | Core hashing 辅助 API、研究流/基准、2 个测试模块、实现规范、优化报告/原始数据/验证记录，共 9 个文件 |
| `618c119` `fix(audit): make text fingerprints portable across line endings` | 优化记录使用 LF 规范化文本指纹，另保留原工作树指纹 |

本交付及最后的选型文档提交包含：`AGENTS.md`、`README.md`、`docs/PROJECT_RESTART.md`、`papers/index.md`、三份新增原始 PDF、`papers/portfolio-manifest-2026-10-08.json`、三组候选报告和本 README。提交哈希以 Git 日志及最终回复为准。

跨 Core/研究/测试/规范的原因是复用 Core 拥有的原始域编码，精确保持字节流与私钥生命周期。没有改变六个冻结域、原 `shake256` 输出、生产 HIBE/IBS/协议或参数；优化适配器显式注入，不自动注册生产后端。三份新 PDF 原样保存，旧五篇 manifest 和队友冻结证据未修改。

## 命令与结果

统一从仓库根目录的 WSL Sage 环境运行，路径为 `~/miniconda3/envs/sage`。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ~/miniconda3/envs/sage/bin/python \
  -m pytest -q -p no:cacheprovider tests/test_foo_li_parameter_screen.py \
  tests/test_foo_li_oracle_model.py tests/test_foo_li_runtime_reference.py \
  tests/test_online_sampling_reference.py tests/test_encoding.py
```

参数相关 **227 passed in 47.21s**，包含新 32 项。第一次新测试 4 项失败已在参数报告记录并修复，最终没有失败。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ~/miniconda3/envs/sage/bin/python \
  -m pytest -q -p no:cacheprovider tests/test_prepared_hashing.py \
  tests/test_prepared_context_stream.py tests/test_encoding.py \
  tests/test_foo_li_runtime_reference.py tests/test_foo_li_oracle_model.py \
  tests/test_online_sampling_reference.py
```

优化相关 **219 passed in 3.69s**，包含新 24 项。两个批次有重叠，不累计成 446 个独立检查。

参数审计、基准生成和精确校验入口在各报告中；本机 CPU 为 Intel Core Ultra 9 275HX，Sage 10.9。基准 9 组，每组每方法 7 次，交替顺序，包含编码/首次准备，126 次计时输出检查一致；未测 RSS，也未运行安全参数下的完整性能比较。

附加交付检查：新增资料 `%PDF`/页数/指纹、本地链接、原始 SIS 向量方程及范数、未改写冻结证据、便携文本指纹与 `git diff --check`。源参数范围、消息/身份长度、模型及重复数分别随报告保存。

## 剩余工作

认证型 IBS 的固定密钥及普通/强不可伪造归约、明确查询损失和可恢复格式先冻结，再实施 B 的研究后端；Foo–Li 继续收紧严格质量/提取范数并估计未排除候选的经典/量子成本。匿名 HIBE、合法参数、完整胶囊/消息认证、真实端到端消融和三套配置实现仍待完成。

本轮没有完成量子安全证明、NIST 等级、增强隐私或旧漏洞修复。测试和现成组件不替代组合安全证明，代码复用和普通哈希复制本身不宣称密码学原创。
