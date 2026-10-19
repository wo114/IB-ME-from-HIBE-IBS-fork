# SRGG 独立 IBS 续审的发布集成核验（WIP）

本包核对 PR #37 合并后的 SRGG 独立工作线，不含 DeepSeek 的 guarded/v1 改写，也不涉及 HIBE。发布分支以 `upstream/main` 的 `d861fe9` 为基线，将 `7353770..d1071b6` 的 41 个 SRGG 提交整合进去。原文是仓库冻结的 `papers/2025_efficient_ibs_jia.pdf`（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`）。

## 冻结证据与当前主线的差别

[原 source-Schur 包](../2026-10-18-srgg-source-schur/README_zh-CN.md)的 `MANIFEST.json`（SHA-256 `cb763a00b8f3c71dd27767ac05721abf61138e4fc9bc302471330e38d95cb081`）与 `validation.json`（SHA-256 `4757218ca76254b97a17c685e8c8714c1e52675fec2c7963d4c56e62e3533e6f`）保持原字节。最初发布桥接了 `ci/suites.json` 和 `src/ibme/lattice/matrix_sampling/mp12_extension.py` 两个非 SRGG 文件；当前主线 `8cc69c7` 还包含既有高基数 `prime_gadget.py` 变更与 CI 更新，PR48 又在 CI 中新增 `test_radix_kem.py`。本轮完整扫描确认最终树恰有这三个非 SRGG 文件与原包不同，没有 SRGG 源码漂移。该差异不能全部归因于 PR48，也不是 source-Schur 实验重跑或原论文分布证明的变化。

[`verify_publication.py`](verify_publication.py)逐项核对原清单的 246 个文件：243 项直接与当前工作树吻合；三项桥接同时核对旧清单、旧字节快照及最终树的固定当前字节。CI 当前值明确固定为 PR48 的 12473 B / `251bffb7d8306aee12241c4002daa6d01ae36b14f853e91b27f7857ec5b583bd`；新增 prime-gadget 快照固定为原包的 5536 B / `f936c51e407c11f7d0f13c102f03a77fdebab900b449496c806f9cb156b90311`。它仅在执行原版 verifier 时替换三份旧字节，以复核原包的全部生命周期、安全标记和其他来源绑定。未放宽为忽略任意后续漂移，未替换实际运行代码。发钥、历史、故障材料引用的原清单哈希完全保留，不沿哈希链重写旧回执。该集成核验不能把旧实验结果提升为新主线重跑的结果。

[故障历史包](../2026-10-18-srgg-fault-history-law/README_zh-CN.md)原 `MANIFEST.json` 把 `validation.json` 的混合换行生成态记为 932 B / `6409c2fe…`，而 Git 中规范 LF 文件是 914 B / `3ff06195…`。本次只修正清单该一项，回执内容未变；原错误记录仍可从父提交 `d1071b6` 追溯。

## 范围与验收

旧 v1 回执中的 `fixed_root_only` 是**证据生成范围标签**，不能解读为数值不等式仅在这六条根上成立。那些不等式所用门限 64 与其余数值常数不随根变；六根是已执行见证。但此 PR 没有交付把条件界施加到全部可接受根的完整 guard/服务路径，因此旧包仍是历史 WIP，不能称作接受集定理。DeepSeek 的改写单独交付。

原 Table 4 三行参数保持 `n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`，Gaussian 两种解释分别标记。规定的 WSL Sage 10.9／Python 3.13.15 环境下，整合代码的 `PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg*.py` 得到 **1954 passed**（515.03 秒）；旧九包普通与 `-O` 校验均通过。故障历史修正后 verifier 已通过；运行 [`verify_all_publication.py`](verify_all_publication.py) 对 19 个交付包作普通与 `python -O` 双模式校验，**38/38 通过**，其中 source-Schur 使用上述旧字节快照。命令与结果记录于 [validation.json](validation.json)。

上段测试和 `validation.json` 是最初发布批次的历史收据，其 244/2 计数保持原样；本轮最终树改为 243/3，实际重放和命令另行归档到本次 PR 审查记录，不能据此改写旧执行次数或声称重新运行原论文参数生命周期。

原文采样／参数对应、QROM 模拟、真实结构攻击成本、完整随机发钥后签名与故障历史、原生 strong 的同消息替换问题仍未闭合；旧回执中的公开替换反例须保留。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。功能测试及历史包通过不等于正式安全证明或 NIST 等级。

2026-10-19 PR52 集成：CI 仅将已交付 Sageloli SIS／RSIS 的来源改为 backend.py、阶段改为 standalone_source；原测试选择及算法计数不变。当前 CI 固定字节更新为 12493 B／`2ae1556512a95d52b97940d9fb712c5e946375b1a19c948ad302eb0c85faaeeb`，原 CI 快照与历史 validation 保留，源码清单仍为243项直接匹配＋3项显式桥接。
