# 本地同步记录（2026-10-12）

## 同步边界

- 当前分支：`codex/independent-primitive-assembly-2026-10-11`。
- 框架及三人分工基点：`f98de52f25e117fa7e365c686c23e0c142d004b1`，已含上游 `bc22c9c`。
- 新合入 Luo 固定提交：`c43c232`、`f079ce1`、`886fc12`、`e5e0b97752f9291ce7621dd830d665baff86aef8`。
- 已执行 `git fetch --all`。合并无冲突；未提交的 Luo 第二十四步不纳入此同步切点。
- 保留现有 6 个未提交路径，包括 README 改动和用户已有删除；同步前后逐文件 SHA-256 一致。合并时尚未修改状态页之前，既有工作区 diff 亦逐字节一致。
- 本次仅合入本地；没有合并远端 PR 或切换到旧的本地 main。

## 修改文件

Luo 原分支的 144 个文件列于 [merged-files.txt](merged-files.txt)。其中运行源码仅为新增 `src/ibme/ibs/luo_module_profiles.py` 及修改 `src/ibme/protocol/luo_hybrid.py`；其它是研究脚本、测试及历史证据。

本次额外更新 [PROJECT_STATUS](../../PROJECT_STATUS.md)、[三人分工](../../workplans/三人方案分工与统一框架交付.md)，将已合入内容与待固定外部工作分开；新增本目录 README、文件清单、两份 JUnit、字节属性和 SHA-256 清单。

## 本次执行与结果

在合并后的工作树、Python 环境 `PYTHONPATH=src`、`PYTHONDONTWRITEBYTECODE=1` 下执行：

```text
python -B -m pytest tests/test_assembly.py tests/test_combination_matrix.py tests/test_cli_selection.py tests/test_cli_receiver_state.py tests/test_cli_state_lock.py tests/test_luo_c64b_profile.py tests/test_luo_cross_version_harness.py -q --junitxml=.../sync-regression.junit.xml
python -B -m pytest tests/test_luo_hybrid_ibme.py -q --junitxml=.../legacy-runtime.junit.xml
python -B experiments/research/audit_luo_c64b_delivery.py
python -B experiments/research/audit_luo_c64b_selection.py --repo .
git diff --check
git diff --cached --check
```

- [框架及 C64B 回归](sync-regression.junit.xml)：173 passed / 3 skipped，77.97 s；三项跳过依赖 Sage 的真实叶缓存。
- [旧研究入口与 CLI](legacy-runtime.junit.xml)：25 passed，269.24 s。
- C64B 交付审计：exit 0，25 个清单文件及历史收据一致。
- C64B 参数算术与证据检查：exit 0，28 个谓词全部通过；未重跑估计器或参数网格。
- 合计本次 pytest 为 198 passed / 3 skipped；历史 25 项最大容量装配收据没有被替换或冒称本次重跑。
- 两项 Git 空白检查通过。测试私有状态在 pytest 临时目录中，不纳入提交。

## 参数和边界

C64B 的完整 17 字段见 [profile.json](../../research/2026-10-11-luo-c64b-handoff/profile.json)，对应 `c64b_params()`；旧默认配置保持不变。C64B 测试覆盖 reference/compact 的诚实往返、对象恢复、固定发钥、错身份与篡改。组合 HIBE 为教学 ABB10 + Hybrid，身份 Alice/Bob，包含二进制、空消息与最大 3924 B 应用消息的旧入口验收。固定测试随机源与 CLI 系统随机源依各测试实现记录，次数逐项见 JUnit；时长为本机功能回归时间，不作性能基准。

这些是实现与兼容性证据；研究组合保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。Luo 的经典 ROM 条件引用、启发式成本与测试不能合成为无条件安全等级；本次没有完成 CHKP 后端或安全参数准入。未跑全部仓库测试，未验证跨 OS/反回滚或完整形式安全证明。
