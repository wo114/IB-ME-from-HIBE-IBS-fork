# PR43／46／47／48 审查与接收记录

本轮按用户“审查远端 PR 并尝试合并”的授权执行。接收基线 `8cc69c72a26bd91c0defc2052f92bd0780f0bb21`；原 B 开发分支及 Foo–Li 本地 WIP 保留。源码合入与研究／安全准入分别判断，遵守 2026-10-18 的论文安全／匿名工作前提，不新增基础证明任务。

| PR | 固定原始 head | 审查范围 |
|---|---|---|
| [43](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/43) | `fa912804749d64977078579e1691a2ed083171c2` | 320 个 SRGG 范围文件；独立 source-Schur／参数与来源研究，默认 joint 选择不变，WIP 属性保留 |
| [46](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/46) | `0c68a27c03d5092b369a95d636bc34091f6fbf33` | 三组完整系统展示卡、原收据／源码绑定及校验器 |
| [47](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/47) | `8fdac5c91e2739ef93a03cb81242bc19670b13ae` | 基于 PR46 的同版本报告、演示材料与绑定 |
| [48](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/48) | `9da2c1689b0263b265c2e81a2785ad0cd35cafb3` | 93-bit q 的独立高基数 3m seed KEM、真实根／父／256 叶／32 B 采样与严格 wire；不计新 HIBE |

三个只读审查分别覆盖 PR43、PR48、PR46/47。未发现需阻止源算法／材料接收的 P0/P1；本轮定位的版本集成、文案和运行环境问题如下。合入的精确提交和最终状态以对应 PR 及 Git 记录为准，不把远端全绿当作本机实际执行。

## 实际验证

在规定 WSL conda `~/miniconda3/envs/sage`（本机 Sage 10.7、Python 3.12.13）运行：

```sh
source ~/miniconda3/etc/profile.d/conda.sh
conda activate sage
PYTHONPATH=.:src:.pytest-tmp-sage-deps PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_srgg*.py tests/test_radix_kem.py tests/test_mp12_radix_runtime.py tests/test_blocked_3m_objects.py tests/test_ci_catalog.py tests/test_sageloli_probe.py --basetemp=.pytest-tmp-pr-review-oct18-sage -q
```

首轮 **2024 passed、2 failed、0 skipped**，554.03 秒。两项失败都是新建私有目录应为 0700 的 POSIX 检查：临时目录在 `/mnt/d` 的 Windows 挂载盘上返回 0777；没有改算法或删掉权限断言。将这两项的临时目录改到原生 Linux `/tmp` 后，**2 passed、0 skipped**，4.55 秒。首轮与复验分别归档，不相加伪装成一次全绿执行：

```sh
PYTHONPATH=.:src:.pytest-tmp-sage-deps PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest tests/test_srgg_service.py::test_new_issuer_directory_is_private_on_posix tests/test_srgg_structured_service.py::test_new_issuer_directory_is_private_on_posix --basetemp=/tmp/ibme-pr-review-2026-10-18-permissions -q
```

原始记录为 [`sage-initial.junit.xml`](sage-initial.junit.xml) 和 [`sage-posix-replay.junit.xml`](sage-posix-replay.junit.xml)。首轮命令当时使用的 PYTHONPATH 为 `.pytest-tmp-sage-deps:src`；pytest 会加入仓库根，实际执行通过。直接运行交付脚本及其子进程时必须显式包含 `.`，见下段。

材料在精确 PR47 独立快照中用 Windows Python 3.14 实际运行两个原校验器：展示卡 **392 checks**、报告材料 **164 checks**，退出码均 0。另从原始 phases 重算全部 27 项显示计时中位数及次数，核对三个原收据对应提交的 2340 个源码 provider。主 Suite digest 为 `10a23d28bfdf9b2e18b140149561c43d62f2649feb78b72510d350b419233346`。没有为此重新生成密码密钥或重跑历史性能实验。

合并前远端检查：PR43 为 23 success／1 预期手动 skipped；PR46、47、48 各 46 success／2 预期手动 skipped。`main` 分支规则查询返回空数组，账号有 push 权限；接收仍依赖上述实际审查和验证，没有使用管理员绕过或强制推送。

## SRGG 历史证据的版本集成

完整扫描原 source-Schur 清单 246 项，最终合并树只有三个非 SRGG 文件与冻结字节不同：CI suites、MP12 extension、prime gadget。CI 与 prime gadget 的部分漂移在本轮前的主线已经存在，不能全部归因于 PR48。

修正发布桥接时同时检查旧清单、旧快照和固定当前字节；新增 prime gadget 原字节快照，CI 固定为含 PR48 的 12473 B／`251bffb7d8306aee12241c4002daa6d01ae36b14f853e91b27f7857ec5b583bd`。现在是 **243 项直接匹配、3 项明确桥接**。原 source-Schur MANIFEST／validation 和原集成 validation 均保持字节；没有沿旧哈希链改写历史结果，也没有把原算法切换成快照代码。

修正后的 `verify_publication.py` 已由独立审查者在普通和 `-O` 模式各运行通过。批量原驱动在本机存在一处环境元数据限制：random-key-sign-law 冻结环境为 Python 3.13.15／Sage 10.9／WSL 6.18，当前为 Python 3.12.13／Sage 10.7／WSL 6.6；其原 verifier 比较整个报告导致失败。独立六行重放确认，除 `environment.platform/python/sage` 三项外，所有数学值、上下文与前驱哈希、重放布尔、安全／null 字段完全相同。保留原 verifier 和回执，**不宣称本机原驱动 38/38 通过**。

完整逐包普通／优化模式检查为 **36 次原校验成功、2 次原环境元数据断言失败**；后两项另以普通／优化模式独立重放六行数学报告，均通过，非环境规范 payload SHA-256 为 `31444a9cb1b70341d8bb751ecc82b6d440d984348fcd51aa4e660748776fcb23`。运行前后 246 项源码与材料字节一致，没有其他失败或差异。精确退出码、输出、环境及命令见 [`publication-review.json`](publication-review.json)。运行直接脚本时使用 `PYTHONPATH=.:src:.pytest-tmp-sage-deps`；一次遗漏 `.` 的本机命令造成子进程导入 `experiments` 失败，已纠正，不作为源码问题或通过结果。

## 材料冲突与文案

PR46 的进度文档与主线冲突，需保留主线 IBS 接入盘点、C64B 实测及 ABB10／CHKP 接手安排，再加入展示卡。PR47 继续按依赖顺序接收，进度文档不得以旧头覆盖这些更新。

报告及同批 README 将包含 `compare.py` 的命令组称为“只读”不准确：该比较脚本会写回 `comparison.json`。材料合入时须明确先生成／核验比较数据，再执行两个只读校验器，并同步报告在 materials.json 的 SHA-256；其余原收据、cards、Suite 与计时保持不变。

PR43 仍为独立研究 WIP；PR48 仍为组件，不宣称公共 HIBEBackend、Hybrid、CLI 或完整 IB-ME。三张展示卡共用一个 LATTE HIBE；不计三种 HIBE，不作跨安全目标速度排名。安全字段保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`，未新增安全等级或基础安全证明。
