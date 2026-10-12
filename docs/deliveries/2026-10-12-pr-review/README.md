# #9—#12 独立审查与合入记录

日期：2026-10-12（Asia/Shanghai）。用户要求审查全部未合并 PR，合格者直接合并；本批开工时有 #9/#10/#11/#12 四个。本批全部已合入 `main`，源码接收基点 `7686fd906198e74d3ce140c542908ae253e20ef5`。这是研究代码的接收，不是正式安全准入或整个项目完成。

## 1. 版本、结论与合入关系

| PR | 固定审查 head | 结论 / GitHub 合入记录 |
|---|---|---|
| [#10 规范/目录](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/10) | `2868cf54411188562440820eba266ca3dd278fd9` | 内容已完整包含在 #11；随 #11 接收并被 GitHub 标记 MERGED。保留 Git 历史，没有重复合并旧规范；提供者 mergeCommit 为 `f61eb5727f2b1556da9dc9d7a2889660325ec977` |
| [#11 公共装配/分工](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/11) | `57a02e597ddde9cef30dd16bf2874ab9cd192b17` | 注册/能力/容量、严格 suite、CLI v2/恢复、源驱动与修正分工可接收；`4bda55121467e3059d9618417172293d9594d53a` |
| [#9 Luo 交付](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/9) | `e5e0b97752f9291ce7621dd830d665baff86aef8` | C64B 17字段 helper、专用入口 profile 绑定、理论条件/证据工具及真实恢复可接收；`00e4345b32399b22e4f579ba4ba5c54c2652a582` |
| [#12 MP12 研究 HIBE](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/12) | `77957196f1d7fabb80cf2a18a05064fbd7ecc32c` | 六方法/真实委派、对象/绑定/固定状态、自定义 registry 的 source/Sage 研究实现可接收；先将 base 从镜像分支改为 main，再合入 `7686fd906198e74d3ce140c542908ae253e20ef5` |

本批没有发现需要阻止这些研究模块合入的代码问题。#10 的旧期限/单主原语分工已由 #11 `57a02e5` 修正；不把旧规范单独覆盖到最新 main。Draft 依本轮用户授权转为 ready 后合并，使用 merge 方法保留依赖历史，指定 expected head，不强推、不绕过保护、不删除仍可用于其它工作的分支。

## 2. 实际审查范围

- #10：共同接口与算法专属约束的分离、19条目录及新增原文/代码边界；模型/参数/源码/实跑/准入不混计。
- #11：`assembly/registry`、SuiteConfig/预检/容量、factory/decoders/公开绑定、CLI 配置/公钥/对象外壳、选参互斥、状态恢复/保存顺序、硬链接输出保护、公共 runner。没有未交付原语的 mock 降级。
- #9：C64B 与原默认逐字段区分，Setup 错 profile 在熵前拒绝，研究读取器与两格式绑定、最新共同装配/恢复、条件证书与原始账本的来源和失败留痕。没有把条件可用性指数当安全等级。
- #12：计算型根与统计根分 profile、真实 Extract→Derive、H/G 与公开 context、固定256原像、方程/核格/GS/宽度、规范整数/资源/对象绑定、失败地址恢复、32 B 种子、明确公开攻击负控。没有把它改名为原 CHKP 或正式安全后端。

原工作树在审查过程中出现另一轮部署实现的未提交改动。我们保留这些文件，迁到新管理工作树审查；旧树中断的联合运行不计结果。最终所有测试在干净、固定联合源码 `ea62d6543a16a07bd3c5a3a2c94cfe0f5d1dd3e9` 执行；合入后的 `src/`、`tests/`、`experiments/` 与它完全相同。各原 PR 的已有 CI 成功是补充证据，不替代本轮合并后的源码核对。

## 3. 本轮命令与结果

Windows 独立回归：

```text
python -m pytest -p no:cacheprovider -q --tb=short tests/test_assembly.py tests/test_cli_selection.py tests/test_combination_matrix.py tests/test_luo_c64b_profile.py tests/luo_acceptance tests/test_luo_acceptance_evidence.py tests/test_luo_cross_version_harness.py tests/test_luo_lifecycle_contract.py tests/test_luo_robust_abort_certificate.py --junitxml=test-results/pr-review-integration.xml
```

首轮 **243 passed / 1 failed**，唯一失败是隔离 checkout 尚未安装 Python 包，证书子进程无法导入 `ibme`。没有数学断言失败或密码代码改动。统一设置当前工作树 `PYTHONPATH=src` 后，仅重跑受影响证书文件，**39 passed**；原244个唯一用例的失败已关闭，不再重复耗时的无关密码测试。保留[初次 JUnit](initial-integration.junit.xml)与[复跑 JUnit](certificate-fixed-env.junit.xml)，不删除失败历史。

```text
PYTHONPATH=src python -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_robust_abort_certificate.py --junitxml=test-results/pr-review-certificate-fixed-env.xml
python -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_candidate_evidence.py tests/test_luo_candidate_probe.py tests/test_luo_lifecycle_evidence.py tests/test_luo_lifecycle_runner.py tests/test_luo_acceptance_evidence.py --junitxml=test-results/pr-review-evidence.xml
```

第二行证据/实验工具 **69 passed**，其中与首轮重叠的用例不重复计数；[JUnit](evidence.junit.xml)。Windows Python 3.14.6，准确环境见[机器收据](review.json)。上述 `PYTHONPATH=src` 为环境说明，PowerShell 实际用 `$env:PYTHONPATH`；子进程同样继承该源路径。

指定 WSL Sage 环境：

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest -p no:cacheprovider -q --tb=short tests/test_first_suite_hibe_reference.py --junitxml=test-results/pr-review-sage.xml
```

**48 passed、无 skip，34.13 s**；[JUnit](sage.junit.xml)。包括实际计算型根生成、绑定/规范解析、固定状态、失败不重试、真实已有密钥恢复/载荷边界；fixture从既有真实 n2 交付复制到本机被忽略目录，转换 engine 亦为既有冻结编译产物。没有把拷贝称新发钥，原21项完整探针收据/54次性能批次没有重跑。

当前 C64B 装配源固定后实跑：

```text
python experiments/research/luo_assembly_handoff.py --target-root . --head ea62d6543a16a07bd3c5a3a2c94cfe0f5d1dd3e9 --profile-json docs/research/2026-10-11-luo-c64b-handoff/profile.json
```

**25项检查通过**：[原始收据](c64b-assembly.json)。reference 为预检，compact 为实际 Setup/发钥/最大3924 B消息/恢复/错身份和篡改拒绝；16383 B签名、20415 B外载荷。此条仍是教学 ABB10 HIBE，不能计成 MP12/原CHKP+C64B 已验收。原 PR #9 的 `0bf0855` 收据仍作历史，本条才是当前联合代码复跑。

合计按 `(classname,name)` 去重并用环境复跑覆盖已修正失败，**350个独立 pytest 用例最终通过**；25个探针断言另计。没有把39/69中的重复用例相加，也没有把历史/skip算本轮成功。首次文件通配符错误、错误源 head 的预检拒绝和中止的旧树运行均在收据标记，不计密码执行。

## 4. 参数、安全与材料界限

本轮没有改密码代码/参数：教学 ABB10/负控、默认 Luo 与明确 C64B，以及 MP12 n2 的原固定输入均保留。具体输入、重复/缓存/源环境在测试代码、公共 probe 和对应原交付记录中；这不是公平性能实验，测试和探针曾并行，不能从时间得 A+B<C 或方案排名。

MP12 n2/q549755813911 公开恢复已成功，C64B 条件可用性/模型、正式参数、变体定理对应仍待核；全部相关研究继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。原 CHKP/RandBasis、忠实 ABB-ROM、默认入口/wheel、其它方案与全就绪池、正式安全实例和最终作品仍未完成。测试通过不构成 SIS/LWE/IBME 或 QROM 安全证明。

合入后发现现行规范仍将整个 first_suite 概括为“没有后端”，以及状态把 C64B/#12写成未合并；本次只修正这些文档事实、补 C64B 专属契约和 T0 当前批次状态，不动历史交付/结果/失败数据。不接收另一轮部署的未提交源码。

归档只含源码/版本、JUnit、公共 JSON 和审查结论；主私钥、真实私钥/基/原像/生产种子与复制的 private fixture不进入 Git。main工作目录原三个未跟踪论文/清单保持数据完整，不盲目清理。

## 5. 本次文档提交文件

- 更新 `IMPLEMENTATION_SPEC.md`、`ARCHITECTURE.md`，解释自定义 source 后端与原CHKP/默认CLI的边界。
- 更新 `docs/specs/first-suite-research.md`、`docs/specs/luo-ibs.md`、`docs/PROJECT_STATUS.md`、`docs/workplans/2026-10-12/tasks.json`，同步准确信息和本批接收状态。
- 新增本目录 `README.md`、`review.json`、`c64b-assembly.json`、`initial-integration.junit.xml`、`certificate-fixed-env.junit.xml`、`evidence.junit.xml`、`sage.junit.xml`。

源代码和测试没有因文档修订改变，按规范完成链接/JSON/任务一致性、`git diff --check` 和最终状态检查后提交。提交信息：`docs(review): record PR acceptance and align research contracts`；准确提交哈希由最终交付和 Git 历史定位。
