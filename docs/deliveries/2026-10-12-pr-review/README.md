# #9—#13 独立审查与合入记录

日期：2026-10-12（Asia/Shanghai）。用户要求审查全部未合并 PR，合格者直接合并；开工时有 #9/#10/#11/#12，期间新增 #13。本批五个 PR 均已合入 `main`，最终源码接收基点 `94f21683983921b2969ab5c5647d9cb2dab402b8`。#9—#12 的验证边界继续固定在 `7686fd9`，#13 单列下面追加验收。这是研究代码的接收，不是正式安全准入或整个项目完成。

## 1. 版本、结论与合入关系

| PR | 固定审查 head | 结论 / GitHub 合入记录 |
|---|---|---|
| [#10 规范/目录](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/10) | `2868cf54411188562440820eba266ca3dd278fd9` | 内容已完整包含在 #11；随 #11 接收并被 GitHub 标记 MERGED。保留 Git 历史，没有重复合并旧规范；提供者 mergeCommit 为 `f61eb5727f2b1556da9dc9d7a2889660325ec977` |
| [#11 公共装配/分工](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/11) | `57a02e597ddde9cef30dd16bf2874ab9cd192b17` | 注册/能力/容量、严格 suite、CLI v2/恢复、源驱动与修正分工可接收；`4bda55121467e3059d9618417172293d9594d53a` |
| [#9 Luo 交付](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/9) | `e5e0b97752f9291ce7621dd830d665baff86aef8` | C64B 17字段 helper、专用入口 profile 绑定、理论条件/证据工具及真实恢复可接收；`00e4345b32399b22e4f579ba4ba5c54c2652a582` |
| [#12 MP12 研究 HIBE](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/12) | `77957196f1d7fabb80cf2a18a05064fbd7ecc32c` | 六方法/真实委派、对象/绑定/固定状态、自定义 registry 的 source/Sage 研究实现可接收；先将 base 从镜像分支改为 main，再合入 `7686fd906198e74d3ce140c542908ae253e20ef5` |
| [#13 安装/公共入口](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/13) | 最终 `3c8441f84f8cedf17aa545129a1498d1d9f3c24c` | 安装/API/默认可选登记可接收；修正并加强独立性测试，协调主线文档冲突，两组远端 basic/hybrid 均成功；`94f21683983921b2969ab5c5647d9cb2dab402b8` |

首批没有发现阻止研究模块合入的代码问题；#13 发现并修复一项真实 CI 契约失败后才合入。#10 的旧期限/单主原语分工已由 #11 `57a02e5` 修正；不把旧规范单独覆盖到最新 main。Draft 依本轮用户授权转为 ready 后合并，使用 merge 方法保留依赖历史，指定 expected head，不强推、不绕过保护、不删除仍可用于其它工作的分支。

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

MP12 n2/q549755813911 公开恢复已成功，C64B 条件可用性/模型、正式参数、变体定理对应仍待核；全部相关研究继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。#13 已补默认可选入口/wheel；原 CHKP/RandBasis、忠实 ABB-ROM、正式大尺寸/模型、其它方案与全就绪池、正式安全实例和最终作品仍未完成。测试通过不构成 SIS/LWE/IBME 或 QROM 安全证明。

合入后发现现行规范仍将整个 first_suite 概括为“没有后端”，以及状态把 C64B/#12写成未合并；本次只修正这些文档事实、补 C64B 专属契约和 T0 当前批次状态，不动历史交付/结果/失败数据。不接收另一轮部署的未提交源码。

归档只含源码/版本、JUnit、公共 JSON 和审查结论；主私钥、真实私钥/基/原像/生产种子与复制的 private fixture不进入 Git。main工作目录原三个未跟踪论文/清单保持数据完整，不盲目清理。

## 5. 本次文档提交文件

- 更新 `IMPLEMENTATION_SPEC.md`、`ARCHITECTURE.md`，解释自定义 source 后端与原CHKP/默认CLI的边界。
- 更新 `docs/specs/first-suite-research.md`、`docs/specs/luo-ibs.md`、`docs/PROJECT_STATUS.md`、`docs/workplans/2026-10-12/tasks.json`，同步准确信息和本批接收状态。
- 新增本目录 `README.md`、`review.json`、`c64b-assembly.json`、`initial-integration.junit.xml`、`certificate-fixed-env.junit.xml`、`evidence.junit.xml`、`sage.junit.xml`。

源代码和测试没有因文档修订改变，按规范完成链接/JSON/任务一致性、`git diff --check` 和最终状态检查后提交。提交信息：`docs(review): record PR acceptance and align research contracts`；准确提交哈希由最终交付和 Git 历史定位。

## 6. #13 追加审查、修复与安装验证

初始 `46d623c` 的两次远端 basic-checks 失败在 `test_source_only_fresh_process_without_experiments`：原断言要求 `experiments` 不可见，但新 wheel 正需要其部分支持代码。依赖是否安装不等于 Luo 是否依赖它，不能删除整个测试或标为 skip。审查修正和队友同时提交的 `c026f9f` 合并，保留确实可见且一旦执行即报错的临时 namespace、最高优先级导入拦截器、自检以及完整恢复/缓存/Sign/Verify。另增加禁止尝试的计数，确保代码即便捕获 ImportError 也不能悄悄改用另一条路径；结束时禁止 namespace 被载入。没有改密码算法、参数或 wire。

修复提交 `9fdc9b2`、协调提交 `350b435`；主线文档冲突合并为 `3c8441f`，没有强推或覆盖队友的独立修复。最终 Windows 相关文件 **173 passed / 2明确Sage skip**，[JUnit](pr13-portable.junit.xml)；Sage公共入口和原真实HIBE **55 passed**，[JUnit](pr13-sage.junit.xml)。安装支持库确实存在的独立 Python 环境另跑此契约1项通过，[JUnit](pr13-installed-independence.junit.xml)；该1项不与173重复计数。原350、173和55交叠，不能相加为总用例数。

```text
PYTHONPATH=src python -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_ibs_contract.py tests/test_public_research_api.py tests/test_assembly.py tests/test_cli_selection.py tests/test_combination_matrix.py
python -m pip wheel --no-deps --no-build-isolation --wheel-dir test-results/pr13-review-wheel .
python -m pip install --no-deps --target test-results/pr13-review-install/windows test-results/pr13-review-wheel/ibme-0.1.0-py3-none-any.whl
```

指定 Sage 同样执行 `tests/test_public_research_api.py tests/test_first_suite_hibe_reference.py`，用 `~/miniconda3/envs/sage/bin/python`；wheel安装到独立 target，不改全局依赖。精确命令见收据/探针。对生成 wheel 逐个核 Python 源与最终被审源码相同，143成员、138 Python源，私钥/状态/seed/PDF/JUnit等材料未进入包；[检查](pr13-wheel-inspection.json)。测试/文档修订没有改变该 wheel 的密码源码。

两个平台都以 `python -I`、仓库外 cwd、唯一安装目录导入执行 API 探针：Windows3项/34 provider，Sage10项/63 provider，全部路径来自安装目录；[Windows](pr13-windows-installed.json)、[Sage](pr13-sage-installed.json)。Sage实际scalar调用、原四种匹配和密钥恢复；无native、无熵的新Root/新receiver拒绝及已有状态复用通过，没有生成替代测试密钥。

同一安装候选从仓库外实际 CLI **8步/82.76 s**：Setup、发Alice/Bob钥、加密、首次解密、第二进程恢复、已有receiver复用、篡改拒绝；42B消息、117505B完整密文、1次新Root/receiver/leaf流程。native只在所需步骤配置，私钥/状态仅在ignored目录。[收据](pr13-cli-lifecycle.json)；测试时间不作公平性能或优化结论。

最终 head `3c8441f` 的 push/PR 两组 basic-checks 与 hybrid-research 均成功，详见[追加机器记录](pr13-review.json)。2026-10-12 按授权转ready后合入，源码与已验代码一致。当前默认入口须明确选择 `mp12-chkp-reference` / `n2-reference` 和 Hybrid；无Sage仍unavailable，原 `chkp` 不改名，已知n2攻击/none/false不变。

最后文档修订同步安装已完成的状态、T0接收与本记录；没有再改密码代码。归档使用LF并给出实际归档 SHA，原始本机 JUnit 的原SHA在原运行收据保留。最终本地/远端版本以交付提交为准。

最终收尾提交另更新 `ARCHITECTURE.md`、`IMPLEMENTATION_SPEC.md`、`docs/PROJECT_STATUS.md`、`docs/specs/first-suite-research.md`、`docs/workplans/2026-10-12/tasks.json` 及本目录 `README.md/review.json`。本目录新增 `.gitattributes`、`pr13-review.json`、`pr13-wheel-inspection.json`、`pr13-windows-installed.json`、`pr13-sage-installed.json`、`pr13-cli-lifecycle.json`、`pr13-portable.junit.xml`、`pr13-sage.junit.xml`、`pr13-installed-independence.junit.xml`。提交信息：`docs(review): finalize merged public API validation`；修复的测试提交与合入 SHA 在上文保留。

## 7. 本地主目录保护

本机 `D:/zcode_projects/ibme` 仍有3份原未跟踪论文/清单；其中 `papers/2016_ntru_ibs_xie.pdf` 与主线同名已跟踪文件字节不同。保护检查在执行 fast-forward 之前拒绝，因此没有覆盖、移动、暂存或清理这3份文件，主目录仍在原 `bc22c9c`。这是本地主目录同步的具体限制，不是远端合并失败。

远端main和本任务的管理工作树 `pr-merge-review/ibme` 都已包含五个PR和最终记录，可从该工作树继续；准确主目录状态/文件指纹见 `review.json`。文档来源应按该最新 checkout，不能从旧主目录误读当前接口。论文版本需要另行保留/比较后再同步主目录，本轮没有改动它们。此保护说明对应文档提交 `docs(review): preserve local paper collision evidence`。
