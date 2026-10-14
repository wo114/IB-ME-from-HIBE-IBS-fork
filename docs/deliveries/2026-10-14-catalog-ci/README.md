# 19条算法路线的通用 CI 与组合验收

本次修改解决一个实际问题：原来的 CI 主要围绕 Luo 编写，新算法加入后需要手工改 workflow，容易漏测，也容易把“没有代码”误报成“通过”。现在 CI 只负责发现、执行和记录，不因为算法名字是 Luo、Wang 或 SRGG 就走特殊分支。

## 现在的结构

1. src/ibme/assembly/catalog.py 固定登记 19 条路线：8 条 HIBE、11 条 IBS。
2. src/ibme/assembly/registry.py 通过后端自己的 default_preset 和能力描述选择参数，删除了 id.startswith("luo-") 这种算法名耦合。Wang–PW 和 SRGG 在源代码可用时通过公共注册表登记；缺少依赖时会显示为不可运行，不会换成 mock。
3. ci/suites.json 用数据描述每条路线的测试文件、环境和当前阶段。新增某个算法的 tests/test_<算法>*.py 后，目录会自动发现它，不需要再改 workflow。
4. ci/run.py 提供 plan、run、summary 三个命令。它会区分 awaiting_tests、not_executed、missing_dependency、partial 和 passed，拒绝复用旧 JUnit 文件，并为收据记录测试文件哈希。跳过、XFAIL、没有执行断言和缺失收据都不能变成正式通过。
5. experiments/run_combination_matrix.py 继续复用同一个公共装配入口。计划阶段只读显式 JSON 选择，不导入用户代码、不取随机数、不生成密钥；执行阶段才运行明确选定的组合。ci/combinations.json 当前只选择两组研究组合，不能推导出全部 HIBE×IBS 组合都已验收。
6. .github/workflows/basic-checks.yml 现在按“计划 → Windows 可移植套件 / Sage 套件矩阵 → 汇总”运行，动作版本固定；Sage 使用固定摘要的官方 10.9 Linux amd64 镜像。缺少某条路线的实现会显示待处理状态，而不是伪造成功。

## 当前目录能表达什么

| 路线 | 当前公共适配器 | 当前状态 |
|---|---:|---|
| ABB-ROM、CHKP-ROM | 有 | 研究/教学后端分别记录，不能由 CI 代替安全证明 |
| Luo 矩阵、Luo 模格 | 有 | 原有单体与组合回归继续保留 |
| Wang–PW、SRGG | 有 | 已通过公共注册表和独立 Sage 单体测试 |
| Yu、Foo–Li | 已有独立 IBS 研究实现，未登记公共适配器 | 独立实现与公共登记分别统计；不能写成只有组件 |
| LATTE | 已有独立 LATTE-3 HIBE，默认适配器未登记 | 本 CI 选择公开契约/复用诊断；完整原生六方法和真实实物见独立交付，不当作本 CI 重跑 |
| SageLoli、ML-DSA、Falcon、Xie-NTRU | 部分来源/组件或候选 | 没有完整公共后端时保持待实现 |
| GKR、Zhang、ABB标准模型、CHKP标准模型、Lai | 候选/模型路线 | 不能因为出现在目录里就算已实现 |

“有适配器”只表示公共接口可以描述或构造；“测试通过”只表示本次输入和环境下的功能观察；两者都不表示正式参数、安全等级、完整归约或所有组合已经成立。所有路线和收据默认 security_claim=none。

## 已实际执行的结果

以下是在本工作树执行的结果，测试不包含私钥、种子、密文或秘密运行状态：

| 套件 | 结果 |
|---|---|
| 公共框架 | 424 passed，5 skipped |
| Luo 组合回归 | 161 passed，3 skipped |
| Wang–PW Sage 单体 | 410 passed，0 skipped |
| SRGG Sage 单体 | 153 passed，0 skipped |
| 两组明确选定组合（ABB10教学 HIBE + Wang–PW/SRGG研究 IBS） | 69 passed，0 skipped |

公共框架和 Luo 回归的 skip 是既有 Sage/本地依赖边界，CI 收据把它们标为 partial；没有把 skip 计入通过。Wang–PW、SRGG 和选定组合在规定 Sage 环境中没有 skip。两组组合使用的是教学 ABB10 与研究参数 IBS，组合收据仍明确 security_claim=none、combination_accepted=false。

本地 WSL 工作树是 Windows worktree 的挂载副本，Git 无法解析其 .git 指针，所以两份 Sage 收据的 revision 字段显示 unavailable；测试文件与 CI 脚本哈希仍已记录。GitHub Actions 在正常 checkout 中会记录 revision。这个环境限制不改变测试结果，也不被当作安全证据。

## 运行方式

    python ci/run.py plan
    python ci/run.py run framework
    python ci/run.py summary

需要 Sage 时使用项目规定的 WSL 环境：

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run wang-pw
    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python ci/run.py run srgg2025

这些命令只建立可审查的运行证据。它们不重新证明原论文定理，不给参数标注 NIST 等级，也不把有限攻击测试写成一般安全证明。

## 集成审查修正

PR22 的独立 LATTE-3 已先合入；本分支合并该基线并保留候选源码打包及 LATTE 原生源码包两项配置。LATTE 的公开元数据检查纳入本 CI；完整原生 `tests/test_latte_hibe.py` 仍使用指定 WSL 构建，证据见 [C1 交付](../../research/team-c-delivery/2026-10-14-latte-hibe/README.md)，本容器未执行该文件。

最初远端 ABB 任务为 **181 passed / 39 skipped / 0 failed**，因误设 `allow_skips=false` 而退出失败。跳过来自通用契约中不适用的 mock/ABB 分支、可选 native/Flatter 及未提供的私有实物；修正为允许输出 **partial**。逐项 skip 原因仍进 JSON，未降低断言失败、全部跳过、空执行、缺失收据及旧 JUnit 的拒绝条件；它不等于 ABB 完整单体验收。当前默认 registry 的 ABB 仍是教学实现，另行交付的真实 ABB 研究路径不由这次教学回归替代。

合并后的 Sage 集成回归最初为 **193 passed / 1 failed**：新的目录命令经旧 MP12 默认登记提前导入 `sage.all`，其模块初始化读取系统随机数。已将默认后端展示拆成无算法加载的公开 metadata；实际选用仍调用原完整登记及其参数校验，算法、wire 和安全声明不变。测试同时比较展示 metadata 与实际登记能力，并在冷启动子进程禁止 `os.urandom`、检查两个列表命令都不加载 `sage.all`。该文件同时进入 portable 和 Sage 任务，防止仅 Windows 看不到这条初始化路径。跨公共装配与 MP12 入口仅为这一展示边界修正。

修正后的本地结果（各套件有重叠，不相加）：

- Windows：`python -m pytest -p no:cacheprovider -q tests/test_ci_catalog.py tests/test_registry_extension_contract.py tests/test_combination_extension_contract.py tests/test_cli_selection.py tests/test_research_state_integrity.py tests/test_latte_metadata.py` → **172 passed / 2 skipped**。
- 指定 WSL Sage：`python -m pytest -p no:cacheprovider -q tests/test_latte_hibe.py tests/test_assembly.py tests/test_hybrid_key_binding.py tests/test_ci_catalog.py tests/test_registry_extension_contract.py tests/test_combination_extension_contract.py tests/test_registered_compositions.py` → **196 passed / 0 skipped**；这里的 `python` 为 `~/miniconda3/envs/sage/bin/python`，OMP8/OpenBLAS1。
- 同一 Sage 环境：`python ci/run.py run abb-rom --output <新目录>` → **181 passed / 39 skipped**、收据 `partial`；`python ci/run.py run latte --output <新目录>` → **14 passed**，不包含独立原生测试文件。
- Windows Python3.14/setuptools84.0.0：`python -m pip wheel . --no-deps --no-build-isolation --wheel-dir test-results/c-structure-hibe/pr23-wheel` 成功；wheel SHA256 `7b2b96f3f2f542bebe2931f8d8af878c627cf516626ede5e51f6a7990bd45f54`。最初 Sage 构建隔离因镜像取依赖停滞而中止，其无隔离构建也因环境缺 setuptools 失败；最终使用上述已有 Windows 构建环境，没有改变算法或安装 Sage 依赖。
- 将该 wheel 以 `--no-index --no-deps --target test-results/c-structure-hibe/pr23-installed` 安装到新目录；指定 Sage `python -I tests/install_probes/verify_latte_hibe.py <安装目录> <已有实物目录> <新收据>` 通过：13个 provider 来自安装包、原私钥零新取熵恢复解密，另建独立实例完成六方法。两个候选源包和19条路线的安装后冷启动展示在 Windows/Sage 均通过，未导入 `sage.all`、未取熵。真实 LATTE 参数和输入仍以 C1 交付为准，这些检查不升级安全声明。

本次审查修正文件为 `ci/suites.json`、本说明、`src/ibme/assembly/{__init__,catalog,registry}.py`、`src/ibme/hibe/mp12_chkp/__init__.py`、`tests/test_ci_catalog.py`；PR原有范围不另算新原语。原生构建、私钥状态、完整 C1 证据和参数声明均保留。
