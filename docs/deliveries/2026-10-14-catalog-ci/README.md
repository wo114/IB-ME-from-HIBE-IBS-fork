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
| Yu | 有组件，未登记完整 IBS 适配器 | 测试可被目录发现，完整 IBS 仍待交付 |
| LATTE、Foo–Li、SageLoli、ML-DSA、Falcon、Xie-NTRU | 部分来源/组件或候选 | 没有完整公共后端时保持待实现 |
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
