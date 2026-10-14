# PR14 / PR15 / PR16 固定版本审查

2026-10-13，按用户“先审核已有 PR，再继续工作”的顺序执行。审查和复跑使用 Git archive 的独立副本，原 D 盘仓库及当前未提交的 `abb_rom/parameter_screen.py` 未改动。下述结论针对固定提交，不自动覆盖后续推送。

| PR / 固定提交 | 结论 | 实际边界 |
|---|---|---|
| [#14 CHKP 与 Luo](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/14)，`87deec24f52c1c776a489566cf76f11d0d4a5aff` | 可接收为研究交付；审查范围内未发现新增的阻断性算法或接口缺陷 | 明示 MP12 GenTrap/full-basis 根、CHKP RandBasis 父、最大深度 SampleD256 叶；n=2 已有公开种子恢复反例，不能作为安全实例 |
| [#15 ABB 与公共矩阵工具](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/15)，`bf47453a3bde50048dd6a4c386ac560fedb9229a` | 保留 draft / WIP；不能按完整 HIBE 或组合验收 | 接口、对象与公共工具有实物；正条件同组父→叶→256 bit 完整闭环尚无通过收据，单地址配置不覆盖多身份组合 |
| [#16 Wang–Pan–Wagner](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/16)，`d892615d1cbc17a3c1ac007f643ad1c32843fc5a` | 可接收为独立研究参考实现；审查范围内未发现剩余阻断性缺陷 | 不在公共 registry，未组合 HIBE，有限 Gaussian 统计距离和正式参数未准入 |

共同基线为 `14f11634840e21751f9f8d0122dddf8651ee4eef`。抓取时 main 为 `2650ab3d7344720f616764cdc45fd94dd91de180`，其后继仅新增 MIT License。此次没有发布 GitHub review/comment，没有合并远程 PR。结论是当前材料的接收建议，不是绝无未知缺陷或安全证明。

## 代码、论文与材料核对

- #14：六方法、参数快照、五对象、真实矩阵/路径绑定、固定地址墓碑、接收者/主状态事务、失败与硬退出、原始 CPA 与外层认证分层；迁移后的旧入口及已合入 MP12 入口同时检查。原根算法不改称 CHKP GenBasis，确定性 LLL 不宣称 Gaussian 或原创构造。
- #16：本地 Wang Figure 4（PDF 16–17）、Pan–Wagner Figure 5（PDF 12）、MP12 Lemma 5.3（PDF 23）、GPV08 §4.2（PDF 15）对照。委派关系 `A R_x = H1-G` 与签名所用 `[-R_x; I]` 一致；完整基由实际陷门构造，用户不携带主陷门；GPV 中心为 `-t`、按原基更新、逐 GS 长度调整宽度。H1/H2 绑定完整公钥、身份和消息；PW 盐及公开验证对应转换。采用完整基 + GPV 的 SamplePre，不能改称 MP12 扰动算法的精确实现。
- #15：公开同组预检、整个矩阵 Gaussian SampleR、完整核格、精确规范 HNF/三角解、逐 bit 新 SamplePre、严格对象、失败地址和安装入口；缺失的真实闭环保留缺失，不用旧 248 维委派或教学控制补齐。
- Git 对象逐项校验 #14 的 193 个被哈希文件、#16 的 18 个被哈希文件：均无差异，包含清单自身后完整覆盖各 PR 的 194 / 19 个变更路径。中文路径用 NUL 分隔读取，避免 Git 显示转义误报缺文件。见 [manifest-review.json](manifest-review.json)。
- #14 的原发布核对器通过：130 份历史源码、48 份 CHKP 材料、12 阶段、40 份 Luo 终验收材料；它明确不认证历史运行真实性，也不是本机新根/父/叶运行。

## 本机实际复跑

| 检查 | 结果 | 不能扩大成什么 |
|---|---|---|
| #14 Sage：CHKP 全部专属测试、CLI 主状态、公共 API、选择、装配、有限 first-suite | 首批 **1053 passed / 1 failed**，91.65 s | 首批不是全绿；失败原始 JUnit 保留 |
| 上述唯一失败再次用源码环境复现 | **1 failed** | 添加 `PYTHONPATH=src:.` 不能修复子进程主动重设路径 |
| #14 wheel 安装后，同一子进程 CLI 用例 | **1 passed**，7.74 s | 是该失败的定向复核，不把 1054+1 相加 |
| #14 安装包，仓库外 `python -I` 的 catalog | `chkp` / MP12 入口可发现；CHKP runtime_available=true | catalog 不生成密钥、不构成诚实生命周期 |
| #15 相关 ABB / matrix 专属 Sage 批次 | **140 passed / 7 skipped**，19.91 s | 4 项外部私有/历史 witness 未提供，3 项真实完整实例未提供；skip 不计通过 |
| #16 四份 Wang 专属测试 | **396 passed / 0 failed / 0 skipped**，25.37 s | 不替代 Gaussian 距离或 SIS 安全证明 |
| #16 原驱动生命周期复跑 | **15/15 检查，16/16 签名通过** | 是驱动明示的固定测试熵，不冒称生产随机重复实验 |
| #16 Sage 独立 HNF / 双向整数包含 | **3/3 完整核基通过** | 不是高维资源或安全等级估计 |

唯一 CLI 导入失败在 #15 继承的基线代码中也复现：测试子进程只给 `src` 路径，而 Sage 下现有 MP12 公开入口需要已安装的 `experiments` provider。测试环境没有安装项目，因而 `ModuleNotFoundError: experiments`。#14 未引入这条依赖。安装该固定 PR 的 wheel 后该用例通过。复核没有修改源码、用例或跳过失败；原失败及最终定向通过均归档。

构建 wheel：568180 B，SHA256 `3e2eb644189175109814323fb1cb85ce99dccf7813e817b5414f5ba92952bcbe`。Sage venv 使用原 conda 环境的 system-site-packages，独立安装此 wheel，不改全局 Sage 包。`/tmp` 中环境未持续保留后，安装目录另置 `~/.cache/ibme-pr14-review-20261013`；不把临时环境丢失当作代码缺陷。

关键命令（分别在对应固定 archive 副本根目录）：

```bash
PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -m pytest \
  tests/test_chkp*.py tests/test_cli_master_state.py tests/test_public_research_api.py \
  tests/test_cli_selection.py tests/test_assembly.py tests/test_first_suite_finite_sampling.py -q --tb=short
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest \
  tests/test_abb_rom*.py tests/test_matrix_*.py tests/test_abb_real_lifecycle_contract.py -q --tb=short
~/miniconda3/envs/sage/bin/python experiments/research/wang_kernel_exact.sage --out <公开收据路径>
```

```powershell
$env:PYTHONPATH='src'
python -m pytest tests/test_wang_pw_ibs.py tests/test_wang_pw_boundary_regressions.py tests/test_wang_pw_sampling_regressions.py tests/test_wang_pw_linear_regressions.py -q --tb=short
python experiments/research/wang_pw_receipt.py --out <公开收据路径>
python docs/deliveries/2026-10-12-chkp-luo/verify_publication.py
python -m pip wheel --no-deps --no-build-isolation --wheel-dir <输出目录> .
```

安装复核用指定 Sage Python 创建独立 venv，`pip install --no-deps --no-index <该 wheel>`，再以其 Python 复跑上述唯一 CLI 用例；仓库外 catalog 使用 `-I -m ibme.cli list-backends --json`。完整原始 JUnit、两个 Wang 收据、安装 catalog 及计数见 [review-summary.json](review-summary.json)。#14/#16 远程 CI 无结果；#15 同 head 的 basic-checks / hybrid-research 为 success，未把无结果写成 CI 通过。

## 合并阻塞与 A 后续

对 #14 与 #15 做只读 `git merge-tree --write-tree`，四处真实冲突：

1. `experiments/research/chkp_tobasis.py`
2. `experiments/research/first_suite/finite_gaussian.py`
3. `experiments/research/first_suite/finite_gpv.py`
4. `experiments/research/first_suite/finite_randbasis.py`

#14 将原实现移至 `src/ibme/lattice/chkp/` 并保持旧入口别名；#15 已把公共数学集中到 `matrix_sampling`，旧入口为窄配置适配。不能简单选择一方：旧 GPV 上限 256 维 / scalar 2^80，CHKP 明示域为 512 维 / scalar 2^88，并且 RandBasis 使用 ExtendedGPV。继续 A3 应复用单一数学引擎、保留两种参数域、真实扩展采样器及固定字节对照；统筹最后接入 registry 与组合。现阶段尚未合并这些 PR，更不能声称合并后回归已通过。

带 `-text` 的历史证据原样保留 CRLF。用 `git -c core.whitespace=cr-at-eol diff --check <base> <head>` 三个 PR 均通过；当前 A 工作树直接检查不带该设置。见 [static-review-checks.json](static-review-checks.json)。

ABB 新 q104 实例的进程已不在运行；目录仍仅有 Setup 通过记录及父 pending，缺 `receipt.json/completed`。外部终止原因、最终父耗熵、结束时资源和源指纹未知。保留已有 master 墓碑，不重发、不覆盖旧状态，不能把旧 running 观察继续写成当前运行。未提交参数筛查改动也不纳入固定 head 审查或覆盖。

## 参数与安全声明

#14：n=2、q=1099511627791、127/254/381 维、86 B 内部身份、32 B seed；完整昂贵实验仍引用队友固定材料，本机没有重新生成。#16：n=2、q=7、m_bar=6、4 个身份长度 5/3/5/4 B、4 条消息长度 0/1/11/64 B，单次驱动共 16 次签名；真实运行软件/平台写在各收据。#15：n=1、q104、m832、86 B/32 B 的正条件样例只有 Setup 通过，真实完整验证尚缺。

全部为研究/教学输入，SHAKE 工程实例不视为理想 RO 等价证明；保留 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。未完成正式参数估计、模型对应、完整归约与可比组合，不宣称 NIST 等级、标准模型安全、增强隐私或完整竞赛安全实例。功能测试和已知攻击材料不能替代安全证明。
