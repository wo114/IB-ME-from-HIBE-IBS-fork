# SRGG、Sageloli、Lai：新交付接收就绪核对

2026-10-19，基于主分支 `18cae9432fa0fd6c745dfd22004b0830e8996def`，另行读取开放 PR 的固定版本。用户指出三条路线已有新交付后，本轮核对了实际源码、公开收据、验证器和定向测试。**此前仅依据旧 LATTE 展示三组回答“这些尚未完成”不够准确；新交付已完成的参数落地和实际运行应直接接收为已完成事实。**

本轮只改本文、[audit.json](audit.json)及 `docs/PROJECT_STATUS.md` 的接收入口；不改原语、参数、协议、界面、旧报告/PPT或历史收据。原始 PR 仍开放，本轮不将其写成已合入 main，也不把一次就绪核对称为完整源码审查或正式安全认证。

## 当前实际完成程度

| 路线 / 固定交付 | 已完成、可接收的事实 | 尚须统筹完成的实物 |
|---|---|---|
| [SRGG PR58](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/58)，`e23ab4ff5da62e51a340c18ecb4b4c61c6137f63` | Table 4 三档 n512 参数已进入显式 `srgg2025-paper`；三档×reference/compact 六个 LATTE 完整组合各34项，共204项；PARAM-I 两格式各3份系统随机状态、9对warm和9次零熵恢复；隔离安装15步CLI＋第16进程恢复，均有公开原始收据。**不是只有调试参数或单体。** | 合入及与其它接入分支整合；纳入最终配置清单、界面/材料和同机器评测。PARAM-II/III重复性能不是本批已完成项，不必重开三档选参。 |
| [Sageloli PR57](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/57)，`922a90084f4d53af88656000207f96a8e2311d7f` | 旧 v2 SIS/RSIS 的公共描述符、默认选择器/CLI、两条 LATTE＋Hybrid＋BYTEAUTH配对各34项已完成。 | 该接入使用小参数，保留已知公开伪造记录；不能用这两份配对收据代表下面的论文参数环版。 |
| [Sageloli PR59](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/59)，算法核对于 `32d0c0bd8d9c75efc1464cbbf91d665ba3574f52`，补充材料最新 `293482a0a746355ef614e8918a99b614c5df404f` | v3环原生实现已跑 `(d,k,l)=(2048,65,132)/(2048,153,308)` 两档论文点；全部身份发钥列、诚实签验、10项负控、独立进程恢复及恢复后新签名有4份公开收据。新建峰值约1.361/6.194 GiB，身份发钥85.135/520.232 s。**“论文规模无法运行”的旧工程判断已被推进。** | v3尚未登记公共BackendSpec/CLI，也没有v3＋HIBE完整IB-ME收据。应接入这个v3，显式核定3.078/7.203 MiB签名载荷及137.415/754.961 MiB身份钥的状态/导入预算，先完成一个实际配对。 |
| [Lai PR60](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/60)，`2180286c432ce8ea5d44d32091d2ef7b9393c1e2` | 完整两级HIBE、公私对象、registry/CLI/state与显式C2 `target-research` 已交；C2为n2048/q274877976577/k39，已有生产CSPRNG目标生命周期和C2＋Luo CLI运行报告，原GSA系数LWE成本记录169.94/154.23（经典/量子）。**不是只写了参数投影或没有HIBE。** | C2逐次原始目标收据未收入公开交付，现有摘要不能冒充接收方已经复放目标状态。本轮发布复测57＋210项不含C2重跑。应优先补可移交的C2公开生命周期/恢复/错配收据，再做所选组合的统一测量；无需从头扫描C2。默认A点仍为低强度研究基线，不能当目标配置。 |

PR59在本轮核对期间更新。比较 `32d0c0b..293482a`，`src/`、`experiments/`、`tests/`、CI及包配置无变更；新增的是已合入的报告材料和PR59公开复核材料。因此本轮20项算法/结构复验的源码仍与最新头一致，另外重新执行了最新公开验证器。

## 这次实际独立核对了什么

本机使用规定的 `~/miniconda3/envs/sage`，所有测试在上述固定 PR checkout 下依次运行，不在不同分支间并发切换。SRGG两种格式各实际新建一轮PARAM-I单体并签验/恢复；未重跑Sageloli两档大参数新建、Lai C2全生命周期或估计器，不新做攻击研究。以下是**本轮重验78个不同条目**，与作者已交的325/180/267项不累加为新增总用例。

| 固定交付 | 本轮执行 | 结果 |
|---|---|---|
| SRGG PR58 | `test_srgg_paper_registration.py`＋`test_srgg_paper_assembly.py -k "not actual_sampled_lifecycle"` | 26 passed，2 deselected，6.15 s |
| SRGG PR58 | `test_srgg_paper_assembly.py -k actual_sampled_lifecycle`：两种格式的真实采样、签验和固定钥恢复 | 2 passed，10 deselected，63.15 s |
| Sageloli PR59 | `test_sageloli_ring_structured.py`：两档宽度公式、大模数编码、结构采样等 | 20 passed，4.61 s |
| Lai PR60 | `test_lai_hibe.py`＋`test_lai_target_parameters.py` | 20 passed，72.12 s；A点功能及目标参数表，不是C2生命周期 |
| Sageloli PR57 | `test_sageloli_assembly.py`，显式使用本机已建LATTE原生引擎 | 10 passed，28.61 s；两条v2完整配对 |

同批 Windows 标准库只读核验：

- SRGG `docs/research/2026-10-19-srgg-paper-latte/verify.py` 通过，核对6份配置/204功能检查、6个基准根、1824条基准provider和154条安装provider、零熵恢复与篡改摘要负例。
- Sageloli `docs/research/team-b-delivery/2026-10-19-sageloli-ring-target/verify.py` 在普通及 `python -O` 下通过：36项清单、4份大参数收据、180个无失败/无skip的作者JUnit条目。最新 `.../2026-10-19-sageloli-pr59-review/verify.py` 亦通过：37项完整源上传、历史23成功/1预期手动skip、180条测试集合关系。它们是**对已有执行证据的核对**，不是本机重跑180项或两档新建。
- Lai `docs/research/team-c-delivery/2026-10-19-lai-publication/verify_delivery.py` 在普通及 `python -O` 下通过：44项源码绑定、57＋210个无重叠作者JUnit条目，明确 `target_c2_rerun=false`。

本轮环境为Core Ultra9 275HX、WSL Sage10.9/Python3.13.14；除Lai复验OMP/OpenBLAS均1外，测试OMP4/OpenBLAS1。这里的pytest耗时不用于比较密码方案速度。原SRGG基准是i9-14900HX/Sage10.7，Sageloli论文点是Ultra7 255HX/Sage10.9；不与本机旧数据混排。

复跑上述测试的一般入口（先checkout对应固定提交；仅缺省登记/参数解释测试不代表完整目标运行）：

```sh
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python -m pytest -q <表中测试文件和筛选参数>
```

Windows Git读取固定PR，WSL执行Sage；本Windows managed worktree的Git指针不能直接作为WSL原生Git仓库使用。所有原语代码只读，临时字节码/pytest缓存均为ignored；本轮未改动主工作目录中的其它AI文件。

## 接下来何时做、按什么结束

**接收核对已在本轮做，不再等待全部候选同时完成，也不把补证明列为前置任务。** 后续验收按以下顺序集中收口，由统筹负责公共层，模块owner只补各自明确缺件：

1. **下一项先接收已有完整配对的SRGG论文入口。** 完成代码审查/合入与跨分支回归，将三档参数落地、六组完整配对登记为已完成；不重复原语开发或三档参数搜索。报告/界面需要的同机重复性能只补实际选用档位。
2. **随后收口Lai C2目标证据。** 优先从原成功状态/日志导出脱敏原始收据并与源码绑定；若原件不可取得，独立保留一套发布版本的生产CSPRNG目标实跑与恢复收据。原报告C2完整CLI约13.5分钟，这是补一轮运行证据的参考，不是继续开长期选参研究。至少固定一个具体IBS、完整suite和输入/计时边界后纳入候选。
3. **再做Sageloli v3公共接入及第一套真实配对。** 复用已交五方法和环原生实现，新增显式v3描述符和容量/状态预算，不能借用v2小参数配对结果。先选一档/一个HIBE完成全流程、错配/篡改/恢复，再扩大参数与组合覆盖。
4. **逐配置更新验收结论和声明范围。** 论文安全性、HIBE匿名沿用用户研发前提；已有参数实现和工程实跑及时确认。数值估计只按已覆盖模型说明，不自行写NIST类别；不因为尚未追加证明而把已完成工程工作重新列为未完成。

第1、2项可在各自文件边界独立推进，不以PR59接入为前提；第3项不需要等新的采样器研究。这里的顺序只收口这次新交付，不重新启动暂缓路线。公开包中有对应收据并通过核对才计完成，不能仅用“状态改true”代替实物。

## 三个标志现在如何理解

本批作者交付都保留 `security_claim=none / backend_admitted=false / parameters_are_formal=false`，本轮不改它们或历史收据。**这不能继续被概括为“参数和实现都没完成”。** 实际应分别记载：论文参数是否落地、目标规模是否运行、公共入口是否可用、具体完整配对是否实跑，以及声明采用哪些原文/工作假设。

SRGG论文点和Sageloli v3的参数实现/运行已交付；Lai C2的实现/历史目标运行也已交付，但公开原始证据不完整。当前剩余主线是统筹接收、缺件和相应组合验收。与LATTE配对的论文参数IBS也不能单独把整个系统变成128位已验收配置；Lai的169.94/154.23系数LWE/GSA成本不能直接改名为整体HIBE或NIST等级。默认Lai A点只作研究基线。

Sageloli旧v2展开表示的TB级/多年外推结论保留为该版本历史；新v3已实测1.36/6.19 GiB，不能将旧限制当成新实现或论文算法本身不可行。候选、默认登记、实际组合和正式声明继续分列。本轮没有完成正式安全准入、全PR代码审查、合并或新配对，不对这些欠项作提前承诺。
