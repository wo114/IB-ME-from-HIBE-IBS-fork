# A交接缺口表：已提交实物、复用CHKP与当前真实运行

本页是A的交接清单；全队优先级仍由PROJECT_STATUS/总计划发布。源与实测分层，未通过完整闭环的ABB不登记为已验收后端。所有研究实现/组合继续none/false。

| A任务 | 可审查实物/证据 | 仍缺什么 |
|---|---|---|
| A0 同组参数/资源 | [MP12角色与九组投影](../2026-10-12-hibe-reference/README.md)、[ABB12组同输入选择](../2026-10-13-abb-backend-wip/compatible-profile-screen.json)；q104单地址完整快照，根父叶宽度/噪声/32 B/86 B/资源不混拼 | 正式高n的两角色估计及可执行工具域；条件正确性不覆盖模型/采样/资源全失败 |
| A1 公开HIBE与状态 | MP12变体已合入并安装/CLI验收；队友CHKP完整源码/收据固定为PR14 head87deec2；六方法/绑定/五对象/固定状态分别命名 | PR14统一接收与独立复核属统筹；n2保密攻击已成功，正式参数/模型未放行 |
| A3 公共矩阵工具 | [单源/真实248维两次委派](../2026-10-12-matrix-tools/README.md)、[精确规范核格/三角计算/隔离安装](../2026-10-13-abb-canonical-fix/README.md)；实际Gaussians、完整格、真实消费者 | 1536维输入域不保证所有Sage workspace可跑；高n/完整总资源概率/正式分布条件仍缺 |
| A2 ABB-ROM | [六方法/五codec/固定状态/独立Spec](../2026-10-13-abb-backend-wip/README.md)；真实AP09 Setup，历史父中断/FAILED恢复；当前d5a2a77独立q104实例进行中 | 正条件诚实父/叶、256 noisy bit/新SamplePre闭环；完整Hybrid+Luo身份与字节攻击；正式模型与可比完整数据 |
| AR 储备 | [GKR/ABB标准/CHKP标准模型、缺口、有限对象数与重启条件](../2026-10-13-reserves/README.md)，7项计数检查通过 | AR说明交付完成；三项完整backend仍未实施，不能计入已实现池 |

## 三条矩阵HIBE分别命名

| 实现/交付 | 根/父/叶算法 | 同组实测研究输入 | 证据归属 |
|---|---|---|---|
| 本A已合入 `mp12-chkp-reference` | MP12计算型[I|Ahat]根 / Algorithm4紧凑DelTrap / CHKP H/G固定256原像 | n2/q549755813911；84/168/252维，内部身份86 B、seed32 B | A原21项真实组合、公开攻击和安装/CLI；见前批，不重跑或与队友相加 |
| 队友PR14 `chkp`，版本`chkp-ro-mp12-root-finite-v1` | 明示MP12-GenTrap/full-basis根 / CHKP ExtBasis-RandBasis-ToBasis / 最大深度SampleD256 | n2/q1099511627791；m_bar45，127/254/381维，Rwidth²1024，rootGS²1078992910，parentwidth²591288114680，leafwidth²82903323983053440，qalpha4；身份86 B/seed32 B | 队友交付的44项组合、CLI15命令/59检查和公开种子恢复；本批只读源码/收据，不冒称本机重跑 |
| 本A新 `abb-rom-finite`，版本`abb-rom-ap09-matrix-finite-v1` | AP09原稿根 / 原稿SampleR-BasisDel-RandBasis两层 / 每bit新SamplePre | 独立n1/q104/m832候选，单父/单子；q160/m1280也有真实Setup及失败保留；详见快照 | 六方法、对象与工具测试通过；当前诚实完整生命周期仍pending |

两个已有入口均不是把旧教学ABB10改名；队友根算法也须保留其MP12名称，不能写成所有组件均来自同一CHKP原稿。现默认registry中没有加入新ABB提案，统筹需显式接收。CHKP源码位于PR14 `src/ibme/hibe/chkp/`及`src/ibme/lattice/chkp/`，和本分支matrix_sampling路径分开；原子module合并时保留owner与历史出处，不覆盖其阶段收据或清理pending。

## 当前纵向程序与交付版本

公开后端/对象基点：`9da3eca2d687352c07b4e3d559f7f1e25515a805`；确定性规范化修复：`d5a2a774c6985dfd06d56cdbeef3d3d715906cf9`；AR材料：`0fecc4c`。PR15保留draft/WIP供复核，不合并到main。用户原D盘工作区及其无关论文保持原状。

当前源码冻结在d5a2a77的数学版本，新的独立实例位于ignored `test-results/abb-q104-canonical-vertical/private`。一次Setup6.180573 s/135174私有随机字节已完成，父过程仍运行；[观察收据](running-observation.json)只是running，不是通过证据，不知道的父Gaussian计数不填零。源指纹/声明RSS预算/原子pending写入由探针记录；后来只修改说明材料，没有在运行中替换算法。

前一q104实例位于ignored `test-results/abb-q104-vertical/private`，准确总数为1371.056945863 s，实际只有Setup私有熵134888，FAILED状态已恢复核验禁止重发。q160旧Bob失败状态也保留。新实例是新Setup/新公钥，不复用或解除旧FAILED，不把中断后另一次生成拼成同一次闭环。

最终代码回归Sage227 pass/3旧私有witness skip，Windows前批137 pass/8 Sage skip；AR7 pass，测试重叠不求和。隔离wheel/Sage -I的71个provider全部来自安装包，实际失败状态恢复与禁止重发通过。详细命令、文件SHA、参数和已知失败均在各批审计；测试不替代安全证明。

真实纵向完成后用 `tests/test_abb_real_lifecycle_contract.py`读取该同一实物，不生成替代key。入口要求completed/通过收据、源指纹未变、root1、实际86 B/32 B与系统熵；核五对象规范往返、实际公钥/路径、整树固定key复用私有熵0及context/wire控制。完整32 B固定测试熵的重复Enc及新SamplePre Dec由显式 `IBME_ABB_REAL_REPLAY=1`启用。当前运行目录尚无completed，该三项检查全部**明确skip**，不算算法通过、也不加到227 pass。

```bash
IBME_ABB_REAL_PRIVATE_DIR=test-results/abb-q104-canonical-vertical/private \
IBME_ABB_REAL_REPLAY=1 PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest \
  -p no:cacheprovider -q -rs tests/test_abb_real_lifecycle_contract.py
```

此入口尚不覆盖完整Hybrid+Luo组合或同公钥下两receiver/多sender诚实错配，相关验收仍待。当前单地址容量仅为最小纵向切片；不能以容量拒绝替代多身份算法/组合验收，也不将前一个中断实物拼入此实例。

交接文件组：ABB专属params/profiles/identity/objects/key_validation/backend/registration；matrix_sampling scalar/GPV/basis/RandBasis/modular及认领兼容入口；ABB/工具专属tests；delegation/hibe/reserve-costs探针；四个日期批次的公开收据与README。具体逐文件列表可由上述提交的Git stat和审计source清单取得，私钥/实际基/seed/运行状态/native原始栈不在提交中。
