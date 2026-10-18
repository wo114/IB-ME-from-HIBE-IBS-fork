# IBS 接入、参数盘点与 C64B 完整组合实测

2026-10-18，统筹交付。运行源码固定为 main `fc1f342faecd16bc80b63dbc851e7f67601e36a0`。本批先将 [ABB10／CHKP 接手标准](../../workplans/2026-10-18-ABB10与CHKP执行标准.md)提交并推送 main，再盘点已有 IBS，复用已有 C64B 参数补一次完整 LATTE 组合。当前任务排序只由 [PROJECT_STATUS](../../PROJECT_STATUS.md)发布。

**结论：10 个完整独立研究 IBS 中，6 个进入默认选择器，4 个尚未进入。至少 6 条路线的现有小参数配置已有公开伪造记录；这不表示对应论文算法均不可用。** ML-DSA／Falcon 转换采用完整底层参数，Luo 模格有明确的 C64B 研究候选，SRGG 已有独立论文参数实跑，应分别推进。登记、原语运行、参数条件和真实组合是不同完成项。

本批新增 **LATTE＋Luo C64B compact＋Hybrid＋BYTEAUTH**：3 套独立系统随机状态、9 对热加解密、9 次新进程恢复后解密全部成功；另一批固定测试随机数的完整组合 **1 配置、34 检查通过**。它是同一 Luo 算法的新测量配置，不新增算法计数，不替换默认值，也不授予正式安全等级。

## 1. 当前接入与参数清单

[公开盘点收据](evidence/inventory-current.json)由 [audit.py](evidence/audit.py)读取描述符、参数及容量预检生成：不创建后端、不生成密钥、不签名、不读取私有状态；项目私有随机源调用为 0。默认选择器的 `available=true` 表示可装配的研究实现，不表示安全准入。

| IBS 算法 ID | 默认选择器／已有真实配对 | 当前参数与限制 | 可行的改进方向 |
|---|---|---|---|
| `luo-matrix` | 已登记；已有框架配对 | research：n4、k32、q2147483647；既有筛查未给出已接受的目标参数 | 沿用[矩阵版暂停扩参的决定](../../research/2026-10-11/IBS版本决策-模格版主线.md)，优先模格版，不重开盲扫 |
| `luo-module` | 已登记；已有 CHKP／ABB／LATTE 配对；本批补 LATTE＋C64B | N256、k11、l10、q274877844481；默认 research 与显式 C64B 不同，均非正式准入 | 固定现成 C64B 配方、实际组合与参数卡；无需重开已收尾的中止界研究 |
| `srgg2025` | 默认 degree8 路线已登记、已有 LATTE 配对 | 默认 rank1、w3、p257、factor2；挑战空间小，已有固定点公开伪造 | 较大 structured 和论文参数路线分别评估，不能直接继承默认配对结果；见下一节 |
| `wang-pw` | 已登记；已有 LATTE 组合 32 项检查 | n1、q17 调试配置，已有公开线性求解伪造 | 参数必须联动 SIS 维度、宽度、范数和转换；只改盐长度或模数不能解决 |
| `cert-ml-dsa` | 已登记；LATTE 三档真实配对、CLI 和安装恢复已有 | ML-DSA-44／65／87 完整底层参数；认证转换后的 IBS 条件另列 | 保留成熟参数，完成展示候选参数卡和同条件完整系统比较；三档不算三算法 |
| `cert-falcon` | 已登记；LATTE 两档真实配对、CLI 和安装恢复已有 | Falcon v1.2 padded512／1024；不能称为 FN-DSA 或 FIPS206 实现 | 保留现成全参数实例、版本与来源；两档不算两算法 |
| `foo-li` | **未进入默认选择器**；独立 BackendSpec 已有 | q3、n1、m_bar1；已有公开伪造、错身份／消息被接受的记录 | 独立描述符放入调用方临时 registry 后容量预检通过；可做研究接入，但安全展示还须换整组合法参数 |
| `yu2026` | **未进入默认选择器**；独立 BackendSpec 已有 | q3，默认身份／消息各 1 B，当前类最多 4 B；已有公开伪造 | 临时 registry 预检正确拒绝 Wang 帧容量；须先扩实际电路／输入域，不能截断或自行哈希硬接 |
| `sageloli-sis` | **未进入默认选择器**；独立五方法／固定服务已有 | n2、k4、m16、q81；已有公开伪造 | 公共描述符／CLI／配对是一项，目标 SIS 配方和执行域是另一项；原文没有给本路线具体发表数值点 |
| `sageloli-rsis` | **未进入默认选择器**；独立五方法／固定服务已有 | d4、k9、l22、q19683；已有公开伪造 | 原文两组大参数可作起点，先核对资源和执行域；目前不能只修改配置直接运行 |

六条已知不安全的小参数路线为：默认 SRGG、Wang–PW、Foo–Li、Yu、Sageloli SIS、Sageloli RSIS。上述是已存档实例的结果，本批没有重新运行或新增攻击。Luo 矩阵未取得目标参数也不能据此列入安全池；底层标准签名使用完整参数不能自动授予整个 IBS／IB-ME 相同等级。

来源：[Foo–Li](../../research/team-b-delivery/2026-10-15-foo-li-backend/README.md)、[Yu](../../research/team-b-delivery/2026-10-15-yu-backend/README.md)、[Sageloli](../../research/team-b-delivery/2026-10-16-sageloli-complete/README_zh-CN.md)、[Wang–PW](../../research/team-b-delivery/2026-10-13-wang-pw/README.md)、[默认 SRGG](../../research/team-b-delivery/2026-10-13-srgg-full/README.md)、[认证转换的公共接入](../../research/team-c-delivery/2026-10-15-c-framework/README.md)。

### SRGG 已有三个不同的实现范围

1. 默认 `srgg2025` 是 degree8 调试路线，已有组合不能代表下面两条。
2. 独立 structured 变体已有 n512、rank2、w8、r²64 的运行。其 [困难性比较](../../research/team-b-delivery/2026-10-16-srgg-hardness/README.md)对该点给出 LWE classical 30.660／31.536、quantum 27.825／28.622，SIS 57.524／52.205，不能因 n512 就认作目标参数。它们是比较模型成本，未实际执行恢复或伪造攻击。
3. [论文参数独立实现](../../research/team-b-delivery/2026-10-16-srgg-paper-baseline/README_zh-CN.md)已随 PR37 进入主分支：三组均 n512、p16383、b31、w2、Q15744063，rank2／3／4，两种 Gaussian 解释共 6 次固定测试生命周期，另有 PARAM-I 系统随机生命周期；相应批次 221 tests passed。这里的历史次数不累加为本批实跑。它尚无默认登记／CLI 或真实 HIBE 配对。

论文参数实现仍明确记录标准差／密度宽度解释未获作者确认、factor1／factor2 差异及部分有限误差界退化。PARAM-II／III 的同消息签名替换排除当前 native-strong 声明；它不是新消息伪造，不能直接当作普通 EUF-CMA 被攻破。继续按用户决定引用论文与记录工作假设，不新开完整归约、hybrid 或基础证明任务；参数解释、实际采样和功能问题仍需如实处理。不能把“论文参数已跑”改写成“正式参数已准入”。

## 2. 本批实际改善：把现成 C64B 接入 LATTE 实跑

采用已有 [c64b_params()](../../../src/ibme/ibs/luo_module_profiles.py)，[参数决定与引用条件](../../research/2026-10-11-luo-c64b-handoff/参数决定与安全引用条件.md)和 [Luo 终验收](../../research/2026-10-12-luo-final-acceptance/README.md)继续作为来源。没有改变算法、默认参数或公共注册表。

完整 17 字段在 [c64b-suite.json](evidence/c64b-suite.json)。主要数值为 N256、k11、l10、q274877844481、NTT root153250464611、η1、κ64、γ1=190000、γ2=60000000000、γ3=27487784448、dropped_bits28；Extract／Sign 尝试帽各4096，uniform 帽128，最多64个缓存身份，身份／签名输入上限64／4096 B。预检给出应用消息上限3924 B、签名输入额外开销172 B、compact 签名最大16383 B。

历史交付在声明的理想模型、好矩阵条件和调用预算下给出生命周期中止界 <2^-153；该数值不是安全位数。C64B 的 MSIS 比较 classical188.340／quantum170.925，比旧默认对应模型分别低8.468／7.685；compact 签名也从16063增至16383 B。此参数选择改善特定中止预算，存在困难性和尺寸折中，不能概括为全面提高安全或性能。

### 实验方法及结果

源码 `fc1f342`，Intel Core Ultra 9 275HX、WSL2 Linux6.18.33.2、Sage10.9／Python3.13.14、OMP4／OpenBLAS1。SHAKE 等按现有经典 ROM 使用。外部发送／接收身份各64 B，Hybrid 内部身份86 B，底层种子32 B，应用消息32 B。参数为研究配置，非教学 HIBE 小参数替身，亦未获正式安全准入。

[完整基准收据](evidence/latte-c64b.json)：系统 CSPRNG，3 套独立根状态，每套首次加解密后3对热运行；每套另起进程恢复并解密3次。没有固定种子、外层重试或引擎重编译；操作走公开完整协议，包含包装、wire 编解码、验证和 native 启动。新 Python 进程保留操作系统页缓存和已构建引擎，故“冷”不等于整机无缓存。整次命令有300秒上限，全部结束。

| 阶段 | 样本数 | 中位秒 |
|---|---:|---:|
| 导入并装配运行时 | 6 | 1.379315 |
| Setup | 3 | 0.887321 |
| 发送者发钥 | 3 | 0.173301 |
| 接收者发钥／父委派 | 3 | 0.424922 |
| 首次完整加密 | 3 | 0.362730 |
| 首次解密含叶生成 | 3 | 0.381379 |
| 热完整加密 | 9 | 0.548812 |
| 热完整解密 | 9 | 0.227047 |
| 持久化 | 3 | 0.059892 |
| 新进程恢复对象 | 3 | 0.762332 |
| 恢复后完整解密 | 9 | 0.218791 |

12 份完整密文为 **152225—152269 B**。进程树10ms采样最大 RSS 为 **494772224 B（约471.85 MiB）**。三套持久对象的公钥260827—260829 B、主状态522226—522399 B、发送者状态313813 B、接收者状态128172—128245 B；它们包含各自封装／缓存，不能直接相加宣称去重存储。

所有新进程恢复均项目熵读取0、原状态未改写。3套根状态的样本很少；热样本共享各自根。10ms采样可能漏峰，进程树相加也会重复计算共享页，因此 RSS 是该方法观测值，不能当精确物理内存需求。

对照 [旧 Luo 默认完整基线](../../research/2026-10-18-full-system-luo/README.md)的热加／解密0.364461／0.229220秒、wire151876—151955 B，本次 C64B 观察到加密更慢。两批不是配对随机性的消融，也没有完成同安全目标匹配；不写加速收益或全队性能排名。

另一次 [功能组合收据](evidence/c64b-functional.json)使用固定测试随机源，**34／34 通过、0失败、0阻塞、0跳过**：含三类身份错配、空消息、状态恢复、签名／上下文／内层字节修改及规范解析拒绝。这批与3套 CSPRNG 基准的范围不同，分别计数。它未在收据内捕获运行时 provider；本批独立核对该 runner 与固定源码，不将其写成运行时捕获结果。

## 3. 验证、复现与文件范围

[verification.json](evidence/verification.json)由 [verify.py](evidence/verify.py)产生：173份盘点源码、780项基准 provider 记录（120个不同文件）与固定 Git 内容一致；只允许 LF／CRLF 差异，原始捕获摘要保留。故意改坏一个 provider 摘要的负例被拒绝；配置在预检、两份输入、功能和性能收据间一致。验证程序只打开公开文件，没有读取实验私有状态。

交付检查：上述 `verify.py` 最终复跑通过且与保存结果相同；本目录9份JSON均可解析、两份Python脚本语法通过，本报告／PROJECT_STATUS／ALGORITHM_CATALOG共207个本地相对链接存在，文件无行尾空白，`git diff --check`通过。此次只新增文档、公开输入和证据工具，没有因文档修改重跑整套密码算法测试；实际新增组合的34项和系统随机基准结果分别如上。

首次直接套用既有 Git 原始字节校验时，Windows CRLF 与 Git LF 不同而退出；本批验证器显式处理该换行差异，不忽略其它内容。`inventory-initial-unverified.json` 和 `inventory-final.json` 保留采集过程，除采集脚本摘要外与 `inventory-current.json` 的盘点数据相同；**当前复核以 current 文件为准**，不把中间脚本版本写成通过最终脚本核验。原性能输入 `c64b-candidate.json` 的自定义标签被基准 runner 接受；矩阵 runner 仅允许标准标签，故 `c64b-suite.json` 改为 research／research，所有 selection 字段完全相同。

[native-provenance.json](evidence/native-provenance.json)为实验后的独立只读查询，记录本机构建引擎 SHA-256、ABI 和源 ID；它没有生成密钥，也不是 worker 当时捕获的二进制摘要。私有状态保留在 Git 忽略的本机 `test-results/ibs-c64b-latte-20261018`，不进入交付材料，不复制历史密钥。

从仓库根复核公开证据，Python3即可（需本机 Git）：

```text
python docs/deliveries/2026-10-18-ibs-inventory/evidence/verify.py
git diff --check
```

下列为本次实际 Sage 命令的可移交形式；在 WSL 仓库根运行。重现时给私有目录和输出换一个**未使用**的 Git 忽略路径，保留失败，不覆盖本批状态。CPU／内存测量串行执行，两个命令各有300秒外部上限。

```bash
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
timeout --signal=TERM --kill-after=10s 300s ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.full_system_benchmark \
  --suite-file docs/deliveries/2026-10-18-ibs-inventory/evidence/c64b-candidate.json \
  --suite-name latte3-hybrid-luo-module-c64b-compact-byteauth-v1 \
  --private-directory test-results/ibs-c64b-latte-20261018 \
  --repetitions 3 --warm-repetitions 3 --identity-bytes 64 --message-bytes 32 \
  --security-group latte3-cosac-fix-luo-module-c64b-research \
  --source-commit fc1f342faecd16bc80b63dbc851e7f67601e36a0

PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
timeout --signal=TERM --kill-after=10s 300s ~/miniconda3/envs/sage/bin/python \
  -m experiments.run_combination_matrix \
  --suite-file docs/deliveries/2026-10-18-ibs-inventory/evidence/c64b-suite.json \
  --output test-results/ibs-c64b-latte-functional-20261018.json
```

盘点脚本另提供 `--source-commit`、`--output`、`--suite-file`，应在同一 Sage 环境运行并指定新的公开输出文件；它只做元数据采集与预检。不要用预检收据里的 `actual_new_combination_execution=false` 覆盖另一份实际基准，也不要反向把元数据收据改成实跑。

本次文件范围：此 README、`evidence/`内采集／验证脚本与公开 JSON、`docs/PROJECT_STATUS.md`、`docs/ALGORITHM_CATALOG.md`。前一提交 `fc1f342 docs(hibe): publish ABB10 and CHKP handoff criteria` 另改四份标准／计划文档。此次没有修改生产实现或默认参数。

## 4. 剩余四天的具体顺序

1. **先固化已有可展示组合的参数卡。** LATTE＋ML-DSA／Falcon 保留完整底层参数；Luo 显式 C64B 已补完整实跑。按相同目标分组后比较，不要求所有10个 IBS 全部完成才交报告，也不预定最终三代表。
2. **下一项原生 IBS 优先评估 SRGG 已有论文参数路线。** 固定参数解释、输入容量与现有采样记录，先判断能否在预算内完成一个真实 LATTE 配对；不能把默认degree8的配对换个名字搬过来。PR43 的新内容独立审查后再用，不新开基础证明任务或无界参数搜索。
3. **4项默认接入欠账继续保留。** Foo–Li 的静态接线条件可过，但小参数不能作为安全演示。Sageloli 两条需明确公共 descriptor、生命周期和真实配对；论文 RSIS 的 `(k,d,l)=(65,2048,132)/(153,2048,308)`尚未运行，执行域和工作区改造先于长实验。Yu 先解决真实字节容量，优先级低于已有大参数可执行路线。
4. **ABB10／CHKP 由队长安排的 AI 按已推送标准推进。** 较大内存部署仍可作为结果；本机资源不足不等于算法不可行。只记录实际完成的原语／完整组合与资源，三条储备路线继续暂缓。
5. **并行收口作品材料和审查队列。** 本次远端同步仍有 PR43/SRGG、PR45/CHKP 待审；另出现 [PR46 展示卡](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/46)（`0c68a27c03d5092b369a95d636bc34091f6fbf33`）与 [PR47 报告／演示材料](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/47)（`8fdac5c91e2739ef93a03cb81242bc19670b13ae`）。后二者本批只同步元数据，没有完成源码／材料审查或合并；不能记作主分支已有展示界面或最终报告。当前排序仍回到 PROJECT_STATUS。

所有本批结果统一为 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；ROM／论文引用与工作假设如上。功能测试、启发式成本和未观察到失败均不能替代安全证明；也不因此新增已被用户排除的证明任务。
