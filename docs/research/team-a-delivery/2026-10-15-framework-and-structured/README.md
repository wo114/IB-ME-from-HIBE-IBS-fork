# A：真实 ABB 默认接入与结构化 MP12 完整 H/G

本批推进 A0/A3/A1/A2 的可运行研究交付：**真实 `abb-rom` 已进入默认装配；新增 `mp12-structured-hg` 完整 H/G 实现变体；两者分别完成六种 IBS 的共同验收，共12配置404检查。** [任务状态](../../../workplans/2026-10-12/tasks.json)、[原语契约](../../../specs/mp12-structured-hg.md)、[使用方法](../../../FRAMEWORK_USAGE.md)同步更新。GKR、ABB标准模型、CHKP标准模型按用户要求暂缓，未启动新后端。

所有输入保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。n1 ABB 与 n2 结构化 H/G 都有成功的公开恢复攻击，不能提供比赛保密实例的安全承诺。结构化实现选择不新增论文算法、困难假设类别或候选路线；目录仍为8条HIBE、11条IBS。

## 1. 本批代码与来源

运行代码冻结于 `3a5e830966d1dabea743db0f22164beccafb9266`；更早执行各按自己的源码指纹与提交核对，不把新版本归到旧收据。

| 提交 | 实物 |
|---|---|
| `7bc69f6` | 真实ABB独立默认登记、完整参数/依赖预检、CLI真实新建与原树导入探针 |
| `dbb3079` | 共同runner的受信Python恢复入口、ABB六种IBS验收；JSON不能提供代码 |
| `3afd7ff` | 完整H块的结构化SampleLeft/DelTrap、新H/G六方法/五对象、同组参数与原语系统实物 |
| `5f4d032`、`b7f3933` | 真实固定测试流契约、默认装配、严格专项CI |
| `6bc93cf` | 真实框架生成所用代码；补齐seed容量元数据，未改数学门槛 |
| `b0d5140` | 修正协议BOTTOM断言，用原有四叶完成验收和六种IBS组合；未重新发钥 |
| `ac2875c`、`3a5e830` | 有界恶意嵌套解析、隔离安装复放、缺可选研究包时不阻断其它后端 |

修改跨越格工具、HIBE、公共登记/目录、测试/CI和研究验收。原因是 A3 的结构化工具需要真实 HIBE 消费者，统筹需要把已交原语放进默认框架。协议、H/G编码、Hybrid、BYTEAUTH、IBS数学实现及原ABB数学实现均未被替换；没有读取其它原语的私有矩阵绕开接口。

## 2. 结构化 MP12：实际完成了什么

复用既有 MP12 Algorithm3 精确低秩扰动与实际 gadget Gaussian。对 `[A|E]`，把 E 置于末端gadget前并给陷门R补零行，执行实际采样后逆置换坐标；**每一个输出坐标都实际采样**。把完整 m 列H的前 `m−w` 列作为扩展，最后 w 列用于 Algorithm4，得到恰好 `[A|H]` 的接收者陷门。终端直接SampleLeft生成固定256个G目标原像。没有缩短H块、生成完整核格基或使用零/均匀噪声替代Gaussian。

具体论文—算法—条件—接口映射及等式见[契约](../../../specs/mp12-structured-hg.md)：MP12 §5.4/Algorithm3/Theorem5.5、§5.5/Algorithm4/Lemma5.7；CHKP §5.1–5.3 的完整H/G。此MP12委派变体不直接继承原CHKP RandBasis定理。

同组公开配置：n2、q549755813911、根R平方宽度16、qα4、86 B原语身份、32 B seed、2个接收者×各2个发送者。w80、根84列、父采样88维、接收者168列、叶252维；B₀=5120，父平方宽度28288000，B₁=199147520000，叶平方宽度1083362509235200。均用公开声明的界，未以有利秘密几何下调宽度。

| 实际执行 | 结果与边界 |
|---|---|
| 原语系统随机根与完整两层路径 | 同一根两个接收者、四叶、共1024个真实原像；四份32 B实际rounded-noise消息恢复，12个错误私钥得到不同结果；227.087847 s，一次执行，无外层重试 |
| 原语新进程恢复 | 五类对象及原2×2树，4条匹配路径；新根/新钥/熵请求均0，字节不变 |
| 原语公开攻击 | 只给公开矩阵、密文、已知身份及实际有限噪声半径，n2枚举恢复32 B；无私钥/原像/随机带输入 |
| 框架系统随机树 | 独立于上述字面86 B身份原语树；使用未修改的Hybrid身份编码及Luo C64B compact，同根2×2四叶和4条诚实路径 |
| 框架验收修复后复放 | 原生成脚本在全部密钥/诚实密文保存后把协议BOTTOM误写成None；保留失败记录，原对象上零熵完成4匹配+12错配与恢复；没有生成新根、钥或密文 |
| 原树CLI | 17个新进程命令，固定钥发布/复用、4匹配、3错配、4字节攻击；全部零熵，发布后状态字节不变 |

raw seed CPA层可以把错误身份解成另一串32 B，不把这种容错伪称原语完整性；共同协议按既有Hybrid/IBS/BYTEAUTH拒绝。成功/失败地址均固定；pending发布异常、接收者/叶异常、恢复与并发单次尝试都有实际测试。

整父委派随机带请求界1,462,989,752,320 B，整叶26,907,788,083,200 B；分别受原 `2^44` 和既有熵包装器 `2^48` 门约束，**不是预分配内存、RSS或实际消费**。根R320项，父R7040项，每叶固定64512个整数；40维gadget基和受限Schur逆仍实际展开。条件噪声界通过不含范数坏事件、卷积TV、全部abort和硬件/工作区失败。[真实读取的公开预算证书](evidence/structured-budget.json)将完整SampleD TV/失败界保留为null。n128/q65537旧2432维根仍不能通过完整H/G prefix≤512门，不冒充高维HIBE。

## 3. ABB：已有数学后端的默认接入

原AP09/BasisDel/采样实现及版本沿用[上一批](../2026-10-14-abb-complete/README.md)，旧 `abb10` 教学负控另列。默认 `abb-rom` 选择q26/n1：q33554467、52随机行、156 gadget列、总维208；同组86/86 B、32 B seed、实际噪声。原根/父/叶GS门、矩阵归约、有限误差和已知公开n1恢复攻击没有因登记而获得安全准入。

- [新建ML-DSA44 CLI](evidence/abb-cli-new-mldsa.json)：12个主阶段加1个恢复子进程，真实1次HIBE Setup及新发钥、32 B加解密、固定发布复用及4字节拒绝，685.724818 s。
- [原2×2树接Falcon512 CLI](evidence/abb-cli-saved-falcon.json)：15个主阶段加1个恢复子进程，恢复真实旧树，新建IBS实例，3种身份错配及字节拒绝通过；新HIBE根/新发钥为0，1037.618332 s。
- [原实例契约](evidence/abb-real-contract.xml)：3 passed / 0 skip，包括实际32 B固定测试熵加密重现和新SamplePre解密。未重新生成昂贵根或发钥。

**ABB恢复时不重发钥；每次真正解密仍消耗新熵，执行256次新SamplePre。** 两种说法分别核验，不能把ABB描述为零熵解密。无需解密的字节拒绝在任何SamplePre前完成。

## 4. 共同验收、安装与测试

[ABB](evidence/abb-matrix.json)和[结构化H/G](evidence/structured-matrix.json)各6配置202检查：Luo矩阵、Luo模格C64B compact、Wang–PW、SRGG、认证ML-DSA44、认证Falcon512。Wang–PW每组32检查，其余各34；格式/参数档不重复计IBS算法。ABB两份只读worker原收据另存，合并报告没有创造额外执行。

共同驱动对每组实际执行诚实/空消息、三种错配、对象恢复、截断/追加/重复/错版本、BYTEAUTH字段修改、随机签名、错误消息/身份，以及攻击者更换OTS并合法重签外层后到达IBS的拒绝。研究HIBE钥来自已完成系统随机原树；每组新建真实IBS，后续加解密/签名使用明确固定TEST流。无mock、无新HIBE发钥或独立根补位，`security_proof_count=0`。没有新增独立安全归约。

[最终安装](evidence/installed-summary.json)：wheel SHA256 `25e1cb51292b54f95cb2a5e8462e1eab878abcbc64a0de2b11d84e67f157cb3b`，1,377,173 B，运行源码 `3a5e830`。仓库外cwd、`python -I`、唯一安装目录；全部项目provider均限制在安装包，原ABB ML-DSA状态7命令、原ABB Falcon状态7命令、结构化原框架树17命令成功。零新HIBE根/钥；ABB每次匹配解密256个新原像，结构化全部零熵。沿用明确缓存的Flatter/精确Gram及所选签名引擎，未以源码或其它档替代。初版wheel验收不计为最终wheel的第二次独立实例。

| 最终本地测试 | 实际结果 |
|---|---:|
| Sage `ci/run.py run a-structured-hg` | 93 passed / 0 skip |
| Sage `ci/run.py run framework` | 478 passed / 0 skip |
| Windows同一framework | 467 passed / 5明确Sage skip |
| 显式原ABB完整实例契约 | 3 passed / 0 skip |
| 接收PR31固定head Wang–PW专项 | 496 passed / 0 skip |

这些用例集合有交叠，不相加。共享Sage源码外进程测试曾因缺可选 `experiments` 使旧MP12 descriptor阻断其它后端；已修为仅该可选后端不可用，选中结构化时也在写状态前报告缺依赖，随后完整重跑。初次容量元数据缺失、BOTTOM脚本错误、旧测试断言修正及第一次安装启动脚本的CRLF问题均在[audit.json](audit.json)保留；不修改数学门槛、不重发失败密钥、不把失败/skip记成通过。

硬件Intel Core Ultra 9 275HX，24核/24逻辑处理器；WSL2 Linux6.18.33.2、Sage10.9/Python3.13.14，Windows Python3.14。ABB CLI OMP8，其余矩阵/结构化OMP4，OpenBLAS1；每个系统根/组合均单次，参数、身份/消息长度和计时边界在各收据单列。ROM用于H/G和相应原语映射。不同安全性、表示、输入及冷启动边界不用于计算端到端加速或压缩倍率。

## 5. 审查、复放与仍待工作

本轮先接收PR31：固定head `31adede`，本地496项无skip、22个远端成功检查及1个手动strict-security未执行项，审阅固定服务与失败状态后合入 `288f02f`。只读交付核对在该head导出树检查11份清单、134份来源、496测试及3个原实例/41个安装provider；没有重跑其3个系统根。初始checker在有A目录改动的工作树报告差异被单列，不能把它当PR源码缺陷。此工程审查与回归不是独立密码学安全审计。

公开文件采用显式allowlist；私钥、陷门R、基、256原像、随机带/种子、raw状态与子进程私有日志都留在ignored测试目录。精确修改列表见[files-changed.txt](files-changed.txt)，原始来源/哈希/参数与重复次数见[audit.json](audit.json)。只读检查器会核每份收据自己的Git版本、实际JUnit计数、404检查和安装provider；LF/CRLF差异另外列明，不当作字节相同。

[实际核对结果](verification.json)：29份公开证据、1513次provider来源比对通过，换行差异0；1513是跨收据的比对次数，不是唯一文件数，也不是重新执行了1513项密码学测试。

在完整Git历史的仓库中可检查公开交付，不加载私钥或重跑采样：

```text
python ci/check_a_delivery.py docs/research/team-a-delivery/2026-10-15-framework-and-structured
```

复放研究数据使用新的输出文件；已有成功树可以restore，失败发钥地址不得重启或换独立根补位。在仓库根、指定WSL环境：

```sh
export PYTHONPATH="$PWD/src:$PWD"
~/miniconda3/envs/sage/bin/python ci/run.py run a-structured-hg --output test-results/my-a-check
~/miniconda3/envs/sage/bin/python ci/run.py run framework --output test-results/my-framework-check
IBME_ABB_REAL_PRIVATE_DIR=<原ABB完整实例目录> IBME_ABB_REAL_REPLAY=1 ~/miniconda3/envs/sage/bin/python -m pytest -q -p no:cacheprovider tests/test_abb_real_lifecycle_contract.py
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_hibe_probe --private-directory <原已完成私有目录> --restore-only
~/miniconda3/envs/sage/bin/python -m experiments.research.structured_framework_probe --private-directory <原框架私有目录> --restore-only
```

**A仍未全部安全准入**：正式困难参数与完整同组实施域、具体卷积/全服务查询的有限失败账本、计算型根/ROM/固定发钥的构造映射、同安全目标的完整IBME基线/消融及最终三组代表选择仍待。没有把功能通过写成LWE/SIS/匿名性或强认证证明，也不在本批启动用户暂缓的三条储备。
