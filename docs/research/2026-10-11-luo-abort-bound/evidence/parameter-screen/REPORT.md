# Step22：Luo 参数准入矩阵与精确候选筛查

日期：2026-10-11。固定基点：f079ce10fb6b3d2877465b308caaa30276d9e6f9（test(luo): close single-primitive lifecycle evidence）。

本旁路任务完成了当前 §4 默认值及一个精确候选的独立成本重跑、参数不等式/来源映射和概率组合边界检查。选定数学参数、模型硬度估计、完整安全准入是三个不同状态。默认值未修改；候选未注册、未实施密钥生成/签名性能测试。所有对象维持 security_claim=none、backend_admitted=false、parameters_are_formal=false，approved_security_bits=null。

结论：用户指定候选 κ=49、γ₁=145000、γ₂=34000000000、其余数学参数不变、Extract/Sign 帽各4096，构造器检查通过；共同 MSIS 模型成本略升，MLWE 输入不变。主 AI 新可用性证书的数值可复现，但证明仍在独立审查。κ 从64降至49使挑战熵减少42.221929位，泛型量子挑战搜索指数减少21.110965；这项变化独立于可用性改善，不能给予128位量子或NIST保证。

## 1. 实際参数与安全差异

以下所有方案共用 N=256、(k,l)=(11,10)、q=274877844481、root=153250464611、η=1、γ₃=15270991360、d=28、身份上限64 B、IBS消息上限4096 B、均匀抽样帽128、缓存64。纸面候选仅在旁路进程内构造，未改仓库参数。

| 项目 | 当前默认 D | 精确候选 C49 | 对照 C64 |
|---|---:|---:|---:|
| κ | 64 | 49 | 64 |
| γ₁ | 125440 | 145000 | 145000 |
| γ₂ | 31470387200 | 34000000000 | 34000000000 |
| Extract / Sign 最大尝试 | 1024 / 1024 | 4096 / 4096 | 4096 / 4096 |
| β₁=κη | 64 | 49 | 64 |
| β₂=κγ₁ | 8028160 | 7105000 | 9280000 |
| Extract 响应界 γ₁−β₁ | 125376 | 144951 | 144936 |
| Sign 整数响应最大绝对值 γ₂−β₂−1 | 31462359039 | 33992894999 | 33990719999 |
| κ2^(d−1) | 8589934592 | 6576668672 | 8589934592 |
| U=κ2^(d−1)+2γ₃+1 | 39131917313 | 37118651393 | 39131917313 |
| MSIS 共同放松界 B | 78279890946 | 74251512786 | 78282394626 |
| log₂ C，C=binom(256,κ)2^κ | 267.566936 | 225.345006 | 267.566936 |
| 泛型量子挑战搜索指数 log₂ C / 2 | 133.783468 | 112.672503 | 133.783468 |

C49 改动的具体影响：

- q、N、k、l、η不变，所以公开主密钥 t=As₁+s₂ 所对应的 MLWE 分布、NTT 和模数合法性不变。
- γ₁增加扩大身份响应立方体；κ降低后 β₂反而下降。γ₂增加扩大签名响应。两项都需要重新代入签名拒绝界与分叉见证，不能只说“同安全参数”。
- 丢弃低位乘积界下降，压缩误差 U 下降；这使最大见证块 B 下降，抵消了 z 响应范围增长。C49 的共同 SIS 模型由 β=674 变为 β=678。
- κ改变 H1/H2 输出空间、挑战解码消费和挑战猜测模型，不能继承 κ64 的泛型量子筛查门槛。
- 重试帽不改变底层 MLWE 输入，但改变中止分布、资源上限和公钥上下文。17个字段都序列化；不能把候选装入已有默认密钥系统中作为透明参数修改（M:31–33、108、M:521）。

C64 只是同 γ₁/γ₂/帽下的 κ 敏感性对照，未获推荐为安全参数。没有开展第三种掩码选择或网格搜索。

## 2. 论文第三列是什么

“table3rdcol”在本报告中指 PDF 第15页 **Table 1 第三组参数列**，不是论文 Table 3，也不是 §3 矩阵算法参数。表中该列为 κ=49、γ₁=125440、γ₂=31470387200、γ₃=γ₂/2=15735193600、log₂q 标为38，未在表内指定精确 q。当前默认是该列维度/掩码来源上的变体，不继承作者的200 bits、14680 B签名或平均重试数。

补充算术事实：若把表内38解释为位长区间 2^37≤q<2^38，同时要求 α=γ₂=31470387200 整除 q−1，则唯一可能倍率为5、6、7、8，对应 q：

| 倍率 | q | 本轮 Sage 素性 |
|---:|---:|---|
| 5 | 157351936001 | 合数 |
| 6 | 188822323201 | 合数 |
| 7 | 220292710401 | 合数 |
| 8 | 251763097601 | 合数 |

因此该**位长解释和表内固定 γ₃关系**没有精确素数候选；不能推断论文所有可能的近似 log₂q 解释都不成立。历史 J:149–173 搜索记录的首个更大素数为1132933939201，41位，未在本轮采用或扩大搜索。本轮只对上述四个必需候选作精确素性核验。当前 α=30541982720，(q−1)/α=9；这是明确的独立 γ₃选择。

论文 p15–16 已渲染目视核验，p8–14 相关定义/算法/分叉文字已提取核对。只选读本任务涉及部分，不声称阅读全文。论文来源：[ICICS 2024 作者公开稿](https://icics2024.aegean.gr/wp-content/uploads/2024/08/150570198.pdf)，本地PDF SHA256为12c70ae7635c0b88c132bca14990480a8e0cdec2e786a6dcf39256e5bb0dd455。

## 3. 参数准入矩阵

机器可读的22项完整矩阵见 [admission-matrix.json](admission-matrix.json)。下面保留对决策最关键的不等式，所有范数为整数多项式的系数无穷范数。

| 门槛 | 精确条件及当前值 | C49 | 来源/状态 |
|---|---|---|---|
| 环与NTT | N为二次幂；q为素数；q≡1 mod512；root^256≡−1、root^512≡1 modq | 相同 | P:p11；R:61–66；独立 Sage 通过 |
| Hint域 | α=2γ₃为偶数；α\|(q−1)；q>2α=4γ₃=61083965440 | 相同 | P:p12 Alg8/12、Lemma1；R:137–142；通过 |
| 掩码合法 | 1≤κ≤N；γ₁>β₁；γ₂>β₂；2γ₂<q；β₂<γ₃ | 49≤256，145000>49，34000000000>7105000，68000000000<q | M:73–103；通过 |
| Hint位移 | κ2^(d−1)<γ₃ | 6576668672<15270991360 | M:83；通过 |
| Extract响应 | ||z₁,z₂||∞≤γ₁−β₁ | ≤144951 | P:p13 Alg14；M:475–481；算法条件 |
| Sign响应/LowBits | ||z||∞<γ₂−β₂；||LowBits(Ay−z₂c,2γ₃)||∞<γ₃−β₂ | <33992895000；<15263886360 | P:p14 Alg15/16；M:495–511；成功签名的条件 |
| 压缩误差 | ||u||∞≤2γ₃+1；||u′||∞≤κ2^(d−1)+2γ₃+1=U | U=37118651393 | P:p16 Eq4.1；S:78–109；不能漏掉+1/误差块 |
| 已见标签见证 | [A\|Iₖ]，系数尺寸2816×5376；两块界分别2Z+2κX、2U+2κX，其中Z=γ₂−β₂−1，X=γ₁−β₁ | 条件式代数已代入 | S:87–97；非零/模拟条件仍须成立 |
| 未见标签见证 | MLWE均匀t混合后 [A\|Iₖ\|t]，2816×5632；块界2Z、2U、2κ | 末块≤98<q | S:98–109；P:p9–10 E′；包含“已签身份的新标签” |
| 共同放松界 | B=max(2γ₂+2β₂,2U+2β₂,2κ)；2B<q−1 | B=74251512786；148503025572<274877844480 | 仅筛查输入/非平凡性，不是困难性证明 |
| 归一化 | 均匀k×k模块块可逆时左乘其逆；坏块概率≤N/(q−1)=256/274877844480 | 不变 | S:245–278；是归约成功率乘法损失，不是IBS优势的加性2^-30项 |
| 已见标签非零 | Q_guess·1025^(2816)/(2X+1)^(5376) | 须重新使用X=144951 | S:113–147；需缓存/完整视图模拟假设，不能由c≠c′独立推出 |
| 新标签非零 | 整数环为整环，c≠0、CID≠CID′；乘积系数≤2κ<q | 98<q | 整数代数条件；不假设稀疏挑战在Rq可逆 |
| 挑战模型 | C=binom(N,κ)2^κ；log₂C/2≥128是既有泛型量子筛查线 | 112.672503<128，未通过 | S:331–360；不是NIST认证标准 |
| 可用性 | 有限帽、坏A、标量拒绝、RO/XOF预算及生命周期联合界 | 主AI新证书已有可复现数值 | A:92–158；证明审核未结束 |
| 整体准入 | 引用覆盖真实模型、概率/时间归约、参数估计及完整组合 | 未完成 | formal=false，bits=null |

式(4.1)末行简写 H(w,id)，实现仍为 H1(Power2Round(w),id)。不能把不同低位升举当成互相独立的随机预言机输入。最高高位w₁=1024的规范升举低位为−62464，已独立检查。

## 4. 本轮真实估计器结果

固定 [Lattice Estimator 53da5982597709ba0fdf94ea37a84d822310fd84](https://github.com/malb/lattice-estimator/tree/53da5982597709ba0fdf94ea37a84d822310fd84)，工具检出内容干净，导入路径已验证。运行环境为 WSL2 Linux 6.18.33.2、Sage10.9、Python3.13.15、Intel Core Ultra7 255HX。这是本轮实测环境，不能沿用旧报告的Core Ultra9 275HX。

模型：ADPS16/Core-SVP 经典0.292、量子0.265；LGSA；MSIS采用无结构系数维数的齐次 infinity-SIS 对照模型，放松全部坐标到最大块界。模结构/代数攻击未覆盖；模型 rop 不是秒数。

| MSIS输入 | 系数矩阵 | B | 经典log₂ rop | 量子log₂ rop | BKZ β |
|---|---|---:|---:|---:|---:|
| D已见标签精确界 | 2816×5376 | 78279882754 | 196.808 | 178.610 | 674 |
| D已见标签保守界 | 2816×5376 | 78279890946 | 196.808 | 178.610 | 674 |
| D未见标签扩展 | 2816×5632 | 78263834626 | 196.808 | 178.610 | 674 |
| D两分支共同界 | 2816×5632 | 78279890946 | 196.808 | 178.610 | 674 |
| C49两分支共同界 | 2816×5632 | 74251512786 | 197.976 | 179.670 | 678 |
| C64两分支共同界 | 2816×5632 | 78282394626 | 196.808 | 178.610 | 674 |

候选只重跑共同保守输入，分支更紧的模型没有逐项重跑。不是把共同框求解视为完整IBS伪造，也不把数值增长1.168/1.060称为整体安全提升。

MLWE 三个方案的精确对照输入相同：n=2560、m=2816、q=274877844481、Xs=Xe=Uniform(-1,1)。因此当前输入仅运行一次经典、一次量子完整既有格攻击集，再按完全相同输入映射到两个候选；不存在把旧结果冒充候选新跑。

| MLWE对照攻击 | 目标 | 经典log₂ rop | 量子log₂ rop |
|---|---|---:|---:|
| usvp | 启发式秘密搜索 | 201.188000 | 182.585000 |
| bdd | 启发式秘密搜索 | 200.467307 | 182.003279 |
| bdd_hybrid | 启发式秘密搜索 | 200.467307 | 182.003279 |
| bdd_mitm_hybrid | 启发式秘密搜索 | 333.090589 | 333.090589 |
| dual | 区分器 | 203.524000 | 184.705000 |
| dual_hybrid | 区分/部分秘密猜测 | 196.199150 | 178.614315 |

BKW和Arora-GB显式排除。不能把dual成本写为全密钥恢复成本；也不能由模型最小值推导完整IBS优势。默认8个MSIS和12个MLWE成本数与历史输出逐项一致；这20项匹配是当前版本的真实重跑证据。旧源哈希没有被覆盖。

本轮共6个SIS输入×2模型、1个LWE输入×2模型（每模型6类攻击）。未调用旧144点β/ζ网格，也未运行矩阵宽参数前沿。SIS运行仍返回已有警告：内部Euclidean对照分支不使用形状模型；主问题仍为无穷范数，该警告保存在原始JSON。

| 任务 | 上限秒 | 本轮墙钟秒 | 结果 |
|---|---:|---:|---|
| 当前算术/三个构造器检查 | 60 | 5.169 | 完成 |
| 6个SIS输入，经典 | 90 | 48.814 | 完成 |
| 6个SIS输入，量子 | 90 | 51.623 | 完成 |
| 1个LWE输入，经典6攻击 | 120 | 111.693 | 完成 |
| 1个LWE输入，量子6攻击 | 120 | 106.721 | 完成 |

总墙钟324.343秒。每项只跑一次，不是密码原语性能基准；没有实际身份、消息、私钥、密文，消息/身份长度仅记录配置上限。

## 5. 主AI可用性证书：数值已复现，证明状态另列

主AI在本轮后段新增 A 文件和对应测试，尚未提交；最后核对的文件SHA256为3dbf9751592d0f1a07670af0afec480333b142485e38095738b5a1240dc9816d。本旁路只读取并执行纯证书函数，没有修改该文件、重复其LowBits证明或接手CHKP。31项测试通过来自用户报告，本旁路未重跑。并行过程中主AI增加了外部新鲜预言机查询预算及新身份数量检查；在本报告QH=0的三个算例中，先前所有dyadic界逐项保持一致，旧源哈希另保存在观测JSON。

主AI证书的条件为：l≥2、2N|(q−1)、0<Bc=2γ₂−4β₂−1<q、γ₃−2β₂>0、γ₁≥2β₁及既有Hint界。设h=(q−1)/(2γ₃)、G=h(2γ₃−4β₂−1)、F=(G/q)^(Nk)，其正在审核的核心界是：

- δ₀=N/Bc^l，δpair≤δ₀+N/Bc^(l−1)；
- δA≤(δpair+2δ₀F²)/(ε²F²)；
- 好A上每次Sign成功下界为(Bc/(2γ₂+1))^(Nl)(1−ε)F；
- Extract成功下界为((2γ₁−4β₁+1)/(2γ₁+1))^(N(k+l))。

此处列式是对主AI实现和所报候选定理的映射，不是旁路完成证明。其量词为随机Setup的A除δA坏集合外，同一好A上的所有合法固定密钥/消息/挑战输出，掩码每次新抽；不是任意恶意A的保证。

C49默认 ε=1/100、一次Setup/一次新发钥/一次Sign 的有向有理数输出：

| 项 | log₂上界 |
|---|---:|
| 坏A质量 | −295.005945630 |
| Sign重试帽中止，条件好A | −147.668972490 |
| Extract重试帽中止 | −158.059696081 |
| 单次Sign源/哈希解码中止 | −296.024138964 |
| 单次Extract源/哈希解码中止 | −296.023962886 |
| 单生命周期合计 | −147.667898270 |

证书使用1024位有向dyadic运算，完整整数分子保存在 [main-certificate-observations.json](main-certificate-observations.json)，小数log₂只是显示值。此精度会使极小标量项上取整到约2^-1024，不能把显示值误当真实失败率。

生命周期预算有实质影响：

| 假设预算 | ε | 合计log₂上界 | 数值含义 |
|---|---|---:|---|
| 1次Setup、1次Extract、1次Sign | 1/100 | −147.667898270 | 主AI默认单生命周期 |
| 1次Setup、64次Extract、2^20次Sign | 1/100 | −127.668972425 | 不达到2^-128中止目标 |
| 相同64/2^20预算 | 1/256 | −128.589443517 | 在待审定理及理想源模型下达到该可用性目标 |

后一行只是分析中的ε选择，没有修改后端参数。三个算例的额外新鲜预言机查询QH均为0；若允许外部查询，须按A:134–136另加QH乘单次挑战解码中止界。192位Sage实区间独立代入也包围相同的主导结果，见 [conditional-route.json](conditional-route.json)。它不含全部源中止项；主AI证书合计则包含显式标量/挑战解码中止。两份JSON模型边界不同，不能直接当成逐位相同证书。

默认D在ε=1/256下的Sign/Extract帽项分别约2^-20.744、2^-6.120；C64对照为2^-47.559、2^-51.462。它们是弱上界，不能当作实际失败率。把D用于64次Extract与2^20次Sign时并集超过1，须截为1，表示该证明路线在该预算下无有效保证。

单个均匀整数抽样的精确理想字节模型：w=ceil(bitlength(b−1)/8)，ρ=(2^(8w) mod b)/2^(8w)，128次全拒绝概率ρ^128。C49挑战位置最坏b=208，对应ρ=48/256，单位置约2^-309.125。位置与符号最多各一字节宽，故最坏XOF消费κ(128+1)：C49为6321 B，D为8256 B，都≤16384 B；在参数和抽样帽合法的这些profile下，XOF容量不产生额外独立中止。实际SHAKE的理想XOF替换、系统熵失败、恶意输入、缓存超额、存储/并发/回滚事件并未因此全部解决。

## 6. 仍需主AI闭合的安全/组合缺口

| 缺口 | 本轮已经给出的材料 | 仍缺什么 |
|---|---|---|
| 新可用性定理 | 原型条件、精确候选、主AI有向有理输出与独立区间代入 | 第二矩/CRT及所有量词的独立证明审核；审核后冻结定理版本与参数预算 |
| 公开模拟与固定身份缓存 | P:p8–9缓存规则；H1只读高标签；已见/未见标签分支映射 | 真实缓存、有限帽及全部可见信息的模拟误差，编程失败和重复输入概率 |
| E/E′分类 | E′明确包括已签身份上未返回过的新标签 | 各分支概率、签名编程命中分支、分叉事件及完整非零见证约束 |
| 精确安全损失 | P:p9给出的(δ−1/C)((δ−1/C)/t−1/C)，p10使用t²版本，t=s+h | 不可直接把每个分支都赋予完整δ；需分支权重、模拟误差、运行时间和查询预算 |
| 模块归约 | 两种矩阵维度、分块范数、均匀t混合、可逆块条件 | 与作者草图的完整条件对应，不把矩阵§3的d=2γ₂+2κβ₁直接套到模块§4 |
| 已见标签非零 | 当前条件平均猜测界与零见证反例 | 证明真实视图满足该平均界前提；Q_guess=2^20只是分析示例 |
| 后量子口径 | 量子Core-SVP模型和泛型挑战搜索数 | 完整QROM安全引用/归约；κ49的112.672模型限制不能由可用性补偿 |
| 原语到IBME | I规定Wang组合须自适应匿名两层HIBE和自适应IBS；绑定、混合层各有独立条件 | 主AI/CHKP负责人完成相同具体配置、载荷、生命周期、所有安全目标的组合核验 |
| 工程部署 | 参数构造器和既有显式资源帽 | 参数版本选择、计数预算和失效处理；不能静默换默认或把候选加载为现有系统 |

可用性证明完成也不会自动完成EUF-ID-CMA归约。论文式中δ²/t²的概率损失不能简单对197.976等估计值“减去若干位”；量子挑战指数也不能与MLWE/MSIS位数相加。报告不输出一个整体安全位数。

## 7. 可直接复跑的命令

下面命令在Windows PowerShell执行；Sage路径始终使用WSL用户的 ~/miniconda3/envs/sage，无用户名硬编码。所有脚本stdout输出JSON，未给出仓库内输出路径。

~~~powershell
wsl -e bash -lc 'PYTHONDONTWRITEBYTECODE=1 GIT_OPTIONAL_LOCKS=0 timeout --signal=TERM --kill-after=5s 510s ~/miniconda3/envs/sage/bin/python -B /mnt/c/Users/A/.dsh/deliverables/CODEX-step22-luo-parameters/run_current_screens.py --repo /mnt/c/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS --estimator-path ~/lattice-estimator'
~~~

仅重跑精确候选/D的SIS批次可加 --job sis-classical 或 --job sis-quantum；外层timeout相应设90s。此批次只含默认四行及两候选各共同界。MLWE单批加 --job lwe-classical / --job lwe-quantum，外层设120s；输入完全相同不再逐候选重复。无旧广域网格。

~~~powershell
wsl -e bash -lc 'PYTHONDONTWRITEBYTECODE=1 timeout --kill-after=5s 60s ~/miniconda3/envs/sage/bin/python -B /mnt/c/Users/A/.dsh/deliverables/CODEX-step22-luo-parameters/evaluate_conditional_route.py --repo /mnt/c/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS'
~~~

主AI证书原型纯读取运行（在该工作树根目录）：

~~~powershell
$env:PYTHONPATH='src'
python -B -m experiments.research.luo_robust_abort_certificate --profile availability-candidate
python -B -m experiments.research.luo_robust_abort_certificate --profile availability-candidate --extracts 64 --signs 1048576
~~~

这两个CLI命令使用默认ε=1/100；ε=1/256结果来自直接调用certificate(p, epsilon=Fraction(1,256), extracts=64, signs=2**20)。不把两个ε下的结果混写。

首次尝试读取工作树Git元数据时，WSL git不能解析Windows绝对gitdir指针，退出1，尚未运行估计器。仅在旁路runner中将工作树元数据查询改用已安装Windows Git；没有改.git、仓库、估计器、系统或依赖。后续完整重跑5项均成功。

## 8. 来源锚点与交付边界

路径以所给只读活动工作树为基准；M/R/S/J/E/I/H/B/L在f079ce1上的行号；A为本轮读取的主AI未提交快照，须用SHA256识别。

| 键 | 文件及锚点 |
|---|---|
| M | [luo_module.py:53](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/src/ibme/ibs/luo_module.py:53)，条件73–108，抽样188–240，算法442–535 |
| R | [luo_module_math.py:61](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/src/ibme/ibs/luo_module_math.py:61)，Hint域与运算131–186 |
| S | [luo_module_security_screen.py:78](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/experiments/research/luo_module_security_screen.py:78)，见证87–109、非零113–147、预算150–168、成本287–368 |
| J | [luo_joint_parameter_screen.py:149](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/experiments/research/luo_joint_parameter_screen.py:149)，论文列34–37、MLWE映射265–306 |
| E | [luo_parameter_screen.py:194](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/experiments/research/luo_parameter_screen.py:194)，固定提交26–28、攻击目标208–216 |
| I | [IMPLEMENTATION_SPEC.md:59](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/IMPLEMENTATION_SPEC.md:59)，Wang准入7–9、格式/上下文59–75、真实研究组合183–195 |
| H | [module-security.json:4](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/docs/research/2026-10-09-admission/module-security.json:4)，源指纹2919、历史决定3142 |
| B | [joint-screen.json:5778](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/docs/research/2026-10-09-m2b/joint-screen.json:5778)，当前MLWE输入5819 |
| L | [参数与引用边界.md:24](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/docs/research/2026-10-11-luo-lifecycle/参数与引用边界.md:24)，分支命名与旧证据衔接 |
| A | [luo_robust_abort_certificate.py:92](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/experiments/research/luo_robust_abort_certificate.py:92)，候选86–88，模型/排除项145–162 |
| P | [本地论文](C:/Users/A/.codex/worktrees/luo-acceptance-evidence/IB-ME-from-HIBE-IBS/papers/2024_ibs_without_trapdoors_luo.pdf)，PDF p8–10、11–16 |

旁路新增文件全部在本交付目录：

1. REPORT.md：本报告。
2. admission-matrix.json：22项准入矩阵、3个profile、来源/行号、20项旧新成本对照及缺口。
3. current-profile-rerun.json：5个真实有界任务完整成本、环境、输入和指纹。
4. main-certificate-observations.json：主AI原型三个预算/ε组合的完整dyadic证书输出。
5. conditional-route.json：三个profile的192位区间代入和标量/XOF资源界。
6. run_current_screens.py：不写仓库、不运行旧网格的有界复跑入口。
7. evaluate_conditional_route.py：待审定理的区间数值代入入口。
8. paper-page-15.png、paper-page-16.png：源公式/表格目视核验用渲染图。

报告、JSON和脚本均经apply_patch写入；PNG是只读PDF渲染输出。未安装、下载依赖或使用账号/密钥；未生成私有材料；未改params/src；未提交或推送。用户本次明确只读仓库，故Git提交要求不适用于这些仓库外旁路产物。

开工工作树干净；估计器完成时仍干净。最终观察到主AI的未跟踪产物：experiments/research/luo_robust_abort_certificate.py、tests/test_luo_robust_abort_certificate.py、experiments/research/luo_candidate_probe.py、docs/research/2026-10-11-luo-abort-bound/，均保留原状。本旁路的仓库修改列表为空。

交付前证据一致性检查通过：4个JSON均可解析，2个脚本均通过AST语法检查，22项矩阵/3个profile完整，5个有界任务完成，20项历史成本匹配，C49参数与主AIprofile逐字段相同，引用文件存在且所有行号范围有效，已登记源SHA256匹配。首次锚点检查发现H的末行超出文件长度，已改为3158并重新通过；并行主AI更新A后已重新读取和运行，旧有数值证书记录保持一致。git diff --check通过；未运行或声称运行31项主AI测试、完整原语或CHKP攻击验收。

方法说明：采用 scientific-critical-thinking 技能将来源事实、条件推论、模型估计和准入决定分开，PDF技能用于目视核验。技能不作为密码学证据。流程工具引用：Kassis, Agarwal, He, Patel & Brueckner (2026), [Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents](https://doi.org/10.48550/arXiv.2609.00065)，书目信息本轮已核验。

