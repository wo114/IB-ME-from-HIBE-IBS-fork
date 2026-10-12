# CHKP 公开后端收尾记录

日期：2026-10-12。**本轮研究实现和实际功能验收已完成，正式安全参数仍未准入。**12个必要阶段收据已齐：真实根、父、四个256目标叶、种子封装/恢复、CHKP + Luo C64B compact + Hybrid + BYTEAUTH组合及CLI。根父复用有独立来源记录，旧失败没有覆盖。全项目排序由[项目状态](../../PROJECT_STATUS.md)维护；长期接口和算法边界见[CHKP契约](../../specs/chkp-hibe.md)。

## 1. 已实现的范围

| 项目 | 本次代码范围 | 声明边界 |
|---|---|---|
| 公开 HIBE 后端 | [CHKP](../../../src/ibme/hibe/chkp/) 的 Setup、Extract、Derive、Encrypt、Decrypt、对象加载 | 六方法研究后端与真实生命周期已验收；安全属性按下述参数边界报告 |
| 根、父、叶 | MP12 GenTrap 转完整格基；CHKP ExtBasis/RandBasis/ToBasis；最大深度 256 个独立索引目标的 SampleD | 父委派没有用 MP12 DelTrap 替代；历史 `first_suite` 的独立 MP12 profile 不计作本后端验收 |
| 随机性与噪声 | CSPRNG 字节注入；有限 Gaussian；均匀加密向量；实际 `round(qX)` 噪声 | α 是 Gaussian 宽度，非标准差；有限分布误差、中止、资源失败分别记录 |
| 统一装配 | `hibe=chkp` 可与独立选择的IBS进入兼容检查；本轮实际通过Hybrid + Luo C64B compact + BYTEAUTH | 该结果仅属于所记录配置；reference/compact是同一IBS的两种格式，不能算两套算法 |
| 状态与恢复 | 完整公开上下文和参数绑定；固定地址缓存；规范私密对象；CLI 主/接收状态事务 | 同 OS 本地锁与 pending 提供失败后保守阻止；无外部存储认证、防回滚或跨系统锁保证 |

根和采样工具统一从 `src/ibme/lattice/chkp/` 导入，旧实验入口保持兼容，不再复制两套运行时。论文、参数、安全归约与实现对应不因代码迁移而自动成立。

## 2. 冻结参数及必须保留的负面对照

当前 `research_params()`：n=2，q=1099511627791，m=127，父维254，叶维381，qα=4，32 B 种子 / 256 位，内层身份上限86 B。默认 checked LLL 是参数预先固定的确定性后处理，不能依据失败样本临时改策略重抽。

这个小维配置**不是具备密码安全强度的正式参数**。[公开恢复工具](../../../experiments/attacks/chkp_small_dimension.py)只读取公开根上下文、胶囊、已知双方身份和公开有限噪声支持，不读取私钥或原始 seed。当前半径36对应最多 73²=5329 个前导误差组合，可求加密向量并筛选 seed 候选。工具只输出候选数及哈希；实际生命周期必须断言真实 seed 的 SHA-256 在候选中，才写入 `public_attack_matches_seed=true`。公开代数夹具通过不能冒充新采样实例的恢复收据，候选列表也不能未经检查写成唯一恢复。

全部入口继续保持：

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
```

原始 CPA 解密允许低位变化后恢复同一 seed；错误身份也不要求 raw 层主动报错。规范 wire、Hybrid 胶囊 AAD/AEAD、IBS 消息/身份绑定、BYTEAUTH 字节拒绝必须分层检查。Hybrid 包装不能修复公开可恢复的底层 seed 所带来的保密性问题。

## 3. 配置准入修复

共享装配对 CHKP 增加无熵的公开检查：有限噪声支持半径/精度满足资源帽，且现有 `evaluate_noise` 的解密充分条件成立。固定工程预算为 `error_bits=64`、`seed_bits=256`、`encapsulations=2^20`；冻结配置对应的**理想、条件式**并合界为 2^-36，条件是叶原像范数满足所用界。

此数没有包含有限采样 TV/中止、根/父失败、文件系统或安全归约，不能称为整个实现的失败概率。检查是充分条件，不是必要条件。自定义 `CHKPParams` 仍可用于原语诊断；例如 qα=128 或512的配置虽可构造，现已不能通过共享装配。此次噪声准入检查没有改变冻结参数、序列化和 suite 摘要；它只额外拒绝此前会被静态放行的这类自定义配置。LLL具体版本另由源码提交区分，同一suite摘要不证明历史密钥使用同一后处理版本。

## 4. 实际尝试必须完整披露

| 尝试 | 已知事实 | 不得推导的结论 |
|---|---|---|
| 首次 `chkp-lifetime-2026-10-12` | setup 收据通过：根维127、约4.126 s、1,362,388随机字节；主控记录 parent 在约942 s后终止，停留于巨大 HNF 变换后的行列式工作。没有 parent 成功收据，原目录永久保留 pending | 不是父采样通过；也不能仅据运行中止判定论文采样数学失败 |
| 行列式修复后 `chkp-lifetime-2026-10-12-r2` | setup通过：3.225 s、1,406,180随机字节；parent约750 s后终止，已越过ToBasis，栈位于δ=.999的LLL wrapper。失败收据及pending保留 | 没有父成功对象；不把确定性后处理超时写成采样分布或数学前提失败 |
| 固定LLL v2后 `chkp-lifetime-2026-10-12-r3` | 根与父使用源码`0c9a7f3`；[父成功收据](evidence/lifecycle/parent.json)：254维、4606.795 s、26,906,498随机字节、459,799 B对象、进程峰值RSS520,976 KiB。叶使用`2976c1a`，[302.890 s后准备阶段失败](attempt-3-leaf-preparation-failed.json)：ValueError、0随机字节；已确定为标量平方宽度执行域上限，保留pending与失败叶状态 | 父通过仍不是叶通过；不得覆盖失败、删除 pending 重抽，或将不同尝试合并成一次成功 |
| 显式继续 `chkp-lifetime-2026-10-12-r3-resumed` | `0765304`将固定标量执行域扩展至`2^88`；`3c53df1`恢复工具实际通过，11.115 s、0随机字节，根/主密钥逐字节不变、父等于原master缓存。[叶256目标真实采样](evidence/lifecycle/leaf.json)通过：347.726 s、42,660,095随机字节、381维、873,447 B对象、峰值RSS335,940 KiB。[封装/恢复](evidence/lifecycle/roundtrip.json)及无熵缓存复用通过；5329个公开误差组合中唯一seed候选与真实seed匹配 | 不把复制的setup/parent记为本轮新生成；公开攻击成功保留为小维参数不安全的负控，不能因功能通过授予安全等级 |
| 真实 CHKP + C64B 组合 | [prepare](evidence/combination/prepare.json)复用Bob/Alice真实叶并生成Luo C64B发送密钥；[第二接收者Carol](evidence/combination/receiver-Carol.json)通过：3821.835 s、27,045,274随机字节、461,291 B接收密钥。其余三叶及[44项组合检查](evidence/combination/checks.json)全部通过 | 不用教学ABB10、旧first_suite或mock结果代替；不同父基的两次耗时不能直接作为优化加速比 |
| CLI | [新状态实际setup/catalog](evidence/cli/setup.json)通过8项检查、2个实际命令，使用`0db4da9`，总耗时3.927 s；[导入已生成组合状态](evidence/cli/imported.json)通过59项检查、15个实际命令，120.360 s | 导入状态没有重新生成CHKP根父叶或IBS身份；不能记为由该CLI setup生成 |

### r3零熵失败的定位与继续原则

[完整只读预检](evidence/diagnostics/preflight-failure-gate.json)已确定首个拒绝为有限标量平方宽度上限`2^80`；精确GSO与C1宽度充分门已通过，尚未调用采样。此前300秒的[诊断超时](evidence/diagnostics/preflight-timeout.json)只是工具截止时间过短，不计作另一次密码实验失败。

复用本地已计算的几何数据，对唯一固定候选`2^88`做了[标量域检查](evidence/diagnostics/scalar-domain-candidate.json)：原半径上限`2^48`、精度320、质量256、尾参数128、拒绝次数2048和单GPV随机字节预算均通过。这份结果当时尚未检查后续路径/扩展基及256目标总预算，不能单独算叶成功。

用户明确要求从已有成功结果继续。因此修复限定于采样器可执行域及有记录的零熵预检恢复，保持原公钥/上下文/参数/根/父基；不再次GenTrap、RandBasis或LLL，不重抽根父。原r3失败叶状态和pending保留。恢复分支必须核验没有成功叶或耗熵失败，并单列来源、复制结果与第一次实际叶采样；普通后端的失败墓碑规则不因此放开。安全参数和全局抗回滚结论仍未获得准入。

后续[完整预检](evidence/diagnostics/preflight-complete.json)已通过全部17项门，包括ExtendedGPV构造、路径准入、真实身份矩阵绑定及256目标总预算。预检使用与原父快照、`2976c1a`源码及未变化GSO函数严格绑定的本地几何缓存，没有重算GSO或采样。`2^88`只是可执行标量平方宽度上限，实际叶宽度、概率质量、采样顺序、随机带上限及全部误差门保持原值。实际叶调用仍自行执行正常构造检查。[恢复收据](evidence/lifecycle/resume.json)只声明可以进入第一次叶采样；[源setup](evidence/lifecycle/history/setup.json)、[源parent](evidence/lifecycle/history/parent.json)和[源失败](evidence/lifecycle/history/leaf-failed.json)单列且逐字节保留。

[历史完整预检源码](evidence/diagnostics/leaf_full_preflight.py.txt)以非执行文本保存原始字节，SHA-256与原收据一致；静态检查确认其中没有密钥、几何数值或私密文件的固定哈希。原运行依赖本地私密父基及其可信几何缓存，因此公开包允许审查代码和来源链，**不能独立重现同一私密实例的缓存诊断**。私密cache、binding和intent不发布。公开可复用入口是下方生命周期命令及[显式继续工具](../../../experiments/research/chkp_resume_pre_entropy.py)；前者用于新研究实例，后者仅针对满足条件且保留完整本地证据的原实例，均不能把收到的外部pickle当作可信输入。

行列式修复使用精确整数乘积及完整格指数证书，不移除核空间、完整性或上三角检查；LLL 的尺寸约减复用经精确运算保持的有序 GS 向量。这里不填写未经实测的加速倍数。

LLL v2固定δ=.75、无变换矩阵，精确复核size≤.5、Lovasz≥.74以及未放宽的GS界。旧.999约减强度不是CHKP采样前提。新旧输出允许不同；相同确定性后处理的TV由数据处理不增，不能反称输出逐字节相等。选择依据是公开固定代数夹具的有界比较，不从失败私密样本择优挑参数。两个中止尝试分别见[首次](attempt-1-interrupted.json)、[第二次](attempt-2-interrupted.json)。

## 5. 已执行的定向检查

本轮13份JUnit已集中归档；[逐文件索引](evidence/regression/index.json)列出测试文件、复跑参数和版本边界。另有明确标注为原输出转录的几何等价和恢复守卫测试记录。多个批次覆盖相同测试，**不相加为独立测试总数**。

| 收据 | 结果 | 范围与版本 |
|---|---|---|
| [Windows集成检查](evidence/regression/chkp-final-windows.xml) | 235 passed / 19 skipped | 后端、wire、装配、CLI及状态；19项需Sage。早于行列式及LLL修复 |
| [Sage研究检查](evidence/regression/chkp-final-sage.xml) | 292 passed / 25 skipped | 实际格运行时和后端；25项为历史可选native/qFALL检查。早于后处理修复 |
| [行列式修复](evidence/regression/chkp-determinant-repair.xml) | 65 passed | 对应`fa14fd0`改变的ToBasis及运行时 |
| [完整格乘积证书](evidence/regression/chkp-product-certificate.xml) | 16 passed | 整数上三角乘积及反例 |
| [真实驱动守卫](evidence/regression/chkp-driver-guards.xml) | 48 passed | pending、前序、收据、容量；不冒充真实采样 |
| [噪声配置准入](evidence/regression/chkp-configuration-gate.xml) | 37 passed | 冻结配置、过大噪声拒绝、通用装配 |
| [CLI验收工具](evidence/regression/chkp-cli-harness.xml) | 32 passed | 命令/收据/零熵守卫；真实CLI结果另列 |
| [固定LLL v2](evidence/regression/chkp-lll-v2.xml) | 40 passed | 对应`0c9a7f3`，完整格/GS/size/Lovasz检查 |
| [交付清单检查器](evidence/regression/chkp-delivery-audit.xml) | 46 passed / 1 skipped | Windows只跳过需要符号链接权限的用例；独立WSL普通Python执行47项全过 |
| [精确采样算术等价](evidence/regression/chkp-sampler-equivalence.xml) | 48 passed | 对应`0c1a77d`；新旧输出、逐次耗熵和中止一致，含ExtendedGPV和大有理数边界 |
| [采样准备几何等价](evidence/regression/chkp-gs-equivalence-results.json) | 100 passed | 对应`2976c1a`；执行子代理原命令/输出转录，非JUnit，也非主控另行复跑 |
| [LLL几何缓存等价](evidence/regression/chkp-lll-geometry.xml) | 54 passed | 对应`be09ecb`；14个新增几何/最终输出对照及40个既有约减/格证书用例 |
| [固定标量执行域](evidence/regression/chkp-scalar-domain.xml) | 114 passed | 对应`0765304`；包含旧域输出/耗熵轨迹相同、新域准入、超帽及证书不足拒绝 |
| [显式恢复守卫](evidence/regression/chkp-resume-results.json) | Sage 40 passed；Windows 39 passed / 1 skipped | 对应`3c53df1`；原命令输出转录，非JUnit；含实际小型对象编解码与禁止重新生成/采样 |
| [恢复来源验收](evidence/regression/chkp-delivery-audit-recovery-gates.xml) | 66 passed / 1 skipped | 对应`71a3fa1`；缺历史、篡改源测量、假零熵、丢失败或缺完整预检均拒绝；只跳过Windows符号链接权限用例 |

精确算术优化预存共同分母下的整数权重，以整数点积计算原来的有理投影；Gaussian指数采用精确差平方因式分解。原参数、抽样顺序、整数质量和失败规则不变；额外保存O(d²)整数权重，不预分配随机带。此处不根据小算术探针声称整链加速倍数。

`2976c1a`进一步保留每一个GS中间值及门的顺序，用内部QQ专用位长检查减少通用解析开销。投影改用原始列点积：已减去的更早GS向量与当前GS向量精确正交，因此每次残差及最终权重保持相同；外部输入仍走原类型/文本检查。定向100项通过，包含逐值/逐门、最终值合格但中间值超帽的反例、证书与随机调用轨迹对照。[公开48维探针](evidence/regression/public-gs-gate-probe.json)三次CPU中位数0.984899→0.498563 s；这是公开夹具的局部结果，不代表真实254维或整链加速。此改动不改变参数、分布、安全声明或已在运行的父进程。

`be09ecb`对LLL之后的QQ正交化复用每条GS向量的平方范数，避免Sage原实现对每次投影重新计算；仍是原始列投影，精确输出相同。[公开24/40/64维对照](evidence/regression/chkp-lll-geometry-timing.json)各三轮与Sage逐元素一致，局部墙钟中位加速约2.42/2.68/2.42倍；同机并发负载下的这些数不预测整链耗时。LLL、尺寸约减及Lovász/GS/完整格检查没有删减。r3父使用旧实现已经成功，不把新方法的局部成绩回写成其真实耗时。

真实组合预检在Sage通过两种格式，均标记`sampled=false`：签名29455/16383 B、最大应用消息3924 B、内层86/86/32 B。普通Windows Python按预期报告Sage不可用，没有教学或mock回退。真正采样和密码操作只计入各自阶段收据。

运行环境见[环境记录](environment.json)。Sage使用WSL的`~/miniconda3/envs/sage`；真实随机源为系统CSPRNG，固定随机值只用于明确的测试夹具。已有JUnit不是重跑全部历史研究的声明。主控复跑精确采样检查时曾输入不存在的测试文件名，pytest未收集任何测试；纠正文件名后48项通过，未触发密码重抽。

## 6. 研究验收结果与未完成的安全工作

本轮已实际完成：根→父→同叶256目标→实际噪声封装/恢复、四种身份匹配、对象跨进程恢复、无熵缓存复用、分层篡改拒绝、公开恢复负控、真实组合和CLI。失败/超时完整保留；复制的根父明确标记`reused_actual_result`，其历史测量不算本轮新生成。

另外三个新叶地址分别为[Bob/Eve](evidence/combination/leaf-Bob-Eve.json)305.298 s、[Carol/Alice](evidence/combination/leaf-Carol-Alice.json)284.248 s、[Carol/Eve](evidence/combination/leaf-Carol-Eve.json)282.366 s。每个地址256目标，采样后加载字节往返均通过。本轮每个新地址只实采一次，没有根据失败结果另选样本。

组合44项检查耗时60.855 s，覆盖诚实解密、仅发送者错、仅接收者错、双方错、规范编码、对象恢复、IBS消息/身份绑定、有效外层OTS但旧IBS的完整伪造拒绝、空消息、最大载荷及超限前拒绝。原始低位修改仍可恢复同一seed，而Hybrid完整胶囊AAD拒绝；二者作为不同层的行为同时保留。CLI在已保存的真实状态上验证重复发钥、解密、拒绝无明文输出及状态字节不变，没有隐式重采样。

| 实际尺寸 | 字节数 |
|---|---:|
| CHKP内层seed / 编码后的双方身份 | 32 / 86 / 86 |
| 原始CHKP胶囊 | 3,919 |
| C64B compact签名 | 16,383 |
| 完整BYTEAUTH密文，空消息 / 16 B消息 | 119,038 / 119,054 |
| 最大应用消息 / 其完整密文 | 3,924 / 122,962 |

上述尺寸包括所选包装的实际开销，不将原始胶囊大小当作完整IB-ME密文。时间属于共享开发机上的单次记录，不是稳定性能均值；峰值RSS只在具备该字段的生命周期收据中报告，组合驱动没有测得独立整链峰值。

正式安全与可用的大参数仍单独未完成：需同一参数集同时满足困难性、正确性、有限采样与资源条件，并核对 CHKP/MP12/Wang 组合前提和查询相关损失。[静态容量审计](../../../experiments/research/chkp_capacity_audit.py)对 n=16/64/128 的拒绝只属于当前配置和实现上限，不证明所有 CHKP 构造不可行，也不把 n 值等同安全位数。

沿用已有[参数条件结果](evidence/parameters/profile.json)与[容量比较结果](evidence/parameters/capacity.json)，没有重跑历史采样。固定q/根宽度/统计目标下，n=16/64/128对应叶维2445/9516/18939，均超当前512维执行上限；这些数是静态投影。旧结果早于本次`2^88`执行域修复，实际参数字节没有改变，新标量域及真实叶是否可执行分别由完整预检和叶收据证明，不能用静态表替代。

公开交付只纳入脱敏收据、诊断源码文本、源码/清单哈希和测试结果；`test-results/`中的私钥、状态、胶囊试验数据及进程日志继续忽略。[最终清单](source-manifest.json)记录源码版本，清单不包含自身或审计输出的哈希。[公开审计结果](public-audit-result.json)通过12个阶段、130份源码及48份材料的一致性检查，明确没有重跑实验或读取私钥；18份阶段/恢复收据文件不等于18次密码实验。统一README和发布由IB-ME／Luo对话在收到固定交付后完成。

## 7. 复跑入口

以下是新实验的顺序，不是重试已有失败地址的命令。先进入仓库根目录；所有目录须换成未使用过的名称。单次耗时取决于实际基，父LLL没有承诺短时限，不能以小公开夹具计时推算。任何非零退出都应停下检查该轮收据，保留pending。

```bash
(
set -e
export PYTHONPATH=src
export PYTHONDONTWRITEBYTECODE=1
py="$HOME/miniconda3/envs/sage/bin/python"
life=test-results/chkp-new-lifetime
combo=test-results/chkp-new-combination
cli=test-results/chkp-new-cli

for phase in setup parent leaf roundtrip; do
  "$py" -u -B -m experiments.research.chkp_lifecycle "$phase" --directory "$life"
done
for phase in prepare receiver-Carol leaf-Bob-Eve leaf-Carol-Alice leaf-Carol-Eve checks; do
  "$py" -u -B -m experiments.research.chkp_combination "$phase" --lifetime "$life" --directory "$combo"
done
"$py" -B -m experiments.research.chkp_cli_acceptance setup --directory "$cli"
"$py" -B -m experiments.research.chkp_cli_acceptance imported --source "$combo" --directory "$cli"
)
```

每个工具内部检查前序、固定配置、锁和失败标记；这组示例不删除任何旧目录或标记。CLI的`setup`是真正新建实例；`imported`导入已验收组合的固定状态再执行实际CLI命令，两种来源分别报告。

完整公开清单生成后，可用普通Python只读核对：

```text
python -B -m experiments.research.audit_chkp_delivery --directory docs/research/2026-10-12-chkp-closure --source-root .
```

该工具核对12个必要阶段、固定核心源码覆盖和文件哈希；若根父标注复用，还须验收恢复、历史失败及完整预检来源链。缺失/失败/全跳过不能通过，恢复复制不计为第13次新密码实验。它不读取私钥，不重新执行密码实验，不验证Git提交对象，也不证明材料来源真实性或密码安全。历史执行的源码原始字节哈希与最终Git规范换行后的源码哈希分别保留，不据两者不同重做实验或改写旧收据。
