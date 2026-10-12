# CHKP 公开后端收尾记录

日期：2026-10-12。**本页当前为待实际运行证据回填的记录**，不代表整链已经通过。全项目排序仍由[项目状态](../../PROJECT_STATUS.md)维护；长期接口和算法边界见[CHKP 契约](../../specs/chkp-hibe.md)。

## 1. 已实现的范围

| 项目 | 本次代码范围 | 声明边界 |
|---|---|---|
| 公开 HIBE 后端 | [CHKP](../../../src/ibme/hibe/chkp/) 的 Setup、Extract、Derive、Encrypt、Decrypt、对象加载 | 公开接口与实际算法实现已存在；真实生命周期是否完成须看对应收据 |
| 根、父、叶 | MP12 GenTrap 转完整格基；CHKP ExtBasis/RandBasis/ToBasis；最大深度 256 个独立索引目标的 SampleD | 父委派没有用 MP12 DelTrap 替代；历史 `first_suite` 的独立 MP12 profile 不计作本后端验收 |
| 随机性与噪声 | CSPRNG 字节注入；有限 Gaussian；均匀加密向量；实际 `round(qX)` 噪声 | α 是 Gaussian 宽度，非标准差；有限分布误差、中止、资源失败分别记录 |
| 统一装配 | `hibe=chkp` 可与独立选择的 IBS 进入兼容检查；当前实跑目标是 Hybrid + Luo C64B + BYTEAUTH | reference/compact 是同一 IBS 的两种格式，不能算两套算法 |
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
| 固定LLL v2后 `chkp-lifetime-2026-10-12-r3` | 源码`0c9a7f3`；待主控回填各阶段收据、版本及耗时 | 不得覆盖前两次、删除 pending 重抽，或将三次尝试合并成一次成功 |
| 真实 CHKP + C64B 组合 | 待 prepare、第二接收者、其余三叶及 checks 的逐阶段收据 | 不用教学 ABB10、旧 first_suite 或 mock 结果代替 |
| CLI | 待分别填写“导入已生成状态后的 CLI 操作”和“新状态的实际 CLI setup”收据 | 导入状态不能记为由 CLI setup 生成；必须区分二者来源 |

行列式修复使用精确整数乘积及完整格指数证书，不移除核空间、完整性或上三角检查；LLL 的尺寸约减复用经精确运算保持的有序 GS 向量。这里不填写未经实测的加速倍数。

LLL v2固定δ=.75、无变换矩阵，精确复核size≤.5、Lovasz≥.74以及未放宽的GS界。旧.999约减强度不是CHKP采样前提。新旧输出允许不同；相同确定性后处理的TV由数据处理不增，不能反称输出逐字节相等。选择依据是公开固定代数夹具的有界比较，不从失败私密样本择优挑参数。两个中止尝试分别见[首次](attempt-1-interrupted.json)、[第二次](attempt-2-interrupted.json)。

## 5. 已执行的定向检查

本轮10份JUnit已集中归档；[逐文件索引](evidence/regression/index.json)列出测试文件、复跑参数和版本边界。多个批次覆盖相同测试，**不相加为独立测试总数**。

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

精确算术优化预存共同分母下的整数权重，以整数点积计算原来的有理投影；Gaussian指数采用精确差平方因式分解。原参数、抽样顺序、整数质量和失败规则不变；额外保存O(d²)整数权重，不预分配随机带。此处不根据小算术探针声称整链加速倍数。

真实组合预检在Sage通过两种格式，均标记`sampled=false`：签名29455/16383 B、最大应用消息3924 B、内层86/86/32 B。普通Windows Python按预期报告Sage不可用，没有教学或mock回退。真正采样和密码操作只计入各自阶段收据。

运行环境见[环境记录](environment.json)。Sage使用WSL的`~/miniconda3/envs/sage`；真实随机源为系统CSPRNG，固定随机值只用于明确的测试夹具。已有JUnit不是重跑全部历史研究的声明。主控复跑精确采样检查时曾输入不存在的测试文件名，pytest未收集任何测试；纠正文件名后48项通过，未触发密码重抽。

## 6. 收尾条件与未完成的安全工作

研究整链收尾须具备：根→父→同叶256目标→实际噪声封装/恢复、四种身份匹配、对象跨进程恢复、无熵缓存复用、分层篡改拒绝、公开恢复负控、真实组合和 CLI 收据。失败/超时完整保留，空 checks、跳过或历史通过不得充当本轮完成。

正式安全与可用的大参数仍单独未完成：需同一参数集同时满足困难性、正确性、有限采样与资源条件，并核对 CHKP/MP12/Wang 组合前提和查询相关损失。[静态容量审计](../../../experiments/research/chkp_capacity_audit.py)对 n=16/64/128 的拒绝只属于当前配置和实现上限，不证明所有 CHKP 构造不可行，也不把 n 值等同安全位数。

公开交付只纳入脱敏收据、源码/清单哈希和测试结果；`test-results/` 中私钥、状态、胶囊试验数据及进程日志继续忽略。收尾完成后由主 AI 统一提交，本页最终提交和真实验收结果待回填。

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

该工具核对12个必要阶段、固定核心源码覆盖和文件哈希；缺失/失败/全跳过不能通过。它不读取私钥，不重新执行密码实验，不验证Git提交对象，也不证明材料来源真实性或密码安全。
