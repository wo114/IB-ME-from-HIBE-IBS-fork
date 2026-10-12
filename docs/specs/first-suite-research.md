# first_suite 独立研究组件契约

此页迁移自 `upstream/main` 的 `bc22c9c` 版本公共规范，保留已实现组件的算法、状态、资源与证据边界。它补充 [统一实现规范](../../IMPLEMENTATION_SPEC.md)，不发布全项目排序；当前状态见 [PROJECT_STATUS](../PROJECT_STATUS.md)。各段中的“本轮”“下一项”仅指原交付版本。

`experiments/research/first_suite/` 已在本 checkout 中，包含真实有限根/父/叶和固定 256 位种子研究路径。下面日期为 2026-10-11 的迁移段落描述当时的独立组件，不否定新增的计算型 MP12 六方法研究后端。DelTrap 为独立 MP12 profile，不等同于原 CHKP RandBasis；n=1 和新 n=2 公开恢复负控、none/false 声明继续保留。

## 计算型 MP12 六方法研究后端

[公开实现](../../experiments/research/first_suite/hibe_reference.py)、[自定义登记](../../experiments/research/first_suite/hibe_registry.py)和[交付/重放命令](../research/team-a-delivery/2026-10-12-hibe-reference/README.md)对应独立 `MP12-COMPUTATIONAL-CHKP-FINITE/1` profile，backend ID 为 `mp12-chkp-reference`。MP12 §5.2 的计算型 `[I|Ahat]` 根与 Algorithm4 委派，结合 CHKP 的两层 H/G 和共享前导；不关闭旧统计根的 regularity 检查，不继承原 CHKP RandBasis 安全结论。

六方法和 per-call `rng` 满足共同 HIBE 接口；真正 Extract→Derive，固定每叶256原像，并提供 `validate_key_binding`。PK/MSK/两级密钥/密文分别有版本与严格 codec，绑定全参数、公钥与身份路径；失败地址在私有状态中保留，恢复不能重新抽样。缺少 engine 的新进程可以恢复已有状态；新 Setup/委派需要指定的本机转换工具。用户持有的私钥、基、原像、RNG 和生产种子不进入 Git。

当前 profile：n=2、q=549755813911、根/父/叶维度84/168/252、s_R²=16；最多2接收者、每人2子地址。内层身份最多86 B，载荷0—32 B；Hybrid 使用32 B seed，外层共同身份64 B。它是 source checkout/Sage 的研究后端，默认 registry/CLI/wheel 尚未接入；原 `chkp` 的 unavailable 记录不能改名充数。该 profile 已有公开噪声枚举恢复明文反例，不能用于正式推荐或宣称隐私安全。

真实采样/方程/规范解析/绑定、固定状态与完整组合的功能分别验收；raw CPA 容错和 Hybrid/BYTEAUTH 拒绝分层处理。正式参数、两角色 LWE 估计、变体模型和分布对应仍待核验，保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本轮独立复核和版本边界见[PR 合入记录](../deliveries/2026-10-12-pr-review/README.md)；历史探针计数不与本轮测试相加。

## 按既有交付版本保留的专属契约

2026-10-11 首套独立DelTrap契约：`first_suite/compact_delegation.py`以FirstFiniteGPV、最后nk列和真实目标G−A1实现MP12 Algorithm4；额外扩展列进入采样前缀，按公共整次预算先准入，单列坏范数/采样异常中止整次，不重试、不返回旧trapdoor。矩形私有JSON wire绑定外部真实公开矩阵/精确宽度，严格格式/方程/范数；加载不证明生成分布。独立private_basis_bridge可作确定性qFALL完整基转换，旧GenTrap/采样/ToBasis guard保持，非Algorithm3或原CHKP/RandBasis的直接替换。MSK显式研究出口只给持有私钥者已验证的不可变根基，不发钥或变更旧地址。完整范围/变体模型缺口、实际有限链和估算见[本轮记录](../research/2026-10-11-first-suite-compact/README.md)，未注册HIBE后端/安全preset。下一项仍需实际困难参数、模型对应和七入口/全系统验收。

2026-10-11 首套私有根契约：`first_suite/root_generation.py`以系统bytes产生均匀Abar和有限零中心Gaussian R，独立Rust `IBME/MP12-SECRET-ROOT/1`仅作qFALL确定性完整基转换；旧public-fixture接口不改、不回退。输入先验素性/维度/支持模q单射/实际有限熵regularity/整次随机带，输出验严格schema、规范整数、定义关系、完整核格和公开GS界。regularity使用实际条件有限熵、nk列并集与向上取整，中止另列；目标64/128/192位重算取整精度，不对应安全等级。scope的epsilon验收范围独立扩至128，wire形状、旧采样/ToBasis guard保持。真实根保存与恢复无重抽，私有诊断错误不回显输入；探针拒绝覆盖与私钥路径别名。来源/实跑/公开n=1种子恢复反例见[本轮记录](../research/2026-10-11-first-suite-root/README.md)。根主状态组件不注册完整HIBE或安全preset；困难维度/资源、全有限父叶、七入口/字节/组合攻击仍待统一准入。

2026-10-11 首套独立有限采样profile：`first_suite/finite_gaussian.py`、`finite_gpv.py`、`finite_randbasis.py`复用既有有限公式，分别明确新width/radius/256维与1TiB最坏随机带支持域，原reference/CHKP/ToBasis上限保持。默认SecureRandom，无native seed；严格bytes/长度和有限消费，错误与ABORT不重试、不回退。对每个输入重算区间/量化/尾/中止、GPV几何/全部路径与整体随机带账本，不继承native null证书。规范/实跑见[有限误差与CSPRNG](../research/2026-10-11-first-suite-finite/README.md)。它是独立研究原语，不注册HIBE/安全preset；秘密基相关诊断不能作为公开字段。根/父生成和整套参数/模型/协议准入仍需完成。

2026-10-11 首套主/父状态补充：独立`first_suite/delegation_state.py`提供DelegationScope、MasterTreeState、ReceiverState，保存完整根/父整数基及既有固定256位子状态；恢复以真实H/G核对完整核格、身份、scope及GS上界，FAILED状态禁止重抽。主树共用锁序和整树最坏wire增长预留，不序列化RNG/回调/锁。恢复先用普通列范数给出的严格GS充分证书，不成立时仍精确GS，接受条件不放宽；解析与构造不重复GS。规范/范围见[主父发钥树](../research/2026-10-11-first-suite-tree/README.md)。它不是生产HIBE或跨副本/机器同步；CLI接入须保留唯一状态、已有接收钥文件复用及锁/pending语义。原有限采样/规约上限保持。

2026-10-11 首套集中闭环的独立组件：`experiments/research/first_suite/` 定义真实两层H/G、固定256位seed原像状态和CHKP共享前导种子wire，规范见[本轮记录](../research/2026-10-11-first-suite-seed/README.md)。H/G绑定调用方完整规范公开配置、根矩阵、身份分量/角色与位置，模余数经有界拒绝产生；Oracle类型不证明配置语义、素性/秩、GenBasis或安全难度。私有scope再绑定receiver/width/profile，恢复重算目标并验维度、方程、范数；FAILED在执行前保留，跨恢复禁止重抽。私有wire≤16MiB、每整数≤256bit、最多8个sender，按256*D*37 B预留后执行；不是旧32位缓存的扩容，不改变有限原语硬上限/证书。

SeedCapsule固定256末端和最大深度3m前导，q为uint64；MSB位序、实际round(q·连续Gaussian alpha)噪声、D+256独立标量和奇数q平局规则固定。Raw KEM错身份可输出随机种子，须接HYBRID AEAD和Wang/BYTEAUTH验收BOTTOM/全字节完整性。当前探针为原生public-test profile/n=1，不注册HIBE后端、不授予参数准入；主/父钥、七入口/CLI/完整组合仍需contract和攻击验收。队友chkp_*和源后端文件未覆盖。

2026-10-11 公开代码比较契约：独立experiments/research/reuse/用qFALL公开API生成gadget/完整整数基，fixture须显式public_test_fixture=true、n<=4/q<=2^40/m_bar<=96/根维度<=192；JSON长度/形状/规范整数及参数/定义关系先核对，Sage再核对完整核格det=q^n。R为明确的两个测试bit之差，不称Gaussian。该Rust接口无生产发钥或HIBE七算法入口。

独立NativePublicGPV仅用于公开测试，最多256维/256位置，精确列基GSO、C1-exec规则和sigma=s/sqrt(2pi)对应；使用Sage整数DGS uniform+online/MPFR192/tau12，必须显式测试seed。向量方程核对、固定最多D+32个RandBasis尝试，失败不重试；Scalar TV、整链TV及最坏随机带为null，原生内部拒绝没有有限次数证书，不继承旧有限采样证明或生产随机API。现有原语硬上限/profile不变。256位置对象是比较批次，未实现固定私有地址/cache/wire，不将它接为已获准后端。

2026-10-11 同组链诊断补充：独立ibme_chain_audit只调用交付的GenBasis/ExtBasis/GPV/RandBasis/固定叶缓存，不新增HIBE后端或H/G。显式OnlineOptions(tail_bits=64,mass_bits=96,precision_bits=160,gaussian_abort_bits=32,max_uniform_trials=48)、epsilon_bits=32的每项误差与随机带单列；它与默认profile是两个预定输入，不能在随机执行失败后切换profile或重抽。维度192、scalar width²<=10^12、整次随机带256 MiB、leaf32等原有上限保持。

同组诊断的独立Sage规约使用delta=0.999/eta=0.501后精确整数size reduction，验证列变换、完整格、GS上界、|mu|<=1/2和delta=0.99的Lovasz条件。严格eta=1/2可能使本机fplll在父基Babai步骤报错；不能把库调用成功视为上述精确条件已成立。该规约无统一资源/失败准入，不替代队友有界算法或改变部署Setup。终层只用扩展父基，不增加第二RandBasis。32个固定bit恢复成功不满足32 B种子的256bit契约，真实噪声相位计数必须独立于无噪声代数控制。详见[同组核验](../research/2026-10-11-same-input-chain/README.md)，现有wire/协议与安全声明保持。

2026-10-11 原文噪声参考实现：独立experiments/research/ibme_noise_budget.py与ibme_rounded_noise.py提供RoundedNoiseParams(q,alpha,tail_bits,mass_bits,precision_bits,max_radius)、build_rounded_noise、sample_signed/sample_mod_q/sample_vector和certificate。CDF积分目标为round(连续Gaussian宽度q*alpha)，按需投影到Zq；signed表示保留负整数，mod-q表示为[0,q)。非法输入/未获资源或精度准入为InvalidParameterError，错误随机源类型/长度为RandomnessError，源异常传播；不进行零/均匀回退、重采样或隐式升精度。

CDF内点取区间下端floor及单调前缀最大值，边缘夹持原尾部而不条件化；尾误差和CDF整数/区间误差单列。每样本读ceil(mass_bits/8)字节并掩去闲置高bit，不存RNG，不复用输出；生产缺省SecureRandom，测试流必须显式注入。向量输入/布尔mod_q先验证再抽样，当前长度上限65536。误差绑定q/alpha和profile，组合器重算原理想预算，按M*(D+L)计入噪声实现耦合，缺失项不默认零；外部证书不是真实性或密码安全证明。完整说明及界限见[本轮报告](../research/2026-10-11-rounded-noise/README.md)，现有HIBE接口/wire与协议未改。

2026-10-11 CHKP噪声与有限正确性接入补充：锁定36页作者版§2.3.1/PDF12的chi_alpha——先抽连续Gaussian宽度alpha，再round(q*x) mod q；不能把标量D_Z,q*alpha直接当同一误差模型。高斯宽度平方与统计方差分开。§5.1/PDF18–19的解码比较模q下到0与floor(q/2)的距离，严格更近0返回0，否则1；奇数q及平局须按此语义验收。

主AI有限检查器在||x||²<=s²D和精确原文噪声的条件下，显式计入(||x||_1+1)/2取整误差，采用安全整数相位半径floor((floor(q/2)-1)/2)，给出alpha及逐bit/寿命并集界。多bit共享s和b前导按原文允许，条件失败概率并集不假设bit独立。真实连续噪声有限实现误差、固定原像坏范数、GPV TV/ABORT、基/资源失败和LWE成本仍单列，不填默认零、不凭alpha数值放行。检查器与根诊断见[联合核验](../research/2026-10-11-joint-parameters/README.md)，现有wire/协议/后端保持。
