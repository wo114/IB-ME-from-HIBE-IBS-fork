# M2-B2：Luo 模格 IBS 四算法与独立 Sage 核验

日期：2026-10-09；基点 `1d33fe4`。开工及交付前核对远端，`main` 无新增提交、无待合并 PR。本轮完成 **Luo §4 的真实模格 Setup / Extract / Sign / Verify 研究后端**，包括精确 NTT、舍入/Hint、规范对象、固定身份状态和公开验签。它已能使用选定的 256 次、38 位模数输入实际签验，不再只是参数表或数学辅助函数。

当前声明仍为 `security_claim: none`、`backend_admitted: false`。**默认 CLI 的旧 IBS 尚未替换，剩余两个身份认证漏洞尚未关闭。** 新组件的真实算法核验通过，与安全参数准入、完整组合攻击验收是不同的工作。队友 CHKP、格工具文件未占用。

## 1. 实现及论文对应

依据为 [Luo 等，ICICS 2024 固定稿](../../../papers/2024_ibs_without_trapdoors_luo.pdf) §4，[原始公开稿](https://icics2024.aegean.gr/wp-content/uploads/2024/08/150570198.pdf)。研究接口遵守 `IBSBackend` 和四个对象基类；公开入口为 `ibme.ibs.LuoModuleIBSBackend`、`LuoModuleParams` 及相应对象。

| 原文位置 | 当前实现与验收 |
|---|---|
| §4.1，Algorithms 7–12，PDF 第 12 页 | `luo_module_math.py`：Power2Round、Decompose、HighBits、LowBits、MakeHint、UseHint；保留 q−1 特例及低位正负边界 |
| Algorithm 13，PDF 第 13 页 | `setup`：均匀 A，独立均匀小秘密 s₁、s₂，t=As₁+s₂；全部模 q；不是高斯抽样算法 |
| Algorithm 14，第 13 页 | `key_extract`：新整数掩码 y₁、y₂，w=Ay₁+y₂，c_id=H1(Power2Round(w),id)，z₁=s₁c_id+y₁、z₂=s₂c_id+y₂；接受范数 ≤γ₁−β₁ |
| Algorithm 15，第 14 页 | `sign`：新 y、w=Ay、c=H2(id,HighBits(w),M)、z=z₁c+y；严格检查 z、LowBits(w−z₂c)、w₀c 的三个界，生成逐系数 Hint |
| Algorithm 16，第 14 页 | `verify`：公开计算 v=Az−(w₁·2ᵈ+tH1(w₁,id))c，用 Hint 恢复高位，核对 H2 和严格 z 界；不访问主密钥、用户密钥或缓存 |
| §4.3，第 14–15 页 | 独立 Sage 环复算发钥/签名等式、三个接受界、Hint 恢复与哈希输入；不是调用同一 NTT 再断言成功 |
| §4.4，第 15–16 页 | 引用作者给出的 MLWE/MSIS 安全草图；本参数变体、固定缓存和 SHAKE 实例化的完整适用条件仍需准入核验，不据此声称 QROM 或安全位数 |

Algorithm 15 第 9 行的 `zid` 按同节正文与 Algorithm 16 解释为签名 z，在代码处标明。没有新增 z 非零条件，没有放宽验签或用硬编码成功值。提示位没有另加论文不存在的重量上限。

底层环为 Z[X]/(X²⁵⁶+1) 和 Z_q[X]/(X²⁵⁶+1)。通用乘法采用 twist → 循环 NTT → 逆变换 → untwist；公钥 A 的变换预备一次。稀疏挑战乘法在整数环中保留符号，模运算只在相应公开等式中执行；Python 精确整数避免本轮乘积超过 int64 时的溢出。

## 2. 本轮参数和资源

来源为 [M2-B1 精确搜索与原始结果](../2026-10-09-m2b/joint-screen.json)，不是直接照抄 Table 1 的未给出的精确模数。

| 字段 | 值 |
|---|---:|
| N、k、l | 256、11、10 |
| q、位长 | 274877844481、38 |
| 2N 阶 NTT 根 | 153250464611 |
| η、κ | 1、64 |
| γ₁、β₁=κη | 125440、64 |
| γ₂、β₂=κγ₁ | 31470387200、8028160 |
| γ₃、α=2γ₃ | 15270991360、30541982720 |
| d、(q−1)/α | 28、9 |
| 默认身份/IBS 消息上限 | 64 B / 4096 B |
| 默认 Extract / Sign 尝试上限 | 各 1024 |
| 默认每个均匀整数抽样尝试 / 缓存身份上限 | 128 / 64 |
| 完整对象长度上限 | 16 MiB |

Sage 再次核验 q 为素数、根精确为 512 阶、α 整除 q−1、q>2α。κ=64 和 γ₃ 与作者 Table 1 的第三行不同；不继承作者 200 bit、14680 B 或重复次数的数字。上一轮的系数维数 LWE 估算和挑战熵仍是研究筛查，未补出模格代数攻击或完整 MSIS 证书。

本轮编码实测：公钥 **248000 B**，签名 **29455 B**。身份私钥包含完整公钥，5 B 身份为 313666 B；保存三个身份缓存的主状态为 487913 B。JSON 列出各身份的精确长度。这是参考格式的尺寸，未做位压缩、稀疏位置压缩或种子公钥压缩，不能与论文压缩尺寸直接宣称性能优劣。

## 3. 规范编码与密钥生命周期

`MODULE-REF/1` 的外框：`L24M1 || LP(version) || LP(kind) || LP(field₁) || …`。LP 为 uint32 大端长度前缀。公钥、主状态、身份密钥、签名、身份缓存局部记录使用不同 kind，字段数量固定。

参数按 `luo_module.FIELDS` 的 17 个字段顺序编码为 uint64；模系数为 uint64，[0,q)；秘密与签名 z 为有符号 int64；c 为 −1/0/1 的 int8 且固定 κ 重；h 为单字节 0/1。w₁ 的宽度由参数中的最大 Power2Round 值决定。默认最高端 w₁=1024，需要 11 bit，不能截断为 10 bit。

加载严格拒绝维度、范围、类型、错误上下文、截断、追加、重复和版本错误。主状态加载重算 t=As₁+s₂，用户密钥加载重算 Az₁+z₂=w+tH1(w₁,id)；缓存记录按身份字节排序，不接收重复或倒序。错误熵源与采样预算耗尽有独立异常，不返回默认签名；验签遇到非法数据返回 False。

同一身份复用同一份 z₁/z₂/w，跨序列化恢复后仍相同，签名掩码每次重新抽取。主状态仅缓存密钥，RNG 不进入快照。私有对象打印隐藏秘密；私有序列化仍是明文研究格式，尚无加密存储或并发访问机制。

与原文实现层面的差异明确保留：A 为显式真正均匀矩阵，尚未做 §4.2 的 SHAKE128 种子展开；H1/H2 用分离 SHAKE256 角色域和规范编码，额外固定本 IBS 公钥上下文。其输出均为原文要求的稀疏挑战空间。固定身份缓存采用 [R1 的有状态 oracle 引用解释](../2026-10-08-r1/Luo2024IBS实施规格.md)，未声称该解释已经作者确认或完成独立证明。实验中的哈希和伪随机测试带不能视作随机预言机安全证明。

## 4. 本轮核验结果

Windows Python 3.14.6 / pytest 9.1.1；WSL2 指定 conda Sage 环境 Python 3.13.14 / Sage 10.9；硬件 Intel Core Ultra 9 275HX。全部密码实验为显式固定测试随机流，无生产密钥。没有开展可比性能基准。

- 新增两个测试文件：Windows、指定 WSL 环境均 **68 passed**。覆盖所有小维度三元多项式乘法对照、独立 DFT、真实大 q、有符号运算、边界、公开验签、规范编码、缓存恢复、资源中止及非法输入。
- 当前基础 CI 选择在本机实跑：**464 passed、2 xfailed**。两个 XFAIL 仍是默认教学 IBS 的公开伪造与完整协议冒名目标，不计为安全通过。
- WSL 新组件 + BYTEAUTH + 已知漏洞批次：**96 passed、2 xfailed**，同样保留旧根因。
- [独立 Sage 审计](module-audit.json)：2 次真实参数 Setup、6 个身份密钥、18 个常规签名及 6 个恢复后签名，**24 个签名独立方程核验通过**；36 次身份/消息修改拒绝，6 个恢复密钥一致；18 个常规签名掩码未复用（仅在内存中检查）。身份长度为 3/5/9 B，常规消息长度为 0/32/256 B；另有契约测试覆盖 4096 B IBS 消息边界。
- 独立商环对照 97 对多项式，其中 16 对为实际 N=256 且乘积可超过 int64；小素数完整舍入输入 1222 个、Hint 输入 16122 个、带 β 的引理条件检查 114710 个。另覆盖 q−1 特例与 w₁=1024 进位。
- 固定审计重新运行，完整结果对象一致。JSON 含论文和源文件 SHA256、公开公钥/签名向量、完整参数、重试次数及尺寸；不含私有快照或签名掩码。
- 生成 wheel 后，用隔离 Python 3.12.14 只加载 wheel 和公开向量，诚实验签通过，身份和消息替换拒绝；新进程测试也只取得公开材料。
- 模格 IBS 已通过冻结协议接口接入 **TEST-ONLY MockHIBE**，跑诚实匹配、三种不匹配和篡改。该测试不是完整安全 IBME，未改默认后端。

真实参数的 6 次 Extract 接受尝试分别为 5、14、18、19、17、63；18 次常规 Sign 为 1–31 次。这些是选定随机带的功能样本，不是普遍接受率或算法时延。

攻击对照使用本方案的规范签名类型、全部公开验签条件，没有用“拒绝旧签名类型”当作修复：挑战空间仅 16 的小参数，公开零响应固定点枚举在 6 次猜测后伪造成功；真实输入的 64 次公开挑战猜测均被拒绝。前者证明教学对照仍能触及真实漏洞，后者仅为有限回归，**没有证明任意线性、格基或量子攻击都失败**，也不替代旧攻击在完整新实例上的验收。

## 5. 接下来直接处理的事项

大载荷是现在的具体接线门槛：默认 BYTEAUTH 的旧 ABB10 教学 HIBE 上限为 **489 B**，而本模格 IBS 的 Wang 载荷为 `11 + 4 + 29455 + 4 + 89 + |M| = 29563 + |M| B`。空应用消息已超限。仅扩大旧 HIBE 上限将逐比特放大格密文、密钥和时间，不能用 mock 的成功掩盖容量问题。

下一轮主 AI 实施一个公开版本、可审查的 **大载荷 HIBE 适配**，优先考察有依据的混合加密，让 HIBE 处理短随机材料，再承载完整签名/消息；同时保持 `(rcv,phi)`、匿名性和 Wang 输入语义，继续使用 BYTEAUTH 的完整字节认证及内层 OTS 绑定。对称加密或接收者可知 MAC 本身不能代替发送者认证，也不能自动解决自我伪造。先冻结转换依据和格式，再做真实后端接线、完整攻击对照和明确的研究 CLI。队友仍负责 CHKP 两层原语，不等待其完工才研究本方载荷。

IBS 的 4096 B 消息上限也要单独交接：BYTEAUTH 中送给 IBS 的是 `encode_message(rcv,envelope)`，上限包括接收身份与 89 B 绑定 envelope。接收身份最多 64 B 时，统一应用消息上限为 **3924 B**，不是直接给应用 4096 B；后续适配需在完整协议层明确检查。

安全准入继续做有限且必要的论文/参数对应：精确 MSIS/Hint 见证界与成本、MLWE 的模结构风险、固定身份密钥/哈希实例化的引用条件，以及公开线性求解/LLL 与完整冒名验收。不默认重做整篇安全证明或完整 Lean/QROM；不能靠引用消除已经观察到的反例。

尚未实施：混合载荷与默认 IBS 切换、完整真实 HIBE+模格 IBS 攻击验收、安全参数放行、位/种子压缩、侧信道防护、全系统跑分与 A+B<C 消融。矩阵参考与此模格版本分别有真实实现，但还没有新增一个获准安全的完整组合。

## 6. 复现与修改边界

```text
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_module_math.py tests/test_luo_module_backend.py
python -B -m pytest -p no:cacheprovider -ra --tb=short tests/test_encoding.py tests/test_lattice_core.py tests/test_prepared_hashing.py tests/test_known_security_gaps.py tests/test_luo_matrix_reference.py tests/test_luo_ibs_contract.py tests/test_luo_parameter_screen.py tests/test_luo_joint_parameters.py tests/test_luo_module_math.py tests/test_luo_module_backend.py tests/test_byteauth.py --junitxml=test-results/module-basic.xml
wsl --cd /mnt/d/zcode_projects/ibme bash -lc '~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_luo_module_math.py tests/test_luo_module_backend.py tests/test_known_security_gaps.py tests/test_byteauth.py --junitxml=test-results/module-wsl.xml'
wsl --cd /mnt/d/zcode_projects/ibme bash -lc 'PYTHONPATH=src ~/miniconda3/envs/sage/bin/python -B -m experiments.research.luo_module_audit --output docs/research/2026-10-09-module/module-audit.json'
python -B -m pip wheel . --no-index --no-deps --no-build-isolation --wheel-dir <仓库外输出目录>
```

wheel 的隔离验证仅向新进程提供 wheel 路径和 `module-audit.json` 的公开向量，不依赖研究目录或源码路径。重放时比较审计结果对象；不同机器的 Python/Sage/平台字符串应单独报告，而非冒充同环境逐字节复现。

新增 `src/ibme/ibs/luo_module_math.py`、`luo_module.py`、两个相应测试、`experiments/research/luo_module_audit.py`、本目录报告与 JSON；修改 IBS 公共导出、接口规范、CI 选择、README、进度、漏洞状态和主 AI 工作计划。跨 IBS/审计/规范/CI 的修改用于同时冻结该版本格式及验收；未修改队友 HIBE/采样、旧攻击求解器、协议和 CLI 文件。
