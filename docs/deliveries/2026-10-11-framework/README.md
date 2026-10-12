# 统一原语选择、兼容检查与组合测试交付

执行于 2026-10-11—12。当前状态统一见 [PROJECT_STATUS](../../PROJECT_STATUS.md)，实际使用见 [FRAMEWORK_USAGE](../../FRAMEWORK_USAGE.md)，分工见[三人方案分工](../../workplans/三人方案分工与统一框架交付.md)。本目录保存本轮收据，不发布另一份全项目排序。

## 1. 完成范围

- `src/ibme/assembly/`：HIBE/IBS 独立登记、选择与完整参数配置，版本/能力/身份/签名/载荷/胶囊预检，公开对象读取器，复用既有协议的运行实例。
- `src/ibme/cli.py`：`list-backends/check/matrix`、独立 `--hibe/--ibs` 与两边选参；旧预设保留；v2 状态绑定配置、公钥和对象类型。
- 接收事务与上游合并：同一锁、已有接收钥复用、pending、成功/BOTTOM/异常保存后输出，保护状态文件及现有硬链接，保持保守失败语义。
- `experiments/run_combination_matrix.py`：一个驱动对不同已实现配置执行真实生命周期、身份错配、解析/签名/包装负面输入和恢复；空执行/阻塞/异常不算通过。
- 三位队员各主攻一个新增原语，公共协议/CLI/状态不分叉；A CHKP、B 环 HIBE、C BNN-Falcon 转换 IBS，具体任务与支线门槛已写入完整分工。

没有修改 HIBE/IBS 数学算法、Luo 默认参数、基线身份顺序、Hybrid 的 KDF/AAD 或 BYTEAUTH 算法。新增模块仍需要自己的算法、参数和安全前提验收。

## 2. 固定提交与上传

| 提交 | 任务边界 |
|---|---|
| `2868cf54411188562440820eba266ca3dd278fd9` | 规范整理与 `upstream/main bc22c9c` 合并；保留上游 first_suite、接收状态代码；[PR #10](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/10) |
| `0bf0855464a9902ad95c91ea5bdfb4d12e78f5b9` | `feat(framework): add independent primitive selection and compatibility`：装配、CLI、新测试、真实驱动、使用指南 |
| `f61eb57` | `feat(framework): integrate upstream receiver state transactions`：合并上游，解决 CLI 状态语义冲突并补 v2 测试 |
| `401d1c3c12c37dffa58d04ff9ac6d744e9f8693b` | `docs(workplan): define three-person modular scheme delivery`：完整 A/B/C 分工，按用户要求先上传 |
| `ccf34b6fbb5884bdc71761e7fa829dac035e29f8` | `fix(assembly): validate framed capacity and explicit binding capabilities`：最终装配边界修复 |

框架与分工在[PR #11](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/11)；该 PR 包含 PR #10 的整理历史。两者未自动合入主分支。最终文档/收据提交可通过 `git log --oneline -- docs/deliveries/2026-10-11-framework` 定位，避免在自身文件中写循环依赖的提交哈希。

## 3. 本轮实际验证

| 执行范围 | 结果 | 收据及版本边界 |
|---|---|---|
| 最终装配、CLI 选择、组合驱动、接收状态和锁 | **122 passed / 3 skipped，12.49 s** | [JUnit](framework-final.junit.xml)；3 skip 仅为本次 Windows 环境未运行 Sage 的真实叶缓存场景，不是三个新框架场景失败或空跑 |
| 最终源码真实组合 | **1 配置 / 33 检查通过** | [compact 组合](final-compact-matrix.json)及[执行源码 SHA-256](final-runtime-source-manifest.json)；`ccf34b6`，运行前后源码字节未变 |
| 开发期完整默认矩阵 | **9 配置 / 274 检查通过** | [原始收据](development-matrix.json)。执行早于最终预检/状态合并修正，未冻结逐文件源码；仅作本轮开发证据，不写成最终提交上全九配置复跑 |
| 合并后旧 mock / legacy CLI | **3 passed** | [JUnit](cli-legacy.junit.xml)；旧真实教学 CLI 等另外 22 项已在整合前跑过，不合并计作最终新测试 |
| 既有教学攻击与包装负面对照 | **4 passed / 2 strict xfailed，132.25 s** | [JUnit](known-gaps.junit.xml)；两个 xfail 为保留的教学 SIS/IBME 公开认证反例，不能算安全通过 |
| Luo owner 在 `0bf0855` 的 C64B 独立装配 | **25 检查通过** | [外部收据副本](luo-c64b-owner-receipt.json)，来源 `e5e0b97752f9291ce7621dd830d665baff86aef8`；本对话检查报告、HEAD 与收据，未重跑该批。compact 最大 3924 B 消息实跑，reference 仅预检 |

本轮未重跑全仓测试或 first_suite 历史实验。开发过程中发现并直接修复了：Hybrid 胶囊预算未预检、教学矩阵缺少根基列、发钥前 master 参数校验、20 B Baseline 头预算、可选 cryptography 缺失处理、新 IBS 主密钥公钥属性的隐式依赖、CLI 合并后的事务/输出保护。针对修复的回归均包含在最终测试集合中；测试自身曾缺失参数字段的失败已修正，没有删除失败条件。

最终命令（仓库根，PowerShell）：

```powershell
$env:PYTHONPATH = 'src'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B -m pytest tests/test_assembly.py tests/test_combination_matrix.py tests/test_cli_selection.py tests/test_cli_receiver_state.py tests/test_cli_state_lock.py -q
python -B -m pytest tests/test_known_security_gaps.py -q
python -B experiments/run_combination_matrix.py --case abb10-hybrid-luo-module-compact-byteauth-v1 --output outputs/final-compact-new.json
```

最后一条必须使用尚不存在的输出路径；驱动不覆盖收据。默认九配置可省略 `--case` 执行，但不能把未运行的再执行当成当前结果。源码清单记录实际工作树文件字节，Windows 与 Git LF 规范化的字节哈希口径需区分。

## 4. 参数、输入与声明

运行环境：Intel Core Ultra 7 255HX（20 核/20 逻辑处理器）、Python 3.14.7、Windows 11，已配置依赖；实际平台字符串写在各 JSON 中。组合驱动使用显式公共固定测试流，单配置重复数 1，不据此估计尾概率或性能分位数。常规消息 10 B（含二进制边界），发送身份 `Alice` 5 B、接收身份 `Bob` 3 B，另测试空消息及错身份；精确配置完整保存在各收据的 `suite`。

最终组合为**教学 ABB10 + Hybrid + Luo 模格默认研究参数 + compact + BYTEAUTH**，原始身份限额 64 B，inner 身份各 86 B、seed 32 B，Hybrid 载荷上限 65536 B；IBS 输入上限 4096 B，应用上限 3924 B，默认 compact 签名 16063 B。Luo owner 的外部 C64B 是不同的完整参数快照，compact 16383 B，不替换默认也不新增算法 ID。

九个配置是一个教学 HIBE 与三类 IBS 的包装/编码变体，不是九套不同密码算法。mock 测试只验证框架，不能记入真实目标算法；教学 SIS 的公开伪造仍保留。所有相关组合继续 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。论文 ROM/模型前提、参数估计与功能测试分别报告，未宣布安全等级、CCA/QROM 或新理论证明。

## 5. 对象和剩余限制

- **配置 vs 旧裸 wire**：完整 suite 在 CLI v2 对象封装中绑定；旧 ABB10 对象不存 name/security_parameter，SIS 不存 s0/身份或消息限额/security_parameter，公钥还不存 s。裸解码只能检查已编码字段，不能证明未编码的生成条件；metadata 已显式标注 partial。Luo 对象嵌入完整原语参数，签名格式仍由 suite 绑定。
- **状态**：摘要用于一致性，不提供外部认证或防回滚。锁/pending 只描述同 OS 本地进程行为，不宣称硬断电、多主机/跨 OS 事务；不自动删除失败标记。
- **新 IBS**：登记须提供 `master_public_key(master)` 公共回调，适配器无需把对象属性都命名为 public_key；不通过公共协议读取秘密矩阵。
- **未交付算法**：CHKP、LATTE/Lai、BNN-Falcon 等仍为各原语工作线，注册项不会自动回退为教学或 mock。Luo 第二十三步 helper/专属研究入口仍在外部 PR #9，未混入本次框架代码。
- **性能**：本轮耗时是验证命令的观测时间，既无多次统计也无相同安全目标比较，不是方案快慢排名。

目录仅保存公开参数、检查、尺寸和源码指纹，没有保存生成的主私钥、用户密钥、解封装种子或运行状态。仓库既存 README/旧交付文档修改、旧交接文件删除及未跟踪研究文件均由原所有者保留；本次没有提交或清理它们。
