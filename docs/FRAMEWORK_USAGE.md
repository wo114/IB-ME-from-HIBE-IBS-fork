# 分别选择 HIBE 和 IBS

共享协议、独立原语、组合配置分别维护。当前进度见 [PROJECT_STATUS](PROJECT_STATUS.md)，算法来源见 [ALGORITHM_CATALOG](ALGORITHM_CATALOG.md)，公共契约见 [IMPLEMENTATION_SPEC](../IMPLEMENTATION_SPEC.md)。以下命令在仓库根、已有 Python 依赖的环境执行；未安装为 editable package 时，PowerShell 先设置 `$env:PYTHONPATH = 'src'`。

## 1. 先看可选项与兼容性

```text
python -m ibme.cli list-backends
python -m ibme.cli check --hibe abb10 --ibs luo-module --transport hybrid --signature-format compact
python -m ibme.cli matrix
```

三条命令只查看登记信息或计算兼容性，不创建密钥、不运行算法。`--json` 输出机器可读结果；`matrix` 明确标记 `not_executed`。CHKP、LATTE、认证ML-DSA/Falcon已有研究后端登记；缺少Sage或所选参数的native引擎时显示明确依赖失败，Lai等仍显示未实现。选择失败不会回退到 ABB10 或 mock。

| 选择 | 当前实现 | 说明 |
|---|---|---|
| HIBE `abb10` | 教学 ABB10 | 可以 direct，也可由 Hybrid 包装；不具正式安全参数 |
| HIBE `abb-rom` | 真实 ABB-ROM/AP09 研究后端 | `--transport hybrid`；默认 `n1-q26-level-quality-research`，需 Sage/Flatter/精确 Gram 引擎；六种 IBS 共同验收通过，n1可公开攻击；[A本轮交付](research/team-a-delivery/2026-10-15-framework-and-structured/README.md) |
| HIBE `mp12-structured-hg` | 结构化 MP12 / 完整 CHKP H/G 变体 | `--hibe-params n2-full-hg-research --transport hybrid`；无需完整核基或本地转换引擎；n2仍可公开攻击，实际依赖 Sage 及打包的研究工具；[契约](specs/mp12-structured-hg.md) |
| HIBE `mp12-chkp-reference` | 可选 Sage 研究变体 | 显式 `--hibe-params n2-reference`；新根/接收者需配置 native engine，旧状态恢复不需；n2已有公开攻击，见[A安装交付](research/team-a-delivery/2026-10-12-installed-api/README.md) |
| HIBE `chkp` | CHKP RandBasis 研究后端 | Sage运行；`hybrid-research`用于32 B种子；当前n=2可公开攻击，见[统一交付](deliveries/2026-10-12-chkp-luo/README.md) |
| HIBE `latte` | LATTE-3/COSAC-FIX研究后端 | `--hibe-params seed32 --transport hybrid`；需Sage及LATTE引擎，匿名/正式条件未准入；[真实组合/CLI](research/team-c-delivery/2026-10-15-c-framework/README.md) |
| IBS `cert-ml-dsa` | 认证转换研究IBS | `--ibs-params ml-dsa-44`、`ml-dsa-65`或`ml-dsa-87`，reference格式；需对应ML-DSA引擎 |
| IBS `cert-falcon` | 同一转换的Falcon v1.2适配 | `--ibs-params falcon-padded-512`或`falcon-padded-1024`，reference格式；需对应Falcon引擎，不等同FN-DSA |
| IBS `sis` | 教学 SIS IBS | 保留已知公开伪造反例 |
| IBS `luo-matrix` | Luo §3 矩阵研究实现 | 采用显式功能参数；与模格是不同算法实例 |
| IBS `luo-module` | Luo §4 模格研究实现 | reference 默认；compact 为同算法的无损签名编码 |
| HIBE/IBS `mock` | 仅测试 | 必须显式 `--allow-mock`，结果标记 TEST-ONLY |

这里的“兼容”表示该配置能按当前接口、容量和资源规则装配，不能据此宣称密码学安全。全部当前研究组合保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

结构化 H/G 可在指定 WSL Sage 环境中按下例建立新的研究状态。源码运行同时暴露 `src` 和仓库根，或安装完整 wheel；只暴露 `src` 时，缺失的可选研究 provider 会明确不可用，不能影响其它后端的选择。

```sh
export PYTHONPATH="$PWD/src:$PWD"
~/miniconda3/envs/sage/bin/python -m ibme.cli check --hibe mp12-structured-hg --ibs luo-module --transport hybrid --signature-format compact
~/miniconda3/envs/sage/bin/python -m ibme.cli setup --state structured-research-state --hibe mp12-structured-hg --ibs luo-module --transport hybrid --signature-format compact
```

后续 `issue-sender-key`、`issue-receiver-key`、`encrypt`、`decrypt` 与下面的统一示例相同。结构化 H/G 的固定叶恢复和解密耗熵为0；ABB-ROM 每次真实解密仍运行256次新 SamplePre，不能用“恢复不重新发钥”代替这个采样成本。两者都不是正式安全预设。

## 2. 一套完整调用

以下示例选择教学 ABB10 和 Luo 模格 IBS，使用 Hybrid 和 BYTEAUTH，创建一个**新的**状态目录。先准备 `message.bin`。

```text
python -m ibme.cli setup --state selected-state --hibe abb10 --ibs luo-module --transport hybrid --signature-format compact
python -m ibme.cli issue-sender-key Alice --state selected-state
python -m ibme.cli issue-receiver-key Bob --state selected-state
python -m ibme.cli encrypt --state selected-state --sender Alice --receiver Bob --in message.bin --out message.ct
python -m ibme.cli decrypt --state selected-state --sender Alice --receiver Bob --in message.ct --out recovered.bin
```

后续命令从状态恢复已经冻结的选择。需要另一套组合时新建状态目录，例如将 `--ibs luo-module` 换为 `--ibs luo-matrix`，签名格式使用 reference。已有密钥不能通过改 `state.json` 切换参数或算法。

`--transport direct` 让 HIBE 承载全部协议载荷；`hybrid` 让底层 HIBE 加密 32 B 种子，再包装完整载荷。`--protocol byteauth-v1` 为默认，`baseline-v1` 只用于未加 BYTEAUTH 的研究对照；baseline 不承诺任意低位扰动均被拒绝。

## 3. 两边独立选参

`--hibe-params` 和 `--ibs-params` 各接收该后端的预设名或完整参数 JSON 文件；错误字段、错误类型或不属于该后端的参数会被拒绝。参数文件只包含公开配置，不包含私钥。

Python 调用从同一装配入口开始：

```python
from ibme.assembly import make_suite, validate_suite, build_runtime

suite = make_suite(hibe="abb10", ibs="luo-module", transport="hybrid",
                   protocol="byteauth-v1", signature_format="compact")
report = validate_suite(suite)
if not report.ok:
    raise ValueError(report.errors)
runtime = build_runtime(suite)
public, master = runtime.proto.setup(
    runtime.hibe_params, ibs_params=runtime.ibs_params
)
```

配置包括原语标识与版本、全部参数值、传输/协议/签名格式及限制。`SuiteConfig` 提供严格 JSON 读写；参数分属两边，不要求模数、维度或环相同。

### 预检实际检查什么

- 后端是否已实现、版本是否匹配，mock 是否显式允许。
- 参数是否属于所选原语，签名格式是否受支持。
- 两层委派、对象读取器以及 Hybrid 所需的密钥绑定能力。
- 身份长度、完整签名和组帧开销、IBS 输入预算、HIBE 载荷预算。
- Hybrid 的 32 B 种子和两层编码身份；原始身份 64 B 时编码为 86 B。
- 当前组合的状态、配置和对象已编码参数是否一致。旧 ABB10/SIS 的裸对象没有保存所有参数字段，`raw_object_parameter_binding` 会报告部分绑定；v2 CLI 对象封装再绑定完整配置。裸 Python 解码不能追溯旧 wire 中未编码的生成条件。

例如本地默认 Luo 模格参数的 IBS 消息限额为 4096 B，64 B 接收者身份带来 83 B 编码开销，BYTEAUTH 消息封装增加 89 B，所以应用上限为 **3924 B**。参考签名 29455 B、compact 16063 B；这与外部 C64B 候选的 16383 B 不混用。

## 4. 新旧状态如何区分

- 旧 `setup --params education`、`--params luo-module-research` 及旧状态继续使用已有路径。
- 独立选择生成 v2 CLI 状态，绑定完整组合配置、配置摘要、公钥摘要和对象类型；读取使用对应原语的严格解码器。
- 改协议、格式、参数、后端或混入另一状态的密钥会被检查拒绝。摘要用于一致性检查，不能当作外部存储认证或防回滚机制。
- 发钥在现有本地单写者锁内重新加载状态，并先持久化需要保存的主状态再发布密钥，保持 Luo 固定身份服务语义。
- 已有接收密钥验证后复用，避免重新委派丢失叶状态。解密持有同一锁，调用前建立 pending 标记，成功/BOTTOM/异常都先保存完整 v2 接收状态，再输出结果；不确定提交留下标记并阻止解密或重新发钥。
- 加解密输出不能覆盖本状态目录中的密钥、元数据、锁或 pending；也检查现有路径别名和硬链接。该保护不声称抵抗恶意并发文件系统操纵。
- 改配置必须重新 Setup；新路径拒绝覆盖已有状态。仅复制整套旧文件的回滚仍需更强的外部存储机制解决。

## 5. 跑统一组合测试

```text
python experiments/run_combination_matrix.py --list
python experiments/run_combination_matrix.py --output outputs/assembly-matrix.json
python -m pytest tests/test_assembly.py tests/test_cli_selection.py tests/test_combination_matrix.py -q
```

默认执行矩阵覆盖教学 ABB10+Hybrid 与 SIS、Luo 矩阵、Luo 模格两编码的组合，并分别运行 baseline/BYTEAUTH；另有 direct ABB10+SIS 回归。通过 `--case` 选择一个或多个条目，mock 混合组合需明确选对应测试条目。

统一检查包括真实生命周期、三种身份错配、对象恢复、截断/追加/重复/错版本、BYTEAUTH 各认证区、IBS 错消息/错身份、无效签名，以及外层签名有效时内部篡改仍被拒绝。每条收据记录配置、检查数、尺寸、时间、环境和失败阶段，不保存秘密对象。

`matrix` 的静态兼容结果与这里的实际运行结果分别统计。空执行、全阻塞或任一失败不能返回整体验收成功。CHKP 的 Sage 真实生命周期通过专属工具执行，默认 ABB10 矩阵不自动生成昂贵的 CHKP 密钥。固定随机流只用于测试，有限负面样例不证明不可伪造性；教学 SIS 的已知攻击继续由现有安全缺口测试记录。

## CHKP 研究后端

在 WSL 的 `~/miniconda3/envs/sage` 中使用 `--hibe chkp --ibs luo-module --transport hybrid`；两边参数仍分别选择。`--ibs-params` 可指向 C64B 完整参数 JSON（格式遵循上文），不能仅修改旧密钥的参数名字。默认 CHKP `hybrid-research` 是 `seed32` 模式，胶囊3919 B、内层种子32 B、编码身份86 B。`direct-research` 为28 B内容的 `framed32` 模式，现有 IBS/包装载荷容量不足时明确拒绝。

此后端的当前 n=2 参数可公开攻击，禁止用来保密。它用于真实算法、固定缓存和框架接入研究。代码、参数、失败状态和复现入口见 [CHKP 专属规范](specs/chkp-hibe.md)；项目当前完成程度统一见 [PROJECT_STATUS](PROJECT_STATUS.md)。

## LATTE 与认证 IBS 研究调用

在指定WSL Sage环境、按各原语交付构建native引擎后，可使用独立选择。例如新建一套LATTE + Falcon状态：

```sh
export PYTHONPATH="$PWD/src:$PWD"
~/miniconda3/envs/sage/bin/python -m ibme.cli check --hibe latte --hibe-params seed32 --ibs cert-falcon --ibs-params falcon-padded-512 --transport hybrid
~/miniconda3/envs/sage/bin/python -m ibme.cli setup --state latte-falcon-new-state --hibe latte --hibe-params seed32 --ibs cert-falcon --ibs-params falcon-padded-512 --transport hybrid
```

后续发钥/加解密沿用上文命令，从状态恢复冻结选择。换成 `--ibs cert-ml-dsa --ibs-params ml-dsa-44` 可建另一套独立状态。所选参数的引擎在Setup前检查，未安装时不会自动改选参数。两类认证IBS各自机构/用户密钥独立。

明确选定的LATTE矩阵可运行 `python -m experiments.run_combination_matrix --suite-file ci/c-combinations.json --output test-results/c-framework/new.json`。本地10配置338检查、五档系统随机CLI和原状态安装恢复见[C交付](research/team-c-delivery/2026-10-15-c-framework/README.md)；这不表示每个默认池配对都已实跑或安全准入。LATTE匿名性/修订采样、转换强UF/量子模型与正式参数仍待。

## 6. 后续加入新算法

完成独立 HIBE/IBS 的公开接口、对象读取器和真实参数后，在装配目录补登记、能力/容量计算及对应验证器，再将组合加入同一测试驱动。IBS 登记显式提供 `master_public_key(master)` 公共适配回调，框架不要求所有算法把主密钥公钥属性都命名为 `public_key`。登记还需如实描述 `object_parameter_binding`；新后端应保存完整公开参数快照。共同协议不需要为每个新算法复制一份。算法论文条件与正式安全准入另行记录；未交付的原语只阻塞依赖它的组合。
