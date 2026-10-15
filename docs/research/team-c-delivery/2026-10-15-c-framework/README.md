# C1/C2：LATTE 与认证 IBS 接入统一框架

本批由统筹接收 C 的独立原语，默认登记 `latte`（同一 LATTE-3/COSAC-FIX 实现）、`cert-ml-dsa`、`cert-falcon`，复用公共 SuiteConfig、Hybrid、BYTEAUTH、CLI 和状态事务。
实现提交 **`37a124d`**（`feat(assembly): integrate C primitives and Hybrid preflight`）；首批运行源码固定于 **`9c9fd5aeac2fee68556d980dd0f5e328e530fbdd`**。最终依赖门槛修订为 **`30aebdf9d0b54a48644e1d69febe1019d5d6b802`**（`fix(assembly): allow independently installed signature profiles`），另有下节定向/完整回归。同批 CR 资格提交 **`23546d5`**（`docs(hibe): qualify Zhang delegation types and modulus conditions`）。没有另写组合密码协议，没有新增算法计数或改变已有原语数学/私有分布。

## 接入内容

LATTE 参数钩子按共同接口接收 transport 字符串；共同版本标识 `latte3-cosac-fix-v1` 满足 Hybrid 的小写短标识约束，原语 wire 仍为 `IBME/LATTE3/COSAC-FIX/1`。预检调用与构造相同的 HybridLimits 验证器，提前拒绝无效元数据。LATTE 公共导出及 factory 按需加载，无 Sage 的静态发现不导入执行引擎或构建环。认证 IBS 按所选具体参数检查 native ABI，默认引擎存在不能替代其它参数引擎检查。

跨边界范围为默认 registry、共同 Hybrid 预检、CI 框架测试清单和旧 pending 断言、框架用法/目录/状态/任务同步；没有修改基线协议、BYTEAUTH 或 Hybrid 密码运算。完整变更路径见 [files-changed.txt](files-changed.txt)，源码和证据指纹见 [source-check.json](evidence/source-check.json)。私钥、主状态、原像、随机种子和完整诊断不进 Git。

## 首批固定源码验收（9c9fd5a）

| 批次 | 命令/入口 | 结果与边界 |
|---|---|---|
| C 原语和登记 | 指定 Sage 下 `pytest -q tests/test_c_registration.py tests/test_latte_hibe.py tests/test_cert_*.py` | **543 passed / 0 skipped**，87.09 s；含原生 HIBE、两类认证 IBS、官方向量和选参依赖门槛；[JUnit](evidence/sage.xml) |
| Windows 公共框架 | `python ci/run.py run framework --output test-results/c-framework-new` | **435 passed / 5 skipped**，52.56 s；5 项缺 Sage，状态为 **partial**；[收据](evidence/framework.json) |
| 显式组合矩阵 | `experiments.run_combination_matrix --suite-file ci/c-combinations.json` | **10/10 配置、338 项检查通过**；每配置1次，显式固定 TEST 流；[收据](evidence/combinations.json) |
| 系统随机 CLI | `experiments.research.c_framework_cli_probe`，五个参数档各新建一套 | 每档 **15 个新进程命令 + 1 个零熵恢复命令**，全部通过；每档1根、1发送者、2接收者、64 B身份、32 B消息；重复发钥不产生新key |
| wheel 仓库外安装 | [installed-check.py](evidence/installed-check.py) | 从 `/tmp`、仅安装目录 PYTHONPATH，重放上述5份原状态；**5次解密、0熵、0新根/密钥/签名**，原状态字节不变，**121个记录 provider 全来自安装包**；[收据](evidence/installed.json) |
| 字节来源核对 | `python docs/research/team-c-delivery/2026-10-15-c-framework/evidence/check-source.py` | **209份源码**（含95份显式 native 文件）及1321个 provider 出现记录与固定 Git blob 相符；按实际路径处理旧 experiments 别名；不读取秘密状态 |

计数属于各自批次，不能把 pytest、组合断言、历史独立原语或安装复放相加为新增算法/签名数。组合检查覆盖四种匹配、严格 wire、对象恢复、声明支持时的固定发钥、裸 IBS 负例，以及持有新 OTS 密钥重签后仍在 IBS 验证被拒绝的内部消息篡改。CLI 覆盖三个身份错配和截断/追加/重复字段/位修改；错误均返回 BOTTOM 或明确失败且不发布明文。

首批文档同步后，`python -m pytest -q tests/test_ci_catalog.py` 另有25 passed（0.77 s），并核对5份文档本地链接、任务JSON和上述两份JUnit计数；不计作新密码运行。

零熵恢复禁止 native Setup/Delegate/Extract 和普通 Keypair/Sign；只允许公开元数据、规范格式检查、验签和已有叶的 Decrypt，后者仍有原算法的确定性重加密检查。

`ci/c-combinations.json` 的10配置为 LATTE 配 ML-DSA三档、Falcon两档、Luo模格两种格式、Luo矩阵、Wang–PW、SRGG，即 **一个 HIBE 与六种 IBS 算法配对**，参数/格式不另算算法。不同配对的 HIBE/IBS 假设分别记录；转换实现与现成协议复用不宣称密码学原创。

| CLI IBS 参数 | 总时间/s | 完整密文/B | 公开收据 |
|---|---:|---:|---|
| ML-DSA-44 | 54.735 | 142062 | [ml-dsa-44](evidence/cli-ml-dsa-44.json) |
| ML-DSA-65 | 51.621 | 144513 | [ml-dsa-65](evidence/cli-ml-dsa-65.json) |
| ML-DSA-87 | 51.623 | 147785 | [ml-dsa-87](evidence/cli-ml-dsa-87.json) |
| Falcon padded-512 | 53.164 | 138176 | [falcon-padded-512](evidence/cli-falcon-padded-512.json) |
| Falcon padded-1024 | 53.800 | 140303 | [falcon-padded-1024](evidence/cli-falcon-padded-1024.json) |

每档15条命令共消费65836 B外部熵；内部确定性展开不在该计数内。总时间含解释器启动、状态读取和负例，未建立相同安全目标的基线，不作速度优胜结论。

## 最终选参门槛修订（30aebdf）

审查发现原无参环境检查只探测默认ML-DSA-44/Falcon-1024，导致仅安装所选其它档位时误阻断。现在无参发现检查该族任一有效引擎，具体配置仍单独检查所选档位；可用其它档不能替代缺失的所选档。没有改普通签名、转换、状态或HIBE算法。

- 指定Sage重跑完整C集合：**545 passed / 0 skipped**，83.96 s，含新增2项选择边界；[JUnit](evidence/profile-sage.xml)。原543项被包含，不与本次相加。
- Windows框架重跑：**437 passed / 5 skipped**；[收据](evidence/profile-framework.json)。Windows登记/目录定向35 passed；[日志](evidence/profile-windows.txt)。最初直接调用漏设PYTHONPATH时34 passed/1 failed（子进程找不到ibme），按复跑说明设置后通过，不把环境失败算成功。
- 同一10配置矩阵在修订源码重跑，**10/10、338检查通过**；[最终收据](evidence/profile-combinations.json)，不与首批累计。
- 新wheel在仓库外逐档仅链接**所选的一个native引擎**，5份原CLI状态全部零熵解密；再换成仅含其它档的目录，5个缺失选择均拒绝。没有新根/密钥/签名，原状态字节不变，121个provider来自安装包；[脚本](evidence/profile-install-check.py)与[收据](evidence/profile-installed.json)。这项复用原系统随机实例，不重新声称5套新Setup。

最终wheel为1340115 B，SHA256 `472ebdf3bcc862475e0652828c4d5da039dcd8771b4edde3588e8a44c4ce1adb`；仍复用已核ABI引擎，没有重编译原生算术。[源码核对](evidence/source-check.json)分别绑定首批9c9fd5a收据与最终30aebdf的provider/工作树；两版本只改了登记依赖检查和对应测试，209份来源中的其余内容相同。首批五套系统随机CLI仍准确绑定9c9fd5a，不改写其版本。

## 参数、环境和复跑

LATTE 保留作者 LATTE-3：`N=1024, q=68718428161`、两层、32 B seed、身份编码86 B；三层 Gaussian 标准差、768 bit设置及 COSAC 修订见[原 HIBE 交付](../2026-10-14-latte-hibe/README.md)。组合配置采用 `seed32`、Hybrid、BYTEAUTH、原始身份64 B；认证 IBS 使用已固定的 [ML-DSA三档](../2026-10-14-cert-mldsa/README.md)和[Falcon v1.2两档](../2026-10-14-cert-falcon/README.md)，不是 FN-DSA/FIPS206。其它 IBS 使用组合收据中的独立研究参数。身份哈希和候选理论按各自经典 ROM 条件记录，未证明共同 QROM 结论。

硬件 Core Ultra 9 275HX；原生运行 WSL2 Linux 6.18.33.2、Sage10.9/Python3.13.14，Windows 框架和 wheel 构建 Python3.14。wheel 为1339957 B，SHA256 `46e7e151912929e7ce4475a8289aa6a79af7ff015d073ac2a818db41433a85fc`。安装复放使用此前核过源码 ABI 的本机 native 引擎，**本批没有重新构建原生算术**，不将此项说成全新操作系统上的无缓存构建。纯 Python wheel 内含 native 源码和构建入口。

在仓库根、指定 WSL 环境执行；私有目录选全新名称，不覆盖失败/历史状态：

```sh
export PYTHONPATH="$PWD/src:$PWD"
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_c_registration.py tests/test_latte_hibe.py tests/test_cert_*.py
~/miniconda3/envs/sage/bin/python -m experiments.run_combination_matrix --suite-file ci/c-combinations.json --output test-results/c-framework/new-matrix.json
~/miniconda3/envs/sage/bin/python -m experiments.research.c_framework_cli_probe --private-directory test-results/c-framework/new-cli-44 --profile ml-dsa-44 --source-commit 9c9fd5aeac2fee68556d980dd0f5e328e530fbdd
~/miniconda3/envs/sage/bin/python -m experiments.research.c_framework_cli_probe --private-directory test-results/c-framework/new-cli-44 --restore-only
```

需先按独立原语交付构建并配置 LATTE、ML-DSA、Falcon 引擎；依赖或预检失败不换后端。这10项原生组合是本地执行证据，远端 CI 的 `latte` 与 `cert-*` 原有 source/KAT/metadata 范围仍按各 job 清单解释，未宣称远端已重建并跑过本地全部组合。

## 开发失败与 C 剩余边界

原记录保留：旧 preset 参数类型导致3项失败；Hybrid标识含斜杠/大写造成10项预检失败、0项算法检查；发现路径过早导入执行引擎导致1项失败。三处均由上述接口/标识/按需加载修正，未放宽密码运算条件。另一次 CLI 恢复探针把 native `signature`（规范格式检查）误当成 `sign`（新签名）禁止，以99退出且恢复耗熵0。修正探针允许只读格式检查，仍禁止新签名；最终批次使用新独立目录。该失败发生在缓存读取检查、没有 pending 文件，也没有清理任何 marker；不能将其说成已测试 pending 保留。

四份开发证据见 [preset](evidence/development-preset.txt)、[Hybrid](evidence/development-invalid-hybrid.json)、[导入](evidence/development-eager-import.txt)、[恢复探针](evidence/development-restore-guard.json)。

| C 工作包 | 本轮后的状态 | 仍需完成 |
|---|---|---|
| C1 LATTE | 独立后端、默认登记、组合、CLI与安装已运行 | 匿名性到 Wang 的映射、修订采样总误差/中止和正式参数 |
| C1 Lai | [15项精确资格反例](../2026-10-15-lai-qualification/README.md)已交，未实现 HIBE | 标签单位域、Algorithm7/9类型及两层公开参数澄清后才能实施 |
| C2 两类认证 IBS | 独立五方法/KAT/实物、默认登记、真实 LATTE 配对和安装完成 | 转换强 UF、多用户/固定服务、量子模型和正式组合准入 |
| C3 Xie | [修订方程研究核与公开攻击](../2026-10-15-xie-study/README.md)已交 | 原稿冲突、正式分布/拒绝与模型；不是原稿复现或共同 IBSBackend，不能登记可用组合 |
| CR Zhang | [原文类型/模数资格表](../2026-10-15-zhang-qualification/README.md)已交 | 可委派陷门与短向量、SampleLeft输入/长度、q条件及匿名性澄清；未补造 Derive |

全部研究组合仍为 **`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`**。未授予 NIST 位数、匿名/CCA/QROM 或 Wang 全部安全前提；功能测试不能替代证明。其它研究 IBS 的公开小参数反例继续保留。正式条件、全就绪池公平评测与最终三组选择仍待，本批不宣称 C 的全部安全研究或全项目完成。
