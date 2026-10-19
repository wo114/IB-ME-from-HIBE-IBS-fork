# SRGG 论文参数接入、LATTE 完整组合与本机基准

日期：2026-10-19。[队长仓库PR58](https://github.com/youzi258/IB-ME-from-HIBE-IBS/pull/58)已提交，尚未合并。运行实现固定于 `7573014d53b5367698e161abf354b643770cf20e`，基于队长 main `b92967b`。本批由当前线程独立完成，没有调用子智能体；旧作品报告、PPT及另一条研究报告分支均未修改。

本批将已有 Table 4 原实现接入公共框架，新增独立选择器 **`srgg2025-paper`**，支持 PARAM-I／II／III 与 reference／compact 签名。六种真实 LATTE＋Hybrid＋BYTEAUTH 组合均通过，每种34项，共 **204项检查**。隔离安装包在仓库外完成15步独立 CLI 和另一次新进程恢复。

完整重复基准采用 PARAM-I，两种格式分别建立3套独立系统随机状态、执行9对热加解密和9次新进程恢复后解密。它们是同一论文算法／参数的编码选择，不新增 IBS 算法或困难假设计数。

## 1. 本次修改与参数

[公共装配契约](../../specs/srgg-paper-assembly.md)、[描述符](../../../src/ibme/ibs/srgg/paper_registration.py)、[适配器](../../../src/ibme/ibs/srgg/paper.py)。公共注册表和算法目录仅增加显式入口及同路线映射，未改动协议、LATTE、原 SRGG 采样器、参数解释、H1/H2、固定身份缓存或既有 FixedIssuer。

三档固定来源为[论文 PDF](../../../papers/2025_efficient_ibs_jia.pdf) Table 4及§5.1（SHA-256见契约）。共同 n512、p16383、b31、digits2、Q15744063，rank依次2／3／4。本批完整系统只使用 `table-standard-deviation` 和原实现 factor1。原语所用完整数值及来源仍在原始参数记录中；Suite保存明确档位、解释和版本，未知字段或不完整配置被拒绝。

公／私钥沿用原规范 JSON 与公开上下文。compact仅编码签名，恢复仍调用原对象读取器；补上适配边界的原签名范数检查，不把 codec 单独解析成功当作合法签名。格式不能自动互换。

| 论文档位 | reference签名保守上界/B | compact保守上界/B | reference应用容量/B | compact应用容量/B |
|---|---:|---:|---:|---:|
| PARAM-I | 47282 | 15704 | 65364 | 65364 |
| PARAM-II | 67770 | 22616 | 63194 | 65364 |
| PARAM-III | 88258 | 30616 | 42706 | 65364 |

上表及[预检收据](preflight.json)统一使用[六份显式 suite](suites.json)中的128 KiB Hybrid载荷预算、外部身份64 B和内部身份86 B。IBS签名输入上限65536 B，BYTEAUTH签名编码开销172 B，故应用上限可能先受IBS限制；容量是所有合法签名的保守保证，不是本轮测试达到最大长度的结果。底层LATTE仅封装32 B种子。CLI验收的PARAM-I compact沿用默认64 KiB预算，与上述128 KiB实验预算分别记录。

旧`srgg2025`仍是独立的degree8/factor2调试与公开伪造负控，本批不混用它的参数、密钥、配对或安全结论。登记算法总数仍为19条候选路线，研究IBS算法完成数仍为10/11，已默认登记的算法仍为6种；新增的是SRGG已有路线的论文参数入口。

## 2. 真实完整组合与安装恢复

每份功能收据只含公开配置、检查名、状态、尺寸和耗时，不含私钥或密文内容：

| 档位 | reference | compact |
|---|---|---|
| PARAM-I | [34/34](functional-param-i-reference.json) | [34/34](functional-param-i-compact.json) |
| PARAM-II | [34/34](functional-param-ii-reference.json) | [34/34](functional-param-ii-compact.json) |
| PARAM-III | [34/34](functional-param-iii-reference.json) | [34/34](functional-param-iii-compact.json) |

复用原`run_combination_matrix`和公开方法，实际覆盖诚实加解密、三种身份错配、空消息、公钥／主状态／发送者／接收者恢复、同址发钥复用、截断／追加／重复／版本错误、BYTEAUTH字段与一次性公钥修改、IBS错误消息／身份／签名。具有有效外层OTS的旧签名重绑定攻击也实际到达IBS并被拒绝。没有使用HIBE或IBS替身。功能批使用固定公开测试随机源，不能计作CSPRNG性能基准；表中功能批耗时亦不用于格式速度比较。

[安装收据](wheel-install.json)：WSL构建wheel，SHA-256 `d0fc056c3ba270ad155c65254ab489eee87e5455edf168c33379b74e10af9ce0`，隔离安装至Linux `/tmp`，逐一校验555个打包文件，全局环境未修改。该缓存和wheel在Git忽略目录／本机临时目录中，接收者需自行重建安装。

[独立CLI收据](installed-cli.json)：从`/tmp`启动已安装的[验收驱动](../../../experiments/research/srgg_paper_cli_probe.py)，PYTHONPATH只包含安装目录及独立依赖目录，未暴露仓库代码根。15个命令各用新解释器，真实完成Setup、发送者及两个接收者发钥、重复发钥不改状态、加解密、三类身份错配和四种密文修改拒绝。另起第16个进程恢复解密，项目随机源读取0、native不生成新密钥、原状态不变。154条动态provider记录均来自安装目录，并与固定Git源码核对。

## 3. 完整系统重复基准

[实际环境](environment.json)：Intel Core i9-14900HX，WSL2 Linux6.6.87.2，Sage10.7／Python3.12.13，OMP4／OpenBLAS1。从Windows挂载源码目录运行；LATTE由冻结源码重新构建，二进制、ABI和source ID见[构建收据](native-build.json)，每次调用仍执行原校验。环境与二进制指纹是独立只读采集，不能写成worker动态捕获字段。此环境不同于历史Core Ultra／Sage10.9等结果，不做跨批次加速排名。

外部发送／接收身份各64 B，应用消息32 B。两种格式分别3个系统CSPRNG根，每根首次完整加解密后3对热操作，再起新进程恢复原状态并解密3次。无固定种子、外层抽根重试或测量中的引擎重编译，两条命令分别限制300秒。原runner守卫恢复阶段的项目熵、IBS Setup／Extract／Sign及native生成操作。私有对象和原日志留在Git忽略目录，不进入公开材料。

计时经过公共完整协议，包含参数／密钥验证、Hybrid／BYTEAUTH包装、wire编解码、native启动；首次解密包括LATTE真实叶生成。冷态指新Python进程，保留OS页缓存及已构建引擎；缓存热态与恢复单列。

公开原始收据：[reference](benchmark-param-i-reference.json)、[compact](benchmark-param-i-compact.json)。完整阶段、样本、RSS及provider摘要保存在原始记录中。

| 阶段 | 每格式样本数 | reference中位秒 | compact中位秒 |
|---|---:|---:|---:|
| 导入并装配 | 6 | 2.190980 | 2.220555 |
| Setup | 3 | 1.411299 | 1.359027 |
| 发送者发钥 | 3 | 21.892863 | 21.884570 |
| 接收者发钥／父委派 | 3 | 0.450776 | 0.442342 |
| 首次完整加密 | 3 | 7.907180 | 8.974935 |
| 首次解密含叶生成 | 3 | 0.602260 | 0.385420 |
| 持久化 | 3 | 0.050600 | 0.057793 |
| 热完整加密 | 9 | 7.706882 | 7.594920 |
| 热完整解密 | 9 | 0.191727 | 0.201444 |
| 新进程恢复对象 | 3 | 0.712577 | 0.727519 |
| 恢复后完整解密 | 9 | 0.204904 | 0.218283 |

12份reference完整密文为171097—171231 B，12份compact为149191—149291 B。两格式的进程树采样最大RSS分别506896384 B（483.41 MiB）、506789888 B（483.31 MiB）。每格式仅3个独立根，9个热样本共享这些根；两组也没有配对固定相同签名随机性，不能把中位数差异写成编码带来的签名加速。10ms RSS采样可能漏峰且进程树相加可能重复计算共享页，不是精确物理内存需求。全部恢复项目熵读取0且原状态未改写。

## 4. 回归与证据核对

[test-record.json](test-record.json)记录各组真实执行范围：规定Sage环境下158项原后端／codec／新适配器测试、16项公共描述符测试、151项公共框架／目录／CLI／BYTEAUTH／绑定测试均通过，共325个不同测试条目；[158项JUnit](adapter-regression.xml)保留。其后为同10个代数用例补上跨上下文拒绝断言并复验通过，不将它们再计为10个新测试。Windows另有64通过／2个需Sage旧用例跳过，不能算作真实算术验收。

环境问题已记录并解决：首次未激活conda导致Singular缺失，Windows临时目录／硬链接限制，以及Sage宿主上的纯Python发现测试需明确模拟无Sage环境。可选candidate缺失时曾暴露缓存登记边界问题，已先复现失败，再修复为明确不可用且其它后端仍可发现；没有修改无关MP12算法。

[verification.json](verification.json)通过：[verify.py](verify.py)只读公开收据和固定Git对象，核对六份配置／功能、两份重复基准、全部provider内容（只容许LF/CRLF等价）、阶段次数／中位数、恢复零熵、安装来源和安全字段，并用故意改坏的provider摘要作负例。1824条基准provider记录及154条安装CLI记录与固定Git内容一致，共145个不同provider文件。功能runner本身不捕获动态provider，故只独立核对其源码没有改变，不将此误写为功能批动态捕获。

```text
python docs/research/2026-10-19-srgg-paper-latte/verify.py
git diff --check
```

复现从WSL仓库根激活规定的`~/miniconda3/envs/sage`。首次构建并明确设置native路径：

```bash
source ~/miniconda3/etc/profile.d/conda.sh
conda activate sage
export PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1
python -m ibme.hibe.latte.native.build --prefix test-results/srgg-reproduce-native
export IBME_LATTE3_EXECUTABLE="$PWD/test-results/srgg-reproduce-native/bin/ibme-latte3"

python -m experiments.run_combination_matrix --suite-file docs/research/2026-10-19-srgg-paper-latte/suites.json --suite-name latte-srgg-paper-param-i-compact --output test-results/srgg-reproduce-functional.json

timeout --signal=TERM --kill-after=10s 300s python -m experiments.research.full_system_benchmark \
  --suite-file docs/research/2026-10-19-srgg-paper-latte/suites.json \
  --suite-name latte-srgg-paper-param-i-compact \
  --private-directory test-results/srgg-reproduce-benchmark \
  --repetitions 3 --warm-repetitions 3 --identity-bytes 64 --message-bytes 32 \
  --security-group srgg-paper-factor1-table-stddev-research \
  --source-commit 7573014d53b5367698e161abf354b643770cf20e
```

复现须使用新的私有目录，失败保留且不覆盖本批状态。依赖`cryptography`需安装项目hybrid extra。PARAM-II／III的重复CSPRNG完整基准、另一Gaussian解释的完整HIBE配对及Web预设不属于本批已完成项，不能从六组功能测试推得。

SHAKE沿用现有随机预言机接口，论文的QROM结论继续引用原文；不以功能测试推出安全证明。三档是原论文数值的研究实现，未作新的困难参数扫描或修改采样策略。项目安全性／HIBE匿名性沿用用户确认的论文工作前提，`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、NIST类别空值保持不变。
