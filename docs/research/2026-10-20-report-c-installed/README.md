# 报告C组：精确配置安装、空消息恢复与内层签名拒绝

日期：2026-10-20。运行实现固定为 `f8ca35676f8926d96f55b286301037a13bc8e6af`，基于 main `2772199`。本批针对[三代表选择记录](../../deliveries/2026-10-19-report-three-selection/README.md)中 C＝Lai C2＋Sageloli RSIS v3 PARAM-I 的冻结配置，补安装 CLI／wheel、空消息和有效外层下的内层签名负例。

实际结果：一轮新建主根、仓库外安装运行的12条CLI操作和单独的内层签名负例全部符合预期。空消息诚实解密、新进程恢复解密都生成实际存在的空文件；三次完整解密路径都执行真实Lai委派，原持久状态不变。完整密文为 **4,555,404 B**，内层负例为4,555,405 B；整批工具耗时1407.273221秒，约23分27秒，包含准备、格式负例和并发工作，不能当作单次加解密基准。

本批只新增验收工具、对应测试和本目录证据，未改报告正文、全项目状态或导航；这些共享文件由现有负责人接收更新。正式参数、安全准入和算法计数没有随功能验收升级。

## 配置和输入

原[完整C配置](../../deliveries/2026-10-19-report-three-selection/suites/C-lai-c2-sageloli-I.json)的规范 ASCII JSON 摘要为 `9a3c66cfd5073721bf135466197522352010ecbc6a10a6794c710e9b10423c82`。工具在创建私有目录和建根前检查该摘要及公共装配回环，Setup 后再核对 CLI 实际保存的完整 Suite。

| 部件 | 实际选择 |
|---|---|
| HIBE | `lai-ideal-hibe`，C2：n2048、q274877976577、k39、l2、p2、sigma2、sigma_r1；seed32、原语消息上限32 B |
| IBS | `sageloli-rsis`，`Sageloli-RSIS-structured-v3`，PARAM-I：d2048、k65、l132、q=3^65；reference |
| IBS采样与服务 | 身份／签名宽度平方2720281532542／270116709797628319132317；r²49、盐32 B、最多2个已登记身份、签名尝试帽64、tail/mass bits256/320 |
| 包装与限额 | Hybrid＋BYTEAUTH；内部载荷8388608 B、胶囊4194304 B；二者不是应用消息容量 |
| 输入 | 发送者和接收者各64 B公开固定身份；应用消息为空（0 B），受控负例改变为1 B；Hybrid内部身份86 B、HIBE seed32 B |
| 随机与重复 | 1轮独立建根（HIBE和IBS各1个新主根），使用系统CSPRNG；每条CLI命令新解释器；不注入固定种子、不丢弃失败后换根 |
| 安全声明 | `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false` |

`lai-a-256-v1` 是后端版本名，不能据此把本次实际 n2048 写为 n256。Lai 的二进制身份编码、Derive 解释、无 perturbation 的 Klein/GPV 采样、单位 tag 和尝试帽等边界见[Lai契约](../../specs/lai-hibe.md)；Sageloli 的 ROM／QROM 引用、有限精度和 FFT 采样边界见[v3契约](../../specs/sageloli-ring-ibs.md)。本次使用显式 C2 目标研究候选与论文 PARAM-I，没有替换成已知不安全的 debug-small 教学参数，也不将研究候选改称正式安全参数。安全性及HIBE身份匿名性按用户确认的论文引用／工作前提推进；功能测试不替代安全证明。

## 验收方法和判定范围

12条 CLI 操作分别为 Setup、发送者发钥、接收者发钥、重复两类发钥、空消息加密、四类 wire 负例、诚实解密及新进程恢复解密。另有一个独立解释器执行有效外层下的内层签名负例。诚实解密与内层负例最多两个工作进程同时运行；随后恢复解密单独运行。每个工作进程最多900秒，探针总预算1800秒，外层驱动1900秒；超时或失败保留原状态，不重新抽根。

| 检查 | 成功所需的实际观察 |
|---|---|
| 空消息往返 | 两次解密都必须产生实际存在的空文件；缺少输出文件不能算空消息成功 |
| 真实算法路径 | 诚实解密、新进程恢复和内层负例分别执行一次真实Lai Derive，合计3次；不缓存叶密钥、不用mock替代 |
| wire负例 | 截断、追加、重复整个密文和翻转尾字节均拒绝、无输出，而且不触发昂贵Derive |
| 固定身份服务 | 重复发钥、诚实解密、负例及恢复前后，原状态的规范持久文件摘要一致，无pending记录 |
| 安装来源 | CLI在仓库外运行，只从已核对wheel运行副本导入项目模块，关闭用户site目录；实际provider内容绑定冻结Git源码 |
| 恢复语义 | 新解释器恢复已有根、发送者钥和一级接收者钥，动态禁止Setup、Extract、IBS发钥／签名；允许并记录重新随机化的Lai Derive |

**C的恢复需要新的随机数。** 这与LATTE／SRGG批次的恢复条件不同，不能把前者写成零熵恢复，也不能将“未重新建根／发钥”写成“没有重新委派”。对SecureRandom只计数、原读取函数保持调用，不替换随机源或采样器。

内层负例通过公共协议和原语接口构造：用真实发送者钥签名一个绑定新OTS承诺的空消息，先验证该签名有效；保留同一承诺和该签名，将应用消息改为 `b'!'`，直接验签应失败。随后用真实Hybrid HIBE加密此载荷，并产生有效BYTEAUTH外层。实验分别核对规范wire、承诺一致和OTS验签，再进入完整协议解密。只有在实际完成一次Lai委派、协议内的Sageloli验签明确返回 `False`、最终返回BOTTOM时，才计为该负例通过；单独看到BOTTOM或外层格式拒绝不足以通过。

负例读取私有状态的规范封装，通过公共对象解码器和公开绑定校验恢复不透明对象，不读取矩阵／陷门内部字段。它使用原状态的本机私有、逐字节相同副本，诚实与恢复使用原目录；两个目录中的私钥及原始日志均不进Git。

## 公开证据与安装隔离

公开收据记录588个安装文件核对、150个实际导入provider、精确Suite及各阶段结果。150是来源条目数，不是功能测试数。三条实际完整解密路径如下；诚实解密与负例并发，恢复单独执行，**不将三条路径汇总成重复性能样本或用其差值宣称优化收益**。

| 路径 | 整个工作子进程内计时 | Lai Derive | 协议内IBS验签 |
|---|---:|---:|---|
| 诚实空消息解密 | 458.383218 s | 413.153477 s | True |
| 有效外层／被改消息的内层负例 | 561.726325 s，含另一次签名和加密 | 409.343574 s | False |
| 新进程恢复空消息解密 | 431.103089 s | 388.240635 s | True |

表中的工作子进程计时包含CLI状态加载／恢复和协议调用，但不含该子进程计时开始前的模块导入；完整工具批次计时包含进程启动。负例的直接验签还另有一次True和一次False，表内只报告完整协议实际调用的验签结果。

恢复读取项目新熵 **21,889,024 B／334次**，重新执行一次Lai Derive，没有Setup、Extract、IBS发钥或签名调用。状态文件逐字节摘要保持不变，无pending记录；没有缓存二级密钥。熵读取量是接口计数，不是密码随机数的公开内容。

| 文件 | 范围 |
|---|---|
| [installed-cli.json](installed-cli.json) | 12条CLI、单独内层负例、实际参数、阶段观察和动态provider |
| [wheel-build.json](wheel-build.json) | 冻结Git导出、wheel指纹和逐项打包源码指纹 |
| [wheel-install.json](wheel-install.json) | WSL安装运行副本和文件核对数量 |
| [environment.json](environment.json) | 实际软硬件、线程、原生库源码和二进制指纹 |
| [probe-tests.xml](probe-tests.xml) | 删除hostname的12项工具测试原结果 |
| [verify.py](verify.py) | 不读取私有状态、不重跑密码实验的公开记录核验器 |
| [README.md](README.md) | 本批参数、方法、结果、复现条件与未覆盖范围 |

wheel由冻结Git提交的干净导出构建，不使用工作树中的未提交文件，不联网、不修改全局环境。实际wheel SHA-256为 `60413cd2ebcbfce81c595912a6eb414b71346e3a37022c0fa881efa441141e2c`；583个打包源码文件与该提交逐项核对。使用规定WSL Sage，安装到WSL Linux文件系统中以wheel指纹隔离的目录；实际CLI工作目录在仓库外，PYTHONPATH只含安装目录。

实际环境为 Core Ultra 9 275HX、WSL2 Linux6.18.33.2、Sage10.9／Python3.13.14，OMP／OpenBLAS各1线程。使用已有同源Sageloli原生库，未重编，source_id为 `a41fd3e087125317d2bf2c1731e99c5639b27bce1c0b9d8456cd0682bee0ee39`，二进制SHA-256为 `fcfed1b143ebb7f3d46c34597ef6c8b64e2aa6a10a72ce4ab87338bef32d3812`。本批未测完整内存峰值，不能用进程运行时的零散内存快照填补此项。

这是既有Sage／原生依赖下的包安装验收，不代表在无依赖的新机器上从零复现。Sageloli原生库继续执行既有源码／ABI检查，记录实际source_id和二进制指纹，不通过删除检查来运行。wheel、安装副本、密钥、状态、完整密文和原始私有日志为本机产物，不进Git；公开记录中的绝对路径只定位本次环境，移交者须自行重建相应副本。

## 工具验证和只读复核

新工具为[report_c_cli_probe.py](../../../experiments/research/report_c_cli_probe.py)，对应[test_sageloli_report_c_probe.py](../../../tests/test_sageloli_report_c_probe.py)。未修改原语、协议、装配、CLI实现、冻结Suite或旧实验数据。新测试按既有 `tests/test_sageloli_*.py` CI分组收集，无需改CI配置。

在规定WSL Sage、`PYTHONPATH=src:.`、插件自动加载关闭、OMP／OpenBLAS各1线程下执行：

```text
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_sageloli_report_c_probe.py \
  --junitxml=test-results/report-c-installed-2026-10-20/probe-tests.xml
```

12 passed、0 skipped，约3.1秒。测试检查完整C配置经真实CLI参数解析回环、错预算在任何命令或私有目录前拒绝、重复配置字段拒绝、空文件与缺失文件的区别，以及7种不充分的内层拒绝观察必须被拒绝。它们属于工具验收，不是12次密码实验。

无需Sage、wheel或私有状态的只读复核入口：

```text
python -O docs/research/2026-10-20-report-c-installed/verify.py --self-test
```

实际执行通过：核验冻结Git源码、完整Suite、CLI与内层负例记录、真实委派／验签观察、恢复熵、provider和native来源、12项工具测试。6个受控篡改分别改变实际n、外层有效性、协议验签结果、恢复熵、provider指纹和恢复时Setup调用，全部拒绝。这是公开记录间的一致性与来源复核，不读取私有状态、不重跑密码实验。

## 重跑条件

从运行提交的干净Git导出构建wheel；构建环境须已有setuptools／wheel：

```text
python -m pip wheel --no-deps --no-index --no-build-isolation --wheel-dir <wheel输出目录> <干净源码目录>
```

按[运行副本工具](../../../experiments/research/wsl_wheel_runtime.py)用规定WSL Sage安装并逐文件核对wheel。用冻结源码中的 `experiments.research.candidates.sageloli.ring.native.build` 显式构建本机原生库，设置 `IBME_SAGELOLI_RING_NATIVE`；已有二进制也必须通过源码指纹检查。复制公开C Suite至仓库外工作目录，执行：

```text
PYTHONPATH=<已核对的安装目录> PYTHONNOUSERSITE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python -m experiments.research.report_c_cli_probe \
  --suite-file <C的公开Suite副本.json> --private-directory <全新私有目录> \
  --source-commit f8ca35676f8926d96f55b286301037a13bc8e6af --timeout-seconds 900
```

`--suite-file`为验收工具参数，不是新增的 `ibme.cli` 参数。私有目录必须不存在；失败保留现场，不自动重试或重抽根。重新构建wheel的ZIP指纹可能不同，应记录实际指纹并核对源码，而不是伪造原指纹。

## 未由本批覆盖

本批不补C的最大应用消息长度／系统边界、多根重复性能、完整内存测量、Web预设或公平性能排名；也不把一次批次耗时写成Encrypt／Decrypt基准。既有32 B跨组合运行与错误身份记录继续引用[原批收据](../2026-10-19-lai-c2-combinations/README.md)，不并入本次空消息根数或重跑计数。

报告正文、三代表选择表、导航和全项目状态交由当前负责人接收更新，本批仅提供独立证据目录。算法计数、安全元数据和三条暂缓路线保持原约定。
