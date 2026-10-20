# 报告B组：128 KiB冻结配置的安装CLI与恢复验收

日期：2026-10-20。运行实现固定为`f24a333c74e923226be6dbbc876937668ecb3f59`，基于main `2772199`。本批补齐[三代表选择记录](../../deliveries/2026-10-19-report-three-selection/README.md)中B组的**精确128 KiB Suite安装CLI／wheel验收**，不再沿用不同摘要的64 KiB旧安装记录。

实际结果：一个新系统CSPRNG根，仓库外安装运行15步CLI，加另一个新进程恢复解密，全部符合预期。完整密文149,279 B，完整公钥47,353 B；恢复未读取项目新熵，未生成新根、密钥或签名，原状态文件不变。整批工具耗时约51.39秒，包含全部进程启动与负例，**不是Encrypt／Decrypt性能样本**。

本次只修改验收工具、对应测试及本目录证据。导航、PROJECT_STATUS、报告正文、冻结Suite、算法和参数未改，留给现有负责人接收更新；三条暂缓路线不启动。

## 配置与执行范围

使用原[完整B配置](../../deliveries/2026-10-19-report-three-selection/suites/B-latte-srgg-I-compact.json)，规范ASCII JSON摘要为`37a0d413d5daed2c407c03b4b4f1a1fe4b6454e786e9cea3dfe8676a60ce9c97`。

| 部件 | 实际选择 |
|---|---|
| HIBE | LATTE-3，N1024、q68718428161、seed32；最多2个接收者、各2个子身份；原生超时60秒 |
| IBS | SRGG论文PARAM-I，n512、rank2、p16383、base31、digits2、Q15744063、gamma42086491.7；factor1／table-standard-deviation，compact |
| 包装 | Hybrid＋BYTEAUTH，载荷131072 B、胶囊4194304 B；这两个值不表示应用消息容量 |
| 输入 | 外部身份各64 B，内层身份86 B，实际应用消息32 B；公开固定测试身份／消息，不向密码随机源注入种子 |
| 随机性与重复 | 1个新的系统CSPRNG根，无外层重试、无失败样本丢弃；每条CLI命令新建解释器 |
| 声明 | `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；ROM／QROM引用及实现条件沿用[专属契约](../../specs/srgg-paper-assembly.md) |

选定参数、采样、身份服务、wire及安全字段均沿用原配置。沿用用户确认的论文安全性／HIBE匿名工作前提，不新增基础证明或参数估计；功能验收不能替代安全证明。

## 实际完成的操作

| 类别 | 实际观察 |
|---|---|
| Setup与发钥 | 真实LATTE Setup、SRGG发送者发钥、两个接收者父委派；重复签发同身份不改状态、不读项目新熵 |
| 完整往返 | 一次真实完整加密与正确解密；诚实解密实际执行一次LATTE叶提取，恢复出原32 B消息 |
| 身份错配 | 错发送者、错接收者、双方错误，均返回拒绝且不生成输出文件 |
| wire修改 | 截断、追加、重复整个密文、翻转尾字节，均由CLI拒绝且无输出；不将其称为有效外层下的内层签名伪造实验 |
| 新进程恢复 | 第16个解释器恢复已有状态并解密原密文；项目熵读取为0，native只调用meta／decrypt，原状态不变 |

原始公开收据见[installed-cli.json](installed-cli.json)。15步与恢复分别记录，不将16个进程称为16个独立随机根。B组已有同128 KiB配置的34项功能矩阵与三根重复基准继续引用[原批材料](../2026-10-19-srgg-paper-latte/README.md)，不加算成本批的新实验。

## 安装与来源核验

从固定Git提交导出干净源码，用已有Windows构建环境生成纯Python wheel，不联网、不修改全局环境。wheel SHA-256为`8278aea61875a9b51b2698b028ce9f7c06b6ffc69046f0c95c3e65a0cb849223`。

- [构建记录](wheel-build.json)：582个打包源码文件与固定Git原始字节逐项一致，包含原生C源码及候选实现。
- [安装记录](wheel-install.json)：在WSL Linux文件系统的独立目录安装，587个wheel文件全部核对；CLI工作目录在仓库外，PYTHONPATH只含安装目录，关闭用户site目录。
- [执行收据](installed-cli.json)：165个实际导入的项目provider全部来自该安装目录，内容与同一wheel／固定Git一致。此数量是来源条目数，不是功能测试数。
- [环境与native指纹](environment.json)：Core Ultra 9 275HX、WSL2 Linux6.18.33.2、Sage10.9／Python3.13.14，OMP4／OpenBLAS1。使用已有同源LATTE引擎，ABI和源码指纹检查保持执行，未重编引擎或修改其校验。

这是既有Sage／原生依赖下的隔离包安装验收，未声称在无依赖的新机器上从零复现。wheel、安装副本与私有状态是本机产物，不进Git；收据里的实际路径用于定位本次环境，移交时需按命令重建，不要求另一台机器有相同绝对路径。私钥、完整密文、随机带和原始私有日志未复制到本目录。

## 工具改动与验证

[srgg_paper_cli_probe.py](../../../experiments/research/srgg_paper_cli_probe.py)新增可选`--suite-file`，只接受本探针支持的LATTE／SRGG PARAM-I compact完整版本。发钥前核对安装CLI实际保存的Suite及摘要；不匹配时停止并保留失败状态。无此参数的历史调用仍使用64 KiB默认预算，不覆盖旧收据。关键后置条件改为显式检查，不依赖可被`-O`移除的assert。

在规定WSL Sage环境、`PYTHONPATH=src:.`、插件自动加载关闭、OMP／OpenBLAS各1线程执行：

```text
~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_cli_probe.py \
  --junitxml=test-results/srgg-b-installed-2026-10-20/probe-tests.xml
```

**9 passed、0 skipped，3.54秒**，见[去hostname的JUnit](probe-tests.xml)。包括真实CLI参数解析的完整配置回环、旧预算保持、重复JSON字段拒绝、5类不适配配置在创建私有目录前拒绝，以及实际Setup写回错预算时停止发钥。属于验收工具测试，不是9次密码实验；现有`tests/test_srgg_*.py` CI分组会收集该文件。

无需Sage、wheel或私有状态，运行以下只读核验：

```text
python -O docs/research/2026-10-20-report-b-installed/verify.py --self-test
```

核验冻结Git、582份源码、165个动态provider、精确Suite、15个CLI结果、新进程恢复、native元数据及9项测试。5个篡改负例分别改预算、provider哈希、恢复熵、恢复时native提取调用和拒绝退出码，全部必须拒绝。此命令仅读取公开记录，不重跑密码实验。

## 实跑复现方法

先在具有setuptools／wheel的构建环境从固定提交的干净Git导出生成wheel，例如：

```text
python -m pip wheel --no-deps --no-index --no-build-isolation --wheel-dir <wheel输出目录> <干净源码目录>
```

按[运行副本工具](../../../experiments/research/wsl_wheel_runtime.py)用规定WSL Sage安装并核对该wheel，复制B的公开Suite至运行目录，在仓库外启动：

```text
PYTHONPATH=<已核对的安装目录> PYTHONNOUSERSITE=1 OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python -m experiments.research.srgg_paper_cli_probe \
  --suite-file <B的公开Suite副本.json> --private-directory <全新私有目录> \
  --source-commit f24a333c74e923226be6dbbc876937668ecb3f59
```

`--suite-file`属于本验收工具，不是新增的`ibme.cli`参数。私有目录必须不存在；每个CLI命令300秒上限，本次整批额外设置600秒上限。失败保留现场、不重新抽根。设置`IBME_LATTE3_EXECUTABLE`指向按冻结来源构建并通过元数据检查的本机引擎；参考[LATTE契约](../../specs/latte-hibe.md)。重新构建的wheel ZIP指纹可能变化，应重新记录实际指纹，并核对逐项源码。

## 仍未覆盖

本次不补B的最大应用消息长度、系统性边界扫描、多根安装重复、Web预设或同条件性能排名；不补C组安装和有效外层下的内层负例，也不验证所有候选参数。报告可将“B精确128 KiB配置的安装CLI／新进程恢复”记为本批新增完成项，其余欠项保持分别记录。报告正文、全项目状态与整理入口交由各自负责人更新。
