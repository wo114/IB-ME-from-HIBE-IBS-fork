# 演示环境实跑与现有 Web demo 审查

2026-10-18 按用户要求先验收最终演示环境，再检查另一位 AI 的 demo。演示源提交 `fa9a089` 已在自己的分支接到远端 `c7ecccc`，未修改队友主工作目录或其未提交文件。最终运行版本为 `f2f232d61cc2fe8aed96396856c19e3101e04b4a`。

**结论：现有 demo 可以继续作为三组完整系统的功能展示入口。** 它实际调用公共装配层、真实 LATTE 和对应 IBS，没有 mock 回退。已修正 Falcon 参数错标、拒绝结果误分类及派生解释错误，并补充公开实测导出和可移交启动脚本。CLI 持久状态恢复已经实跑；网页仍是进程内临时会话，服务重启后不保留密钥。

## 环境验收

- 指定 WSL conda `~/miniconda3/envs/sage`，Sage 10.9 / Python 3.13.14，Core Ultra 9 275HX，OMP4 / OpenBLAS1，详见[环境](evidence/environment.json)。
- 在新的独立缓存目录从随包固定源码重新构建 [LATTE](evidence/latte-build.json)、[ML-DSA](evidence/mldsa-build.json)、[Falcon](evidence/falcon-build.json)。没有下载替代实现或覆盖旧引擎；构建记录含源码 ABI、编译器与二进制 SHA256。
- 主组合仍是 LATTE-3/COSAC-FIX `seed32` + BNN/ML-DSA-44 + Hybrid + BYTEAUTH，完整 suite 与[已接收参数卡](../2026-10-18-main-showcase-cards/README.md)一致。
- 用全新系统随机状态执行 **15 个 CLI 步骤**：Setup、发送/两接收者发钥、同身份重发复用、完整加解密、三种错配、截断、追加、重复及字节修改。全部退出码符合预期，拒绝时不发布明文输出。
- 另起进程恢复解密：禁止新根、委派、提取、普通签名与公共随机源读取，**恢复成功、公共熵 0 B、原状态字节不变、无 pending 遗留**。本批 64 B 身份、32 B 消息、完整密文 142084 B；一次验收约 61.00 秒，不作为新性能排名。

原始公开结果为 [CLI 收据](evidence/cli-mldsa44-raw.json)。首次命令的 `--source-commit` 完整哈希误填，**原收据未改写**。已把 131 个加载源文件分别与实际 CLI 提交 `33bb04dabb9ae41c6a37464e159114387d1aebb9` 及最终 `f2f232d` 的 Git blob 对齐；[来源清单](evidence/provenance.json)保留错误标签、正确版本和校核结果。没有为纠正标签重发密钥或替换观测值。

## Web demo 的审查与修复

| 问题 | 影响 | 最终处理 |
|---|---|---|
| Falcon 按钮标 512，但没有显式传参数，继承 registry 的 1024 默认档 | 界面名称与实际签名/尺寸不对应 | 显式选择 `falcon-padded-512`；ML-DSA/Luo/HIBE 预设也显式绑定。三组完整 suite 与参数卡逐字段回归比较；[修复前公开收据](evidence/falcon-profile-mismatch-before-fix.json)保留实际 1024 档 |
| 篡改/截断路径把任意 IBMEError 转成 BOTTOM | 后端/资源异常可能被当作成功拒绝 | 只有公共协议实际返回 BOTTOM 才报告拒绝；异常显示“解密未完成”，注入故障测试覆盖此区别 |
| 错误发送者说明称接收密钥只能派生 Alice | 误述两层 HIBE 委派语义 | 改为实际尝试 `(Bob, Carol)`，与密文 `(Bob, Alice)` 不匹配 |
| 结果没有单独标出是否符合该场景预期 | 错配场景意外恢复也可能显示普通成功 | 增加 `expectation_met` 与异常结果提示，保留真实结果 |
| 缺少本次公开结果导出、启动命令写死用户名 | 不便留证和移交 | 增加 JSON 下载，记录完整参数、每次观测、尺寸及计时；不导出密钥、身份文本或消息正文。新增[WSL 启动脚本](../../../experiments/run_web_demo.sh)，默认只绑定回环地址 |

使用浏览器真实点击三个预设，每组重新初始化一个系统随机会话、加密同一条 38 B 中文/Unicode 测试消息，再执行正确双方、错误发送者、错误接收者、双方都错、翻转一位、截断一字节。**三个组合共 18 项核心场景均符合预期**，每份 JSON 均由页面下载并核对参数；浏览器没有 warning/error 级脚本日志。初始 smoke 会话与修复前 Falcon 观测不计入最终三组。

| 最终 Web 配置 | 完整密文 B | 单次 Encrypt / 首次 Decrypt，秒 | 公开导出 |
|---|---:|---:|---|
| LATTE + ML-DSA-44 | 142117 | 0.274884 / 0.427258 | [JSON](evidence/ui-mldsa44.json) |
| LATTE + Falcon-512 | 138201 | 0.246324 / 0.412056 | [JSON](evidence/ui-falcon512.json) |
| LATTE + Luo research/compact | 151924 | 0.400762 / 0.427148 | [JSON](evidence/ui-luo-compact.json) |

本表只记录一次交互观察，身份为 Alice/Bob/Carol，未清 OS 缓存，不代替既有 3 套 cold / 9 次 warm 基准，也不做跨安全目标速度排名。解密计时为协议调用，不含网页通信；导出的密钥大小为初始化/发钥时快照，未重测后续缓存增长。精确计时以导出值为准。主组合[恢复成功截图](evidence/primary-success.jpg)、[拒绝截图](evidence/primary-rejection.jpg)及[浏览器逐项记录](evidence/browser-checks.json)均为实际页面；早期主组合[导出](evidence/ui-mldsa44-before-preset-pin.json)单独保留。

已验证刷新页面重连同一个服务会话且 suite/ciphertext 摘要不变；也实际重启过服务，确认临时会话丢失。**前者不是进程重启恢复；本批的持久恢复证据来自 CLI。** 不把导出参数/测量 JSON 当作密钥备份。

## 复现与检查

在仓库实际 WSL 路径执行：

```sh
bash experiments/run_web_demo.sh --build-native --port 8765
```

Windows 浏览器访问 `http://127.0.0.1:8765`；已有脚本专属引擎时省略 `--build-native`。直接使用旧缓存的调用和范围见 [Web README](../../../src/ibme/webui/README.md)。本次保留的验收服务使用 8766 端口和独立验收缓存，不改变用户默认引擎或 WSL 配置。

CLI 验收复用已有工具，输出目录须是新的，native 环境由启动脚本同样的三个变量配置：

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
timeout --signal=TERM --kill-after=10s 300s \
~/miniconda3/envs/sage/bin/python -m experiments.research.c_framework_cli_probe \
  --private-directory test-results/demo-acceptance-new --profile ml-dsa-44 \
  --source-commit <实际提交>
PYTHONPATH=src:. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_webui.py tests/test_ci_catalog.py
```

最终定向测试 **38 passed / 0 skipped**，[JUnit](evidence/webui-catalog.xml)归档；首次修复时 35 项通过，参数卡回归增加后为 38 项。另有 Bash 语法、Node inline JS 语法与 `git diff --check` 检查通过；启动脚本也在另一新前缀实际执行 `--build-native --help`，三个引擎构建并进入服务参数解析，退出码 0。曾尝试用 Windows 捆绑 Python 跑 pytest，但该解释器未安装 pytest、没有执行测试；没有据此记为通过，实际测试均在规定 WSL Sage 环境完成。

标准 Python 可只读核验公开收据与源码：

```text
python docs/deliveries/2026-10-18-demo-acceptance/evidence/verify.py
```

校验器不打开私有状态、不生成密钥、不执行 native 算法，本次 **369 项检查通过**。私钥及消息/密文文件留在 ignored `test-results/`，未纳入提交。代码改动仅为 `server.py`、静态 HTML、Web README、对应测试、启动脚本；交付材料仅为本记录/公开证据和项目状态。修复提交为 `3b453b2`（真实结果与导出）和 `f2f232d`（显式参数预设）；本交付记录单独提交。

## 尚未完成与声明

网页的服务重启恢复、归档多轮基准的图形查看、更多 HIBE 接入、最终三代表和完整报告排版仍未完成。本批不改变密码算法、采样或原语 wire；对正式参数、QROM 或组合归约不作新增结论，三条暂缓路线未启动。

原文安全性与 HIBE 匿名性沿用用户确定的研发工作前提，ROM 依赖按各原语记录。LATTE 使用作者档，ML-DSA/Falcon 使用对应完整底层档，Luo 为默认 research 配置；不把这些研究组合统称为教学玩具参数，也不升级为已正式准入。全部保留 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`；功能与性能验收不能替代安全证明。
