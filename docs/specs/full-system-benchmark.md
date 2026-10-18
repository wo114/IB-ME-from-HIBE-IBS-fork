# 完整系统统一评测 v1

入口 `experiments.research.full_system_benchmark` 直接使用既有 `SuiteConfig`、`build_runtime` 与公开协议 API，不读取原语私有矩阵或另写组合协议。第一组选择已有真实接入的 LATTE-3 + BNN 认证转换 ML-DSA-44，保留 Hybrid 和 BYTEAUTH；其它已交付且有持久 HIBE 身份缓存的配置可用同一入口。原语微测和完整 IB-ME 加解密分别报告。

## 固定边界

每个 cold repetition 启动独立 Python 进程，实际新建一套根、发送者和接收者。至少3套独立状态，每套至少3轮 warm 加解密；首次解密包含真实叶提取，warm 解密必须保持已持久化的固定接收状态不变。Encrypt 包括 IBS 签名、所选包装、验证和完整 wire 编码；Decrypt 接受该完整 wire，包含严格加载、HIBE 与 IBS 验证。记录的密文是实际协议最外层 `to_bytes()`，与 CLI 输出边界相同。

每套生成/热运行之后再启动新 Python 进程，恢复公钥与已有接收状态，至少3次解密既有密文。该进程禁止公共 `SecureRandom.read`、IBS Setup/KeyExtract/Sign；LATTE native Setup/Delegate/Extract 及普通签名 native Keypair/Sign 也明确禁止，防止确定性生成误算零熵恢复。现有确定性解密重加密检查、metadata、格式检查和验签允许执行。恢复前后接收状态和原文件必须逐字节不变。

每阶段记录秒数与10 ms `/proc` 自进程/后代进程树 RSS 采样，覆盖实际 native 子进程；采样峰值是下界，可能漏掉短脉冲。进程树RSS求和会重复计入共享/COW页，不等于独占物理内存，本版未测PSS。另附 Linux 内核 self/completed-children **累计** RSS 高水位，不能把该累计计数说成各阶段独立峰值。生成和恢复整进程 wall time 包含启动及未分阶段的开销；生成整进程还包含其 warm 操作，不把整进程 wall time误称纯 cold Encrypt 时间。

“冷”指新 Python/runtime/新密钥状态；不清空操作系统页缓存，不重编已核ABI的 native 引擎。进程启动、native 调用、Python/Sage 验证、wire、单独持久化阶段和恢复阶段均有明示口径，不能将子步骤速度写成整个方案加速。

## 调用

先按各原语交付构建依赖。在仓库根、指定 WSL conda 环境运行，私有输出必须使用新目录：

```sh
PYTHONPATH=src:. OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 \
~/miniconda3/envs/sage/bin/python -m experiments.research.full_system_benchmark \
  --suite-file ci/c-combinations.json \
  --suite-name latte3-hybrid-cert-ml-dsa-ml-dsa-44-reference-byteauth-v1 \
  --private-directory test-results/full-system/new-latte-mldsa44 \
  --repetitions 3 --warm-repetitions 3 --identity-bytes 64 --message-bytes 32 \
  --security-group latte3-cosac-fix-bnn-mldsa44-research --source-commit <固定源码>
```

worker 独立保留逐次原始耗时，聚合只统计已成功执行的观察值，输出 min/median/max/mean/sample standard deviation。warm 样本共享各自状态，不冒称全部独立根。三套 cold 样本不足以给出稳定置信区间或尾部概率，后续正式比较按所需精度增加预先规定的重复次数。

生成前记录 pending；中止不重试、保留占用目录和私有诊断。worker 默认900秒时限，超时终止其独立进程组并保留失败状态。退出或未完成的配置不能补零、换后端或纳入成功样本的排名。

## 输出与声明

私有目录有真实主钥/用户钥及缓存，不进Git。公开收据仅含完整选参、环境、源文件指纹、尺寸、耗时、RSS、无私密参数的操作计数及结果；没有私钥、随机带、原像或密文内容。

按用户确认的论文安全/匿名工作前提推进工程。当前选择保留研究参数口径与 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。`security-group` 为显式比较分组，不能自行升级安全等级；不同目标、输入、包装、格式、计时/内存口径或机器的结果分别展示，脚本不做跨组性能排名。算法安全来源及 ROM 条件沿用各原语文档，功能测量不产生安全证明或新的密码学原创声明。
