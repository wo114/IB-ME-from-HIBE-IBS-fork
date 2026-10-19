# 主展示方案随机多身份／多消息批量验收

本批直接补赛题 R4 和验收项 A09 所要求的“随机生成多组身份和消息进行批量正确性测试”。固定源码提交为 `85a93e2a1243d141b5febd153223a91f44e8159e`，实际组合为：

```text
LATTE-3/COSAC-FIX + BNN/ML-DSA-44 + Hybrid + BYTEAUTH
```

运行使用公共 `SuiteConfig`、公共协议 API 和完整最外层 wire，不读取 HIBE／IBS 私有矩阵，不使用 mock，也没有另写一套组合协议。

## 1. 预先固定的批次

公开输入种子为：

```text
d0492c5865b229aaea45df7b96e2a387ecadd146115a9ba5c02ac759ed43142b
```

测试输入由 `SHAKE256` 在域 `IBME:A09:RANDOM-BATCH:INPUTS:v1` 下展开。每个根生成两个 64 B 接收者身份、两个 64 B 发送者身份，并测试完整的 `2 × 2` 配对；四条消息长度预先固定为 0、1、32、1024 B，非空消息内容由同一公开种子生成。种子、生成规则和输入摘要进入公开收据，原始输入字节不重复存档。

输入生成与密码随机性严格分开：公开测试种子没有注入任何密码后端。每个新根、IBS 用户钥、签名、Hybrid seed／nonce 和 BYTEAUTH 一次性钥均使用 `SecureRandom`／操作系统 CSPRNG。三个根各在新 Python 进程中执行一次；失败样本不重试、不替换。

每个配对执行五项检查：

1. 合法接收者和发送者恢复原消息；
2. 错误发送者返回 `BOTTOM`；
3. 错误接收者返回 `BOTTOM`；
4. 双方都错返回 `BOTTOM`；
5. 修改 `byteauth.inner_bytes` 中一个确定位置的单比特，保持 wire 长度和规范解析均有效，解密仍返回 `BOTTOM`。

先完成四个诚实配对，再执行负例，因此所有负例都复用已经存在的两个接收者和每个接收者的两个子身份，没有越过 LATTE 的 `max_receivers=2`、`max_children=2` 容量后再把容量错误算作身份拒绝。

## 2. 实际结果

| 项目 | 实际结果 |
|---|---:|
| 独立 CSPRNG 根 | 3 / 3 完成 |
| 随机身份／消息配对 | 12 / 12 完成 |
| 合法匹配恢复 | 12 / 12 |
| 错误发送者拒绝 | 12 / 12 |
| 错误接收者拒绝 | 12 / 12 |
| 双方错误拒绝 | 12 / 12 |
| 保持格式有效的密文篡改拒绝 | 12 / 12 |
| 总检查 | **60 / 60** |
| 超时／重试／丢弃样本 | 0 / 0 / 0 |

三个根分别消费 28 次、262832 B 公共 `SecureRandom` 输出；没有保存随机字节。每个根实际观察到 LATTE Setup 1 次、Delegate 2 次、Extract 4 次、Encrypt 4 次、Decrypt 16 次，以及 ML-DSA Keypair 3 次、Sign 6 次。完整密文为 142028—143085 B；该范围同时包含四种消息长度，不能与固定 32 B 消息的旧评测直接当作同输入性能比较。

三个新进程总 wall time 为 8.941—10.502 s，中位数 9.101 s；Setup 为 1.519—1.885 s。90 个分阶段观察中的 10 ms 进程树 RSS 最大值为 285454336 B（272.23 MiB）。这些数值用于说明本批稳定运行边界，不作为新的跨方案性能排名。

实际环境为 Intel Xeon Silver 4216、Linux 6.18.56、Nix SageMath 10.9／Python 3.14.7、`OMP_NUM_THREADS=4`、`OPENBLAS_NUM_THREADS=1`。本机没有使用仓库历史中另一台电脑的 conda/Sage 绝对路径。LATTE 与 ML-DSA 均从仓库固定源码重新构建；[native-provenance.json](native-provenance.json)是运行后的独立公开查询，记录源码 ID 和二进制摘要，但不冒充 worker 内嵌采集。

## 3. 证据与复核

- [公开完整收据](receipt.json)，SHA-256 `21f1bb84052004749dc172e396328f683ae46290011fd6cee7cc0e1b31b88de9`；
- [源码、范围和负控校验器](verify.py)；
- 私有 worker 日志只保留在 ignored `test-results/a09-random-batch-85a93e2/`，不进入 Git；收据不含主钥、用户私钥、随机带、原始身份、原始消息或完整密文。

当前机器可执行：

```sh
PYTHONPATH=src:. nix shell nixpkgs#sage -c \
  sage -python docs/research/2026-10-19-primary-random-batch/verify.py --self-test
```

校验器不生成密钥、不执行密码算法、不读取私有运行目录。它核对完整收据、固定 Suite、三个根的 135 份源码 provider 绑定、Git 提交、原生源码 ID和五种受控篡改负例。

## 4. 声明边界

本批固定 LATTE-3 的 `N=1024`、`q=68718428161`、深度 2、seed32 模式，以及 BNN/ML-DSA-44 reference wire、Hybrid 和 BYTEAUTH。参数的完整数值以收据中的严格 Suite 快照为准。

安全元数据保持：

```text
security_claim = none
backend_admitted = false
parameters_are_formal = false
security_proofs_produced = 0
```

所选算法安全性和 HIBE 身份匿名性继续按项目已确认的论文引用／工作假设推进；本批 60 项有限功能与拒绝测试不构成安全证明、失败概率证明、NIST 等级认证或完整组合归约。

## 5. 未计入的第一次运行

在归档阶段发现第一次运行命令手工填写了一个不存在的 40 位 `source_commit`。该次功能观察也是 60/60，但因来源字段无效，不纳入本交付，也没有改写其收据；原目录 `test-results/a09-random-batch-2b1c476/`继续保留。随后运行器增加“提交必须存在且运行源码／Suite 必须与提交一致”的前置门，并在固定提交 `85a93e2` 上复用完全相同的公开输入种子重新执行。最终收据只来自第二批三个新 CSPRNG 根，因此没有按身份或消息重新挑选输入。
