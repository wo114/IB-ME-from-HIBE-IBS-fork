# C1 Lai P2：A 参数点、公共接入与 CLI 生命周期（WIP）

状态：**P2 的 A 点、公共接入和 CLI 两级生命周期已完成；尚未做 P3 组合配对与 P5 目标参数准入**。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。本批证明“A 点（n=256、t=1）能完成两级生命周期，解决 32 B seed 容量与 86 B 身份绑定，并已接入 registry/CLI/state”，不构成安全/目标参数声明。

## 1. 结论

**A 点可行，B/通用 t 不需要为 P2 先做。**

- `n=256, t=1, q=2147484161, k=32, l=2, p=2, σ=2`：两级加解密、32 B 消息、4 字节系数序列化通过。
- 5 个随机种子完整生命周期 **5/5**，平均 **26.29 s**（18.08–28.84 s）。
- 容量 `k·n = 8192 bit = 1024 B`，32 B seed 足够；身份每层 256 bit（86 B 输入哈希到 256 bit，碰撞约 128 bit）。
- 与 B（n=16,t=16）相比，A 不需要改身份向量/公钥/掩码结构，P1 的 `t=1` 代码直接换参数即可；运行时间在可接受范围。

## 2. A 点探针

固定 `n=256, l=2, p=2, σ=2, depth=2`，扫三个 `q≡1 mod 512` 的素数；每个点跑一次完整生命周期（32 B 消息）。

| q | k | tolerance | level 1 | level 2 | 备注 |
|---|---|---|---|---|---|
| 1,073,750,017（2^30+8193） | 31 | 248,524,837 | 通过 | **失败**：残差 279,958,552 > 容差 248,524,837 | 差 13% |
| 2,147,484,161（2^31+513） | 32 | 497,046,000 | 通过 | 通过 | **选为 A 点** |
| 4,294,968,833（2^32+1537） | 33 | 985,333,427 | 通过 | 通过 | q>2^32，需 5 字节；不选 |

A 点单次计时（q=2,147,484,161）：

| 阶段 | 时间 | 备注 |
|---|---|---|
| setup | 0.19 s | `a0^T R + a1 = g` |
| extract（level 1） | 3.16 s | R1 max width 670 |
| derive（level 2） | 5.76 s | R2 max width 137,980 |
| encrypt level 1 | 3.61 s | |
| decrypt level 1 | 0.14 s | |
| encrypt level 2 | 9.66 s | |
| decrypt level 2 | 0.40 s | |
| 5 种子完整生命周期 | 26.29 s 平均 | 5/5 |

## 3. 代码与测试

新增/修改：

- `experiments/research/candidates/lai/backend.py`
  - `A_POINT_PARAMS = Params(q=2147484161, n=256, k=32, l=2, p=2, σ=2, σ_r=1, depth=2)`；
  - `Params.coefficient_bytes`：`q<2^24` 用 3 字节，否则 4 字节；`q≥2^32` 拒绝；
  - `_encode_ring`/`_decode_ring` 按 3/4 字节自适应；
  - `Params` 不再禁止 `q≥2^24`，序列化层再检查。
- `tests/test_lai_p1.py`
  - `test_a_point_capacity_and_identity`：32 B 消息、256-bit 身份、二进制系数；
  - `test_a_point_two_level_lifecycle_and_serialization`：A 点两级生命周期 + 4 字节密文往返。

结果：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest tests/test_lai_p1.py -q
# 22 passed (23-28 s)

... tests/test_lai_p1.py tests/test_lai_qualification.py -q
# 37 passed in 24.87s
```

## 4. 这解决了 P2 的两个硬前置

| P2 前置 | A 点取值 | 结论 |
|---|---|---|
| 32 B seed 容量 | `k·n = 32×256 = 8192 bit = 1024 B` | 32 B 足够 |
| 86 B 身份绑定 | 每层 256 bit 二进制身份（SHAKE 输出） | 碰撞约 128 bit；86 B 输入不再压到 8 bit |
| 序列化 | 4 字节系数（q<2^32） | A 点 q=2^31 可用 |
| 结构 | `t=1`，P1 代码不变 | 不需要通用 t/B 分支 |

## 5. 未做与风险

1. **研究参数，不是目标参数**：q=2^31、n=256、σ=2 没有安全等级；P5 目标 n=1024 时仍需重新筛 q/σ 和估计。
2. **P3 组合配对未做**：registry/CLI/state 已接，但 Wang 包装、`(rcv, phi)` 顺序、四种匹配与恢复尚未在组合层验收；HIBE 盘点仍 3/8，直到状态文档更新。
3. **未做组合配对**：86 B 身份、32 B seed 只是容量满足；Wang 包装、`(rcv, phi)` 顺序、四种匹配、状态恢复仍未接。
4. **采样仍是 Klein，无 perturbation**：功能通过，不是证明级 `ringSampleD`；P5 或正式分布再处理。
5. **q=2^30 的边界很近**：A 点选 q=2^31 而不是 q=2^30；若换 σ/n 需重新扫边界。
6. **Sage 运行 26 s/生命周期**：P2/P3 原型可接受，P5 目标 n=1024 会更慢，需要 C/优化实现或减少重复次数。

## 6. P2 公共接入与 CLI 实测

### 6.1 代码

新增 `src/ibme/hibe/lai/`：

| 文件 | 内容 |
|---|---|
| `params.py` | `LaiParams` A 点、`VERSION=lai-a-256-v1`、Sage-free |
| `codec.py` | 严格二进制编解码（params/ring/vector/matrix/identity） |
| `objects.py` | PK/MSK/SK1/SK2/CT 五对象，`to_bytes/from_bytes` 严格往返 |
| `engine.py` | Sage 环运算、Klein、`ringDelTrap`、Babai 反演、两级加解密 |
| `backend.py` | 冻结 HIBE API 适配、身份/容量校验、`validate_key_binding`、`load_ciphertext` |
| `registration.py` | registry descriptor、presets、`ciphertext_size`、环境/配置钩子 |

`registry.py` 已把 `lai-ideal-hibe` 从 unavailable 循环移出，改为可用研究后端：

- `version=lai-a-256-v1`
- presets：`hybrid-research`（32 B seed）、`direct-research`（framed32）
- `two_level=True`、`key_binding=True`
- `object_parameter_binding=full-parameter-snapshot`
- `available=True`，但 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`

### 6.2 CLI 端到端实测（WSL Sage 10.9 / Python 3.13.15）

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ibme.cli setup \
  --hibe lai-ideal-hibe --ibs luo-module \
  --hibe-params hybrid-research --ibs-params research \
  --transport hybrid --state /tmp/lai-cli-state
```

结果：`suite_digest=1e91be1d001912dc764ae7f435fc7e08f037889e04919a42a93d27b29627f18d`，`identity_bytes=64`，`max_application_bytes=3924`。

| 步骤 | 结果 |
|---|---|
| `issue-receiver-key alice` | `receiver-*.bin` 1,449,465 B |
| `issue-sender-key bob` | `sender-*.bin` 313,778 B |
| `encrypt --sender bob --receiver alice` | 13 B → 229,620 B 密文 |
| `decrypt --receiver alice --sender bob` | 13 B，`cmp` 与原文一致 |

预检的内层 HIBE 密文上限为 101,416 B；完整协议密文 229,620 B。状态目录在 `/tmp/lai-cli-state`，不入 Git。

### 6.3 提交

| 提交 | 内容 |
|---|---|
| `34662d8` | A 点 n=256 参数与 4 字节 codec |
| `a13a97b` | `src/ibme/hibe/lai/`、registry/CLI 接入 |
| `ef1bb04` | Hybrid suite preflight 测试 |
| `7a25c24` | `docs/specs/lai-hibe.md` 契约 |

### 6.4 测试

| 命令 | 结果 |
|---|---|
| `pytest tests/test_lai_hibe.py -q` | **12 passed in 93.81s** |
| `pytest tests/test_lai_p1.py tests/test_lai_qualification.py -q` | **37 passed in 29.29s** |
| Windows：`pytest tests/test_assembly.py tests/test_c_registration.py tests/test_cli_selection.py -q` | **84 passed in 15.02s** |

覆盖：两级诚实生命周期、32 B payload、86 B 最大身份、错误 parent/child、五对象序列化往返、截断/追加/坏 magic、密文无身份明文、`validate_key_binding`、固定 RNG 可复现、registry/catalog、`ciphertext_size`。

## 7. 下一步

1. **P3**：把 Lai 与一个就绪 IBS 接入 Wang 组合，跑四种匹配/错配、状态恢复、篡改/截断/重放；这是“组合层”的验收。
2. **P5**：目标参数（n=1024 等）缩放、宽度/分布复验、estimator；当前 A 点只是研究参数。
3. **文档/状态**：`ALGORITHM_CATALOG.md` 和 `PROJECT_STATUS.md` 的 Lai 行仍写“资格核验/未实现”，需要在统筹确认后同步；本批不改共享状态入口。
4. **性能/尺寸**：当前 key/CT 以 MB 计；P5 前需要评估是否可接受，或改 C/优化实现。

安全声明：本批是功能/工程验证，不是 PLWE/ring-SIS/HIBE/匿名的安全证明；测试通过不代表安全等级。
