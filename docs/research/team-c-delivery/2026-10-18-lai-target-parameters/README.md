# C1 Lai：PLWE 安全参数候选与配置选择（WIP）

日期：2026-10-18。**2026-10-19 算法实现已冻结：[C2-FREEZE.md](C2-FREEZE.md) / [c2-freeze.json](c2-freeze.json)。** 范围：把 A 点研究参数扩展到 **128-bit 级别的 PLWE 候选**，先筛若干组，再确定一组配置。本文是启发式参数筛查，不是 NIST 等级、HIBE 安全证明或正式准入。

## 1. 结论

**2026-10-18 用户确认选 `c2-2048-2p38`：`n=2048, q=274877976577, k=39, l=2, p=2, σ=2, σ_r=1`。C3 不选，仅保留备选记录。**

- PLWE 系数实例估计：**169.9 bit 经典 / 154.2 bit 量子**（固定 estimator、§4 所列 GSA 攻击集，包含混合攻击；C2 的 LGSA 混合路径失败记录保留）。这是对应成本模型的估计，不是整体 HIBE 安全等级。
- 两级生命周期已跑 4 个确定性种子和一次生产 CSPRNG 探针（86 B 身份、32 B 消息），并在随机源修复后重跑目标 CLI，见 §8、§10。首个历史探针为 setup 2.79 s、extract 42.21 s、derive 645.0 s、encrypt 121.04 s、decrypt 21.79 s，解密一致；该历史计时不冒充修复后的生产随机源实测。
- 作为目标候选，它的对象很大：PK 1.62 MB、MSK 2.42 MB、SK1 18.8 MB、SK2 34.8 MB、内层 CT 1.23 MB；这是当前 A 点之外的“可用性代价”。
- `c3-2048-2p39` 作为正确性余量更大的备选（164.1/148.9 bit），尚未跑生命周期；`c1-1024` 只有 74.2/67.3 bit，淘汰；A 点只有 11.7/10.6 bit，只能作研究基线。

## 2. 候选表

| 候选 | n | q（bit） | k | 经典/量子估计 | 正确性余量代理 | 结论 |
|---|---|---|---|---|---|---|
| A 点 | 256 | 2,147,484,161（32） | 32 | 11.7 / 10.6 | 1.67 | 研究基线，淘汰 |
| C1 | 1024 | 34,359,754,753（36） | 36 | 74.2 / 67.3 | 1.51 | <128，淘汰 |
| **C2** | **2048** | **274,877,976,577（39）** | **39** | **169.9 / 154.2** | **2.76** | **选定** |
| C3 | 2048 | 549,755,904,001（40） | 40 | 164.1 / 148.9 | 5.25 | 未选；仅备选，未跑生命周期 |

所有 q 均为素数且 `q≡1 mod 2n`；C2/C3 的 q 在 5 字节系数范围内（`q<2^40`）。

## 3. 尺寸（86 B 身份、公式）

| 候选 | 环元素 | PK | MSK | SK1 | SK2 | 内层 CT |
|---|---|---|---|---|---|---|
| A | 1,024 B | 133 KB | 199 KB | 1.32 MB | 2.40 MB | 101 KB |
| C1 | 5,120 B | 748 KB | 1.12 MB | 8.14 MB | 14.96 MB | 568 KB |
| **C2** | **10,240 B** | **1.62 MB** | **2.42 MB** | **18.82 MB** | **34.80 MB** | **1.23 MB** |
| C3 | 10,240 B | 1.66 MB | 2.48 MB | 19.71 MB | 36.51 MB | 1.26 MB |

C2 的实际单次运行（86 B 身份）：PK 1,617,969 B、MSK 2,416,693 B、SK1 18,821,265 B、SK2 34,795,753 B、CT 1,228,844 B；与公式相差几十字节。

## 4. 估计模型与限制

固定 [lattice-estimator](https://github.com/malb/lattice-estimator) `53da5982597709ba0fdf94ea37a84d822310fd84`，ADPS16 Core-SVP 经典 0.292 / 量子 0.265，**GSA** shape model。输入按 PLWE 的系数 LWE 处理：

- 秘密维度 `n`，样本数 `m=(l+k)·n`（公开 `a` 的 l+k 个环样本）；
- `Xs=D(σ)`，`Xe=D(p·σ)`（p=2）；
- 攻击集：`usvp`、`bdd`、`bdd_hybrid`、`bdd_mitm_hybrid`、`dual`、`dual_hybrid`；C2 的 **LGSA** hybrid 路径触发 estimator `math domain error`，因此完整集用 GSA 跑，C3 的 LGSA 可复现同值。
- C2 完整集最小值：**169.94 bit 经典 / 154.23 bit 量子**（仍是 `usvp`）；C3：164.10 / 148.93。hybrid 项没有把最小值拉低。
- 结果 JSON：[security-estimate.json](security-estimate.json)。这是启发式筛查，不是 NIST 等级或 HIBE 安全证明。

正确性余量代理：以 n=256 的 q=2^30 失败（残差/容差=1.126）和 q=2^31 通过为基线，按 `n^1.9`、`k^2`、`σ^3` 缩放；C2 代理余量 2.76。§8、§10 记录了后续真实运行；这些运行不把代理升级为完整误差界。

## 5. 选择理由

- C2 是第一个同时满足 **经典与量子估计 ≥128 bit**、且真实生命周期跑通的候选；
- C1 在 n=1024 上只有 74/67 bit，单纯加 q 不能把它推到 128；
- C3 的 q 更大、正确性余量更高，但安全估计略低、尺寸/时间更大；作为 C2 失败时的备选；
- A 点保留为研究/演示参数，不参与安全参数比较。

## 6. 未做与风险

1. hybrid 攻击已用 GSA 完整集评估；但 LGSA 在 C2 上不可用，模型差异仍是风险，不能写成 NIST 等级或完整形式化结论。
2. C2 已跑 **4 个独立种子**，全部诚实路径成功；但没有逐种子的残差/容差统计。目标级负测试覆盖 wrong-child/wrong-parent、h/u/v 篡改、非单位标签和截断/追加；v 篡改返回**不同明文**，说明原始 HIBE 无 CCA/完整性，必须依赖外层 BYTEAUTH。
3. 没有 perturbation；Klein 采样仍是功能级，不是证明级 `ringSampleD`。
4. C2 已作为 `target-research` 显式 preset 登记，且目标 CLI 生命周期已跑通；但它仍不是默认 preset，`lai-ideal-hibe` 的默认/CLI 起点仍是 A 点。要提升为默认，还需性能/资源政策审查。
5. 尺寸/时间：SK2 约 35 MB、内层 CT 1.23 MB、完整协议 CT 约 1.36 MB、state 约 26 MB；CLI 生命周期约 13 分钟（Sage），目标演示需评估是否可接受或改 C/优化实现。
6. 本文不声称 NIST category、QROM 安全或完整 HIBE 安全；`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

## 7. 目标 preset 预检（2026-10-18）

用 CLI 的静态 preflight 检查 `target-research` 是否可选（不生成密钥、不执行算法）：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m ibme.cli check \
  --hibe lai-ideal-hibe --ibs luo-module \
  --hibe-params target-research --transport hybrid --json
```

结果：`compatibility.ok=true`、`errors=[]`；`inner_hibe_ciphertext_max_bytes=1,228,844`、`inner_hibe_payload_bytes=32`、`max_application_bytes=3,924`；suite digest `eda3502de91eff42f10969dac9c3e92fd31468b5e1bc8b5fc17c498468b81c28`。`execution=not_executed`，不生成密钥。

## 8. 目标级负测试与 CLI 生命周期（2026-10-18）

### 8.1 负测试

脚本：`experiments/research/candidates/lai/target_negative.py`。使用 C2、86 B 内层身份、32 B 消息、固定种子；结果 JSON 在 `/tmp/lai-target-negative.json`（不入 Git）。

| 检查 | 结果 | 耗时 |
|---|---|---|
| wrong-child key | 拒绝（None） | 778.14 s |
| wrong-parent ciphertext | 拒绝（None） | 180.07 s |
| tampered h' | 拒绝（None） | 25.44 s |
| tampered u0 | 拒绝（None） | 28.53 s |
| tampered v0 | **返回不同明文**（非 None） | 30.27 s |
| non-unit tag | 拒绝（None） | 0.06 s |
| truncated/appended CT | `SerializationError` | 0.03 s |

基础诚实路径：setup 2.88 s、extract 39.98 s、derive 552.95 s、encrypt 94.77 s、decrypt 20.11 s，`ct_bytes=1,228,844`，`honest_ok=true`，`all_ok=true`。`tampered_v0_result=different` 是原始 HIBE 可延展性的负结果，不是“拒绝”成功；组合层必须由 BYTEAUTH 承担完整性。

### 8.2 CLI 完整生命周期

首次 CLI 失败于 `invalid hybrid component type/size`：C2 的 SK1=18.82 MB 超过 hybrid 的 16 MiB component 上限。将 [hybrid_hibe.py](../../../../src/ibme/protocol/hybrid_hibe.py) 的 `HARD_COMPONENT_BYTES`/`HARD_WIRE_BYTES` 提升到 **64 MiB**，capsule 仍为 4 MiB；另加 `HARD_CIPHERTEXT_WIRE_BYTES=20 MiB`。`tests/test_hybrid_hibe.py tests/test_assembly.py` **65 passed**。这是共享协议资源预算变更，需在合并时复核。

重跑命令（`setup` 使用 target preset，state 在 /tmp）：

```sh
python -m ibme.cli setup --hibe lai-ideal-hibe --ibs luo-module \
  --hibe-params target-research --ibs-params research --transport hybrid \
  --state /tmp/lai-target-cli
python -m ibme.cli issue-receiver-key alice --state /tmp/lai-target-cli
python -m ibme.cli issue-sender-key bob --state /tmp/lai-target-cli
python -m ibme.cli encrypt --sender bob --receiver alice \
  --in msg.bin --out ct.bin --state /tmp/lai-target-cli
python -m ibme.cli decrypt --receiver alice --sender bob \
  --in ct.bin --out out.bin --state /tmp/lai-target-cli
```

**2026-10-19 CSPRNG post-fix 实测**：setup 8 s、issue receiver 57 s、issue sender 6 s、encrypt 110 s、decrypt 632 s；14 B → **1,357,049 B** CT，解密一致；receiver key 20,439,553 B、sender key 313,778 B（sender 主要承载 IBS 签名密钥，目标 HIBE 子密钥在解密路径派生）；state 约 26 MB。suite digest `eda3502de91eff42f10969dac9c3e92fd31468b5e1bc8b5fc17c498468b81c28`。这取代了 pre-fix MT 版本的 5/60/11/118/572 s 收据。

### 8.3 多随机种子

`target_probe.py --seed N` 的 4 个独立种子（0 为早前单次，1–3 为 2026-10-19）：

| seed | setup | extract | derive | encrypt | decrypt | 结果 |
|---|---|---|---|---|---|---|
| 0 | 2.79 | 42.21 | 645.0 | 121.04 | 21.79 | ok |
| 1 | 3.03 | 39.09 | 624.84 | 126.73 | 21.83 | ok |
| 2 | 3.13 | 39.13 | 624.06 | 124.18 | 21.33 | ok |
| 3 | 3.05 | 39.56 | 622.38 | 125.27 | 21.14 | ok |

4/4 成功；对象尺寸固定（PK 1,617,969；SK1 18,821,265；SK2 34,795,753；CT 1,228,844）。这只是生命周期成功率和耗时，不是残差分布/宽度统计。

### 8.4 外层 BYTEAUTH 目标级负测试

用 C2 的 CLI state/CT（1,357,049 B）在 `proto.decrypt` 外层做 tamper：

| 用例 | 结果 | 耗时 |
|---|---|---|
| context tamper | 拒绝（BOTTOM） | 10.84 s |
| signature tamper | 拒绝 | 10.46 s |
| inner bytes tamper | 拒绝 | 8.92 s |
| truncated CT | 拒绝 | 9.27 s |
| appended CT | 拒绝 | 10.95 s |

脚本：`experiments/research/candidates/lai/target_byteauth_negative.py`；JSON 在 `/tmp/lai-target-byteauth-negative.json`。以上是 **CSPRNG post-fix** 的 C2 state/CT 结果。**未单独测试** replay；wrong receiver/sender 见 §8.5。wrong-child/wrong-parent 已在原始 HIBE 层覆盖，replay 没有协议级状态。

### 8.5 外层 wrong receiver / wrong sender

脚本：[target_wrong_identity.sh](../../../../experiments/research/candidates/lai/target_wrong_identity.sh)；使用 C2 CSPRNG state/CT，三份独立 state 副本并行。该脚本需要已经完成目标生命周期、并含相应 Carol 接收者密钥的 state；原始 state 保持在仓库外，不随公开交付上传。

| 用例 | CLI 退出 | 结果 | 耗时 |
|---|---|---|---|
| wrong receiver：Carol 解密 Alice 的密文 | 1 | BOTTOM | 619 s |
| wrong sender：Alice 以 mallory 为 sender 解密 | 1 | BOTTOM | 625 s |
| both wrong：Carol + mallory | 1 | BOTTOM | 625 s |

三例都没有输出明文，均返回 BOTTOM；这补齐了组合层 wrong receiver / wrong sender / both 的负测试。replay 仍无协议级状态，未做拒绝测试。

## 9. 64 MiB 资源上限审查与默认决策（2026-10-18）

### 9.1 变更范围

提交 `c484eb5` 只改 `src/ibme/protocol/hybrid_hibe.py` 的两个硬上限：

| 常量 | 旧 | 新 |
|---|---|---|
| `HARD_COMPONENT_BYTES` | 16 MiB | **64 MiB** |
| `HARD_WIRE_BYTES` | 32 MiB + 1024 | **64 MiB + 1024** |
| `HARD_CAPSULE_BYTES` | 4 MiB | **4 MiB（不变）** |
| `HARD_PAYLOAD_BYTES` | 16 MiB | **16 MiB（不变）** |
| `HARD_CIPHERTEXT_WIRE_BYTES` | 无（ciphertext 也走 32 MiB） | **20 MiB（新增，capsule+payload+4 KiB）** |

没有改公共 API、字段编码、KDF/AEAD 或组合语义。

### 9.2 审查结论

- **容量足够**：C2 的 receiver 文件 20,439,553 B（含 IBS 密钥），HIBE SK1=18.82 MB；解密路径派生的 SK2=34.80 MB；C3 的 SK2 约 36.51 MB。64 MiB 对 C2/C3 都有余量；C4（约 67 MB）仍不支持。
- **网络/DoS 风险已收口**：`HARD_CAPSULE_BYTES` 仍为 4 MiB，`HybridCiphertext` 总字段上限约 4 MiB capsule + 16 MiB body；2026-10-19 增加 `HARD_CIPHERTEXT_WIRE_BYTES=20 MiB`，`HybridCiphertext.from_bytes` 在解析前就按 20 MiB 拒绝超长输入，不再先接受 64 MiB。keys 仍用 64 MiB component/wire。
- **内存峰值**：64 MiB component 的 frame/unframe/规范化可能同时持有 2–3 份，峰值约 128–192 MB；C2 目标 CLI 在本地 state 路径实际成功，但不应把该上限解释为可安全接收 64 MiB 远程密钥。
- **历史测试**：`tests/test_hybrid_hibe.py tests/test_assembly.py` **65 passed**（含 ciphertext wire cap）；本次上限审查时 Lai CI 套件为 **56 passed**，随机源测试加入后的记录为 **57 passed**，见[P2 §6.5](../2026-10-18-lai-p2/README.md)和[C2 冻结记录](C2-FREEZE.md)。C2 目标 CLI 生命周期成功。没有刚好 64 MiB 边界的单元测试，64 MiB 仍是硬上限而非性能目标。
- **其他后端**：只是放宽上限，不改变小参数后端的行为；A 点/默认 CLI 不受影响。

### 9.3 默认配置决策

**不把 C2 提升为默认 preset。** 维护现状：

- 默认仍是 A 点 `hybrid-research`/`direct-research`；
- C2 继续作为显式 `target-research` preset，供目标实验选择。

理由：

1. C2 修复后目标 CLI 生命周期约 13.5 分钟（decrypt 632 s；旧 MT 路径为 572 s），state 约 26 MB，SK2 约 35 MB；作为日常默认会显著拖慢 setup/发钥/解密。
2. C2 已有 4 个种子，但没有逐种子残差/容差统计；外层 BYTEAUTH wrong receiver/sender 已通过，replay 仍未单独测。
3. hybrid 攻击已用 GSA 完整集估计；LGSA 在 C2 不可用，模型差异仍是风险。
4. Klein 无 perturbation，仍是功能级采样；目标 CLI 约 13.5 分钟、state 26 MB。

重新评估默认化的最低条件：4 个种子已过（但没有残差统计）、外层 BYTEAUTH tamper/truncate 与 wrong receiver/sender 已过、hybrid GSA 已过、资源政策已补；仍差 replay 需求决策、残差统计和目标性能可接受性。在此之前，C2 是“可选目标配置”，不是默认。

## 10. 随机源修复（2026-10-19）

**确认问题**：`src/ibme/hibe/lai/engine.py` 的 `_Random` 从 `SecureRandom` 取 32 B 后，用 `random.Random`（Mersenne Twister）产生后续所有 `randrange`/`random`/gaussian 随机数；`experiments/research/candidates/lai/backend.py` 有同样实现。MT 不是密码学 PRNG，不能作为正式随机源。

**影响**：此前 C2 目标 CLI/lifecycle 收据使用该 MT 路径。算术结果和功能结论仍成立，但随机质量证据不能用于正式安全声明；旧 CLI 收据应标记为 pre-fix。

**修复**：

- 生产路径（`rng=None` 或 `SecureRandom`）改为 64 KiB 缓冲的 OS CSPRNG 字节流（`SecureRandom.read` → `secrets`/`os.urandom`），实现 `randrange`/`random`/gaussian 的拒绝采样与 53-bit float；
- 显式 `DeterministicRandom` 仍走同一缓冲流，作为可复现测试源，禁止用于生产；
- 不再使用 Mersenne Twister；`src` 与 `experiments` 两个后端都修复。

**验证**：

- `tests/test_lai_hibe.py + tests/test_lai_p1.py`：**36 passed**；
- A 点生产随机源生命周期（无显式 rng）：setup 0.14 s、extract 2.35 s、derive 5.67 s、encrypt 7.57 s、decrypt 0.44 s，解密一致；
- C2 目标生产随机源探针：见 §10.1，**通过**。

### 10.1 C2 生产随机源探针

`target_probe.py --rng secure`（无显式种子，`rng=None` 走 OS CSPRNG）：

| setup | extract | derive | encrypt | decrypt | 结果 |
|---|---|---|---|---|---|
| 2.08 s | 33.20 s | 540.93 s | 106.76 s | 17.41 s | ok |

对象尺寸与确定性路径一致（PK 1,617,969；SK1 18,821,265；SK2 34,795,753；CT 1,228,844）。该次探针没有固定种子，不能与确定性种子逐字节比较；它验证的是生产随机源路径。

**目标 CLI 完整生命周期已在修复后重跑**：见 §8.2 的 2026-10-19 CSPRNG 收据；此前 MT 版本只保留为 pre-fix 功能证据。

## 11. 复现

以下命令从仓库根目录在 WSL 执行。候选表与尺寸计算不运行 estimator，也不生成密钥：

```sh
PYTHONPATH=src:. python -m experiments.research.candidates.lai.target_parameters
```

估计器运行使用固定 checkout（仓库外），脚本检查提交必须为 `53da5982597709ba0fdf94ea37a84d822310fd84`。以下命令使用已有 checkout，不下载或安装依赖：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.lai.security_estimate \
  --estimator-path "$HOME/lattice-estimator" \
  --output build/outputs/lai-security-estimate.json
```

实际脚本分别尝试 `gsa`/`lgsa` 和经典/量子成本模型，`deny_list=("arora-gb", "bkw")`，保留 `bdd_hybrid`、`bdd_mitm_hybrid`、`dual_hybrid`。C2 的 LGSA 异常写入结果，§4 的估计取 GSA；早期排除混合攻击的筛查命令不再是当前结果的复现入口。

C2 生命周期探针已入仓：[target_probe.py](../../../../experiments/research/candidates/lai/target_probe.py)。指定测试种子或生产随机源，每次分别运行一条完整生命周期：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.lai.target_probe --rng deterministic --seed 0
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  -m experiments.research.candidates.lai.target_probe --rng secure
```

探针使用 86 B 身份、32 B 消息；`--seed 0/1/2/3` 对应 §8.3 的四个固定测试种子，`--rng secure` 走生产 CSPRNG。历史计时保持原值，新运行不应期望逐秒或逐字节复现。该探针不属于默认 CI 的目标级生命周期测试，也不测完整残差分布。

A 点、对象、公共登记和候选参数表使用仓库 CI 入口；不把这组测试写成 C2 多次真实运行：

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python \
  ci/run.py run lai-ideal-hibe --output build/outputs/lai-ci-run
```

本报告的 `/tmp` JSON、CLI state 和密文路径是历史本地证据位置，不是公开包内的附件；私钥/state 不随仓库发布。公开包包含源代码、复现命令、参数估计 JSON 及冻结摘要；目标负测试与 CLI 的逐次原始收据未在此目录归档。按当前项目约定，安全/匿名性以原文引用和工作假设推进，不另行补充安全证明；已记录的实现差异和 `none/false/false` 元数据保持不变。
