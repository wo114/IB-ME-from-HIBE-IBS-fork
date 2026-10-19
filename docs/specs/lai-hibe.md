# Lai A 点独立研究 HIBE 契约

本契约限定 `ibme.hibe.lai` 的 `lai-ideal-hibe`、`lai-a-256-v1`。接口沿用[公共规范](../../IMPLEMENTATION_SPEC.md)；原文为 Lai–Cheung–Chow, *Trapdoors for Ideal Lattices with Applications*, Inscrypt 2014 / LNCS 8957:239–256（[本地 PDF](../../papers/2015_ideal_lattice_trapdoors_lai.pdf)）。逐批实测见[P1](../research/team-c-delivery/2026-10-18-lai-p1/README.md)与[P2](../research/team-c-delivery/2026-10-18-lai-p2/README.md)。

## 执行与参数

- A 点：`q=2147484161`（`2^31+513`，素数，`q≡1 mod 512`）、`n=256`、`k=32`、`l=2`、`p=2`、`σ=2`、`σ_r=1`、深度 2。
- `R_q=F_q[x]/(x^256+1)`；`g=(1,2,…,2^31)`；两级身份、每层 256 bit 二进制身份（SHAKE 输出），每层最多 86 B 原始身份。
- 消息容量 `k·n=8192 bit`，当前 `max_message_bytes=32`（Hybrid 的 32 B seed）；`seed32` 与 `framed32` 两种 preset 只影响 transport 配置，不改变环编码。
- 需要 WSL 的 `~/miniconda3/envs/sage`；无 Sage 时 registry 仍可发现，但 `validate_environment` 报告 runtime 不可用，不退回 mock 或其它算法。
- **研究参数**：没有安全等级，不是 NIST category；P5 目标参数需重新筛 `n/q/σ` 并做宽度/估计核验。
- **目标候选（未默认登记）**：`c2-2048-2p38` = `n=2048, q=274877976577, k=39, σ=2`，PLWE 系数实例在固定 estimator 的 GSA 完整攻击集下约 169.9/154.2 bit；真实两级生命周期已跑通多个种子。详见[目标参数筛选](../research/team-c-delivery/2026-10-18-lai-target-parameters/README.md)。它作为显式 `target-research` preset 登记，不是默认 preset，也不改变 `none/false/false`。

## 五方法与算法对应

| 方法 | 实际执行 |
|---|---|
| setup | `ringGenTrap`：`a0^T R + a1 = g`，`u0,u1,u2` 公开向量 |
| extract(msk, rcv) | 一级委派：`a_id1=u0+id1·u1`，`ringDelTrap(a,R,1,h1,a_id1)` |
| derive(sk1, phi) | 二级委派：`F1=(a;a_id1)`，`a_ID=a_id1+id2·u2`，`ringDelTrap(F1,R1,h1,h2,a_ID)` |
| encrypt | `R=R0+id1·R1+id2·R2`，`e1=-e0^T R`；`u=F1·s+p·e0`，`v=(a_ID+h'g)s+p·e1+m` |
| decrypt | `target=h2+h'` 单位检查；`y=u^T R2+v`；Babai 反演 `s`；检查 `e mod p=(0;m)`，失败返回 `None` |
| load_ciphertext | 严格规范对象解码；截断/追加/坏 magic/越界系数/维度错误拒绝 |

身份顺序固定 `(parent_id, child_id)=(rcv, phi)`。`encrypt` 只产生 level-2 密文；level-1 密钥仅用于派生。

## 身份编码（研究选择）

原文没有给出身份到 `R_q` 的编码。本实现把身份 SHAKE 到 `n` 个二进制系数（每层 256 bit），而不是均匀环元素；原因是加密中的 `e1=-e0^T R` 只有在 `id_i·R_i` 保持短时才使解密残差落在 Babai 容差内。均匀 hash 身份在本参数下实测残差约 2.06M，超过容差 242k，直接失败。该选择把每层身份空间限制为 `2^256`，但足以绑定 86 B 输入（碰撞约 128 bit）；不是原文逐字规定。

## 对象、wire 与绑定

五类对象：`LaiPublicKey`、`LaiMasterSecret`、`LaiLevel1SecretKey`、`LaiLevel2SecretKey`、`LaiCiphertext`。均实现 `to_bytes/from_bytes`；公钥/密文只含公开数学数据和完整参数快照，密文无身份明文或身份摘要。

- 环元素编码为 `n` 个系数，`q<2^24` 用 3 B，`q<2^32` 用 4 B，`q<2^40` 用 5 B；当前上限 `q<2^40`。
- 对象带独立 magic、body 长度和字段长度前缀；解析拒绝截断、追加、维度错误和系数越界。
- `validate_key_binding` 在不解密、不采样、不消耗熵的前提下检查主/一级/二级陷门方程和身份派生；供 Hybrid 适配器使用。
- 密钥与密文较大：A 点接收者密钥约 1.4 MB、发送者密钥约 0.31 MB、内层 CT 约 101 KB；这是 256 维/当前编码的直接结果，不是性能结论。

## 随机源

- 生产路径（`rng=None` 或 `SecureRandom`）使用 64 KiB 缓冲的 OS CSPRNG 字节流（`SecureRandom.read` → `secrets`/`os.urandom`），**不使用 Mersenne Twister**；采样仍经统一的 `randrange`/`random` 接口。
- `DeterministicRandom` 只作为显式测试源；它同样走缓冲字节流，输出可复现，禁止用于生产密钥/签名。
- `src/ibme/hibe/lai/engine.py` 与 `experiments/research/candidates/lai/backend.py` 均已修复；目标 CLI 收据应在修复后重跑，旧收据只证明功能路径。

## 状态与并发

本后端为**无状态原语**：setup/extract/derive/encrypt/decrypt 不缓存同址密钥或 pending 记录；同一地址重复发钥会产生独立密钥，调用应用负责持久化、原子写和跨进程锁。`persistent_identity_cache=False`。

## 实现差异与准入

- `ringDelTrap` 输出修正为 `m×k`（原文 Algorithm 9 印刷 `(m+k)×k` 与方程矛盾），旧 tag 归一化为 `(h'g-a1)/h`。
- HIBE 的 `Derive=Extract` 原文只有一句；本实现采用“每层追加 `a_ID` 块、密钥线性增长”的显式补全，见 P1/P2 文档。
- 采样为 Klein/GPV 陪集采样，**没有 perturbation**；功能通过不等于证明级 `ringSampleD` 分布。单位 tag 采样有 4096 次上限，`h_id+h'` 非单位时解密失败。
- 本版本始终 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。PLWE/ring-SIS、HIBE 匿名性、两层模型映射、正式参数/估计和 Wang 组合前提均不因本契约升级。
- 目标参数缩放、采样扰动、`n=1024` 性能、CI 套件与组合配对仍是后续工作；本契约只冻结当前 A 点研究后端。
