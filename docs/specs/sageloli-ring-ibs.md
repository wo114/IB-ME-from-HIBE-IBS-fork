# Sageloli 环原生 RSIS v3 公共接入契约

本契约补充 [共同接口](../../IMPLEMENTATION_SPEC.md)和[传输／状态约定](transport-and-state.md)。算法、实际两档参数和采样边界来自 [PR59 交付](../research/team-b-delivery/2026-10-19-sageloli-ring-target/README.md)，原 v2 契约及状态继续保留，不能自动迁移。

## 选择、参数和依赖

公共后端 ID 为 `sageloli-rsis`，版本为 `Sageloli-RSIS-structured-v3`。它登记到原 RSIS 文献路线，不增加论文算法计数；`sageloli-sis` 的矩阵路线不受本次接入影响。

| 预设 | d / k / l | 身份采样宽度平方 | 签名采样宽度平方 | 含义 |
|---|---|---:|---:|---|
| `PARAM-I` | 2048 / 65 / 132 | 2720281532542 | 270116709797628319132317 | PR59 已运行的 Table 6 第一档，默认选择 |
| `PARAM-II` | 2048 / 153 / 308 | 6438584418095 | 1513219104215593870492656 | PR59 已运行的第二档，完整组合实测另列 |
| `debug-small` | 4 / 9 / 22 | 2^36 | 2^66 | 仅供接线回归，公开可伪造的小参数 |

两档论文预设还固定 `q=3^k`、`r_squared=49`、身份／消息上限 256／4096 B、盐 32 B、最多两个已登记身份、签名尾拒绝帽 64、tail/mass bits 为 256／320。Suite 保存完整数字字段，不仅保存预设名称。与原 `published("I"/"II")` 的向上舍入公式一致性由 Sage 测试核对；本次没有改变宽度解释、采样器、方程或原生算术。

真实运行需要规定的 WSL `~/miniconda3/envs/sage`，以及显式构建并设置的 `IBME_SAGELOLI_RING_NATIVE`。发现／容量预检不编译、不抽样、不写状态。执行时原生库必须通过既有 `source_id` 检查；缺少依赖明确失败，不改用 v2、小参数或 mock。wheel 包含 `native.cpp`，可以在安装包中执行同一显式构建步骤。

## 公共五方法和恢复

公开入口为 `ibme.ibs.sageloli.ring.Backend`，注册描述符位于 `ring_registration.py`。五方法直接调用原 v3 实现。公钥和主状态沿用原对象；发送者私钥的薄包装补充共同接口的 `identity_digest`，其规范字节与原 v3 私钥完全一致，不复制或改变陷门。

公钥、主状态和用户钥通过默认装配器恢复。主状态恢复核对根关系和全部已发用户钥的每个环列；用户钥恢复核对原始精确方程和尾界。恢复器使用禁止熵读取的随机源。原解析器的数据错误在公共边界转为 `SerializationError`，以便协议正确区分解析失败和程序错误。签名解析复用原 v3 的规范、上下文、非零、中心化和范数检查。

对象和 Suite 绑定完整参数；CLI v2 状态再绑定 Suite 摘要、公钥摘要和对象类别。旧后端版本、v2 魔数、参数／上下文不匹配、错误根和错误用户陷门均拒绝。公钥／方程一致性检查不证明生成分布，也不提供存储认证或防回滚。

## 容量与持久服务

`reference` 是原 v3 的固定槽位二进制编码。签名尺寸由帧和张量尺寸精确计算，不创建系数数组：两档分别为 **3,227,824 B** 和 **7,553,200 B**。不提供尚未实现的 compact 格式。

框架默认 Hybrid 载荷为 64 KiB，容不下这两档签名；默认小预算会在任何熵读取和状态创建前拒绝。调用方须显式提供 Hybrid limits。本批 LATTE 组合使用 8 MiB 载荷、4 MiB 胶囊、64 B 外部身份及 32 B HIBE seed；原框架 16 MiB 载荷硬上限和 64 MiB 完整 wire 上限保持不变。

CLI 新增通用 `--hybrid-limits`，接受 JSON 或 JSON 文件，用于 `check` 和独立选择 `setup`。这些限额写入 Suite 和持久状态摘要，后续命令从状态恢复，不能静默换预算；旧配置默认值保持不变。完整例子见[接入交付](../research/2026-10-19-sageloli-ring-integration/README.md)。

默认装配声明固定身份缓存，实际继续由原 v3 主状态账本保存；重复发钥返回原规范私钥，pending/failed 不自动重发。CLI 使用原有 master pending、锁和先持久化再发布事务。静态准入同时计算满用户账本的最坏 wire 上界，超过原 v3 的 2 GiB 编码包络时拒绝；这是存储容量检查，不是峰值内存预测。

## 验收与声明

默认 CI 的既有 `tests/test_sageloli_*.py` 包含新增 portable 注册／容量检查。需要原生库的适配、损坏密钥恢复和真实小配置组合位于 `tests/sageloli_native/test_ring_assembly.py`，显式执行。论文规模完整 CLI、同根组合矩阵和仓库外恢复分别留存收据，不由静态预检或小配置回归推定。

论文安全性沿用项目工作前提；SHAKE 的实际工程使用、ROM/QROM 引用和工作假设仍按原交付解释。本次工程接入不新增安全证明或外部标准等级；有限浮点／FFT 采样误差仍按原交付边界记录。`PARAM-I` 与 `PARAM-II` 两个论文档按 2026-10-20 用户决定登记为 `security_claim=secure`、`backend_admitted=true`、`parameters_are_formal=true`；`debug-small` 明确保持 `none/false/false`，不用于安全展示。
