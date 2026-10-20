# SRGG Table 4 公共装配契约

版本：2026-10-19。公共入口 `srgg2025-paper`，算法版本 `SRGG-PAPER-TABLE4-factor1-v1`。它复用已经交付的论文参数实现，不复制协议或修改采样器。

2026-10-20运行适配：公共后端通过 `experiments/research/candidates/srgg/paper_runtime.py` 使用32768位精确有理数存储储备，承接原8192项级数；其它参数、宽度、精度、tail/mass、尝试帽和熵预算保持原值。历史研究的 `paper_backend.py` 与 `paper_samplef.py` 保持原始字节和8192位标量限制，既有按源码绑定的有限分布证书继续只描述该原始实现及原输入域。当前运行适配不回写旧清单，也不把旧证书扩展为新输入域的验证结果。

## 参数与论文对应

依据固定[论文 PDF](../../papers/2025_efficient_ibs_jia.pdf)（SHA-256 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`）Table 3、§5.1、Tables 4–7。原始数值由 [paper_profiles.py](../../experiments/research/candidates/srgg/paper_profiles.py) 保存。

| 预设 | 环次数 n | 模块秩 k | p | gadget 基／位数 | Q=p·31² | γ |
|---|---:|---:|---:|---|---:|---:|
| PARAM-I | 512 | 2 | 16383 | 31／2 | 15744063 | 42086491.7 |
| PARAM-II | 512 | 3 | 16383 | 31／2 | 15744063 | 63653172.0 |
| PARAM-III | 512 | 4 | 16383 | 31／2 | 15744063 | 86573930.5 |

共享配置保存完整选择 `{"profile_name":"PARAM-I","interpretation":"table-standard-deviation"}`。数值由固定算法版本确定，原语对象同时保存完整数值、来源和解释。两字段均必须存在，拒绝额外数字字段、未知档位和自动解释。多个预设没有隐含默认值，调用者必须明确选择。

主测试使用 `table-standard-deviation`；原实现的 `literal-density-width` 仍可在完整参数 JSON 中显式选择，二者对象不能混用。本批验收不据此宣称另一种解释也完成了完整 LATTE 实测。factor1 与旧 `srgg2025` 的 degree8/factor2 是不同参数路线，不能交叉加载或继承结果。

## 接口与固定身份

[公共描述符](../../src/ibme/ibs/srgg/paper_registration.py)负责静态参数、容量、延迟对象读取和明确的 Sage 依赖；[五方法适配器](../../src/ibme/ibs/srgg/paper.py)调用原 `Setup/Extract/Sign/Verify/load_signature`。不改变原 `paper_backend`、FixedIssuer、H1/H2、Gaussian 精度、中止或重复提取策略。Sage 缺失时可发现入口和计算容量，执行明确报依赖错误。

原语身份上限 4096 B、消息上限 65536 B。公共 IB-ME 的最终输入容量仍由协议编码、HIBE、Hybrid 预算共同决定；原语消息包含协议身份、绑定和长度字段，不等于应用原始消息。

原始 MasterSecret 保留 `pending/failed/issued` 状态，重复同址提取复用已发密钥，失败地址不能靠重试重新发钥。公共 CLI 沿用既有持久事务和整套 Suite 绑定，不增加另一个发钥服务。

## 编码与容量

公钥、主私钥、用户密钥沿用原规范 JSON；公开上下文的生成方式不变。`reference` 为原 JSON 签名；`compact` 仅将签名边界换成已交付的无损 bit-pack 编码。两者各自严格解析，不自动尝试另一种格式。

compact 适配器在原 codec 的参数／上下文／维度／规范编码检查之外，执行原签名范数上界。公共容量按每坐标绝对值不超过 `floor(γ)` 保守计算，不能用某次短签名代替所有合法签名的上界。最大坐标同时出现不必构成合法签名。

本批六种 LATTE 组合统一显式使用 128 KiB Hybrid 明文载荷预算。独立 CLI 的 PARAM-I compact 使用框架原有 64 KiB 预算。两种预算均完整保留签名和消息；没有截断、压短哈希或降低论文参数。

## 运行与声明

需要规定 WSL conda Sage 环境以及从仓库冻结源码构建的 LATTE 引擎；完整安装必须包含 `experiments.research.candidates.srgg` provider，不能仅复制 `src`。入口缺失时不回退教学参数或 mock。

沿用项目已确认的论文安全性／HIBE 匿名性工作前提，理论引用原文。`PARAM-I/II/III` 三个冻结论文档已完成公共接入和组合验收，按 2026-10-20 用户决定登记为 `security_claim=secure`、`backend_admitted=true`、`parameters_are_formal=true`。NIST category 仍为空，论文作者报告的目标位数不转换成本项目的外部认证等级。完整组合实测和源码指纹见[本批记录](../research/2026-10-19-srgg-paper-latte/README.md)。
