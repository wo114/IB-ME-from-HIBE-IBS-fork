# SRGG 本地 WIP：完整诚实服务比较与归约进展

2026-10-16，基于本地 `f3831ac`。**六项联合目标仍未完成，不推送、不更新 PR。**
用户要求全部与 HIBE 选择无关的工作完成后再统一 fork＋PR；本批仅保存可审查的
本地研究结果。native strong 赢法保持原定义。

```text
security_claim=none
backend_admitted=false
parameters_are_formal=false
nist_security_category=null
```

## 已经取得的结果

| 材料 | 已完成范围 | 实际限制 |
|---|---|---|
| [诚实服务 law](honest-service-law.md) | 同一完整 oracle 下，有限发钥/签名到指定 latent/顺序 Gaussian 参考的整个 API 轨迹界，含固定缓存、恢复、相同故障和 cq 提升 | 同故障比较不是零故障概率；未知外部历史需联合 delta_hist |
| [完整 seed 预历史](seed-prehistory.md) | 包含未来 public 的 matrix/H1/H2 切片；经典 q/2^256、量子保守 2q/2^128 | seed 必须新鲜独立；不解决公开 seed 后的目标 H1 编程 |
| [独立 H1 整行比较](quantum-row-switch.md) | 保留 hash bytes、固定 key/bottom 的一般 4q√delta 引理与 minorization 改进；同参数更紧 theta 界 | 不适用于 semi-constant 共享外部目标的相关行；不是完整目标模拟器 |
| [uniform ring-HNF 条件归约](ring-hnf-review.md) | 系数相位、HNF normal-form 嵌入、diamond 界和 signed-polynomial 归约，明确复合环和 auxiliary 量词 | 需要新明确的 Gaussian NF-MLWE 实例及实际 aux 模拟；未完成其参数估计/量子实现 |
| [完整模数审查](full-modulus-review.md) | CBD1 公钥完整 Q、mod9、联合 CRT 的统计下界，以及真实投影 law | 排除统计近均匀路线，没有找到可行的 CRT 攻击，也没有证明计算困难性 |

对于冻结 n512 研究点，fresh genesis、经典 byte-XOF 及同因果故障模型下，
2-key/3-sign 的指定参考距离不超过 2^-172；2^40 次签名的数学预算示例不超过
2^-134。它们不是执行过相应次数的服务验收，也不是 IBS 攻击优势。

H1 的同参数 ideal image 比较重新计算未舍入 theta 界，得到 dual mass
<2^-613、minorization 污染量 <2^-612。在 **q_row<=2^40** 的整行查询预算下，
该项距离 <2^-265。raw byte 查询与首次发钥一般各需最多两次行查询，必须按
正文换算；不能把 q_raw=2^40 自动当成 q_row=2^40。有限实际 sampler 的费用
另由经典 API 的 cq 比较线性支付，不用理想 image 数字代替。

完整 Q 的公钥统计均匀化已被严格排除：任意固定 Ahat，
`TV((Ahat,V),(Ahat,U))>=1-(9/Q)^(dn)`。新候选在 mod9 也有
`TV>=1-2^-96-2^-192`。这些是统计事件，不是高效区分器；计算 Module-LWE
及实际结构攻击的评估仍是必要工作。

## 真正阻塞完整交付的事项

1. **目标身份与签名的完整安全模拟。** 尚未证明 QROM chosen-identity H1、
   目标 Sign、其它身份 Extract/Sign 历史和提取测量能够在同一实际游戏中联合
   模拟。上面的独立行比较和 uniform-HNF 条件定理都不能替它填零。
2. **合格的正式参数。** 已真实运行的 n512 点已有不足强度的通用攻击对照。
   未执行的 n2048/w22 候选 Q/√Bsig 约 2，不满足新相位归约在常规噪声下的
   收缩充分条件。当前没有同时通过完整归约、所有困难性估计及实际运行的参数。
3. **通过条件后的大维运行。** 执行器仍有 n<=512 等公开资源门；没有绕过后
   冒称 n2048 已运行。尚缺合格新候选的完整生命周期、攻击验收和资源实测。

教师要求的 Kyber/ML-KEM、NIST 对标仍是长期目标；不等于本方案已有类别。
继续增加条件工具或重复同一研究点测试不能关闭以上缺口。本批作为 WIP 本地
提交，明确保存已经证明/核验的子结果，不把它描述为 SRGG 全部完成。

## 实际验证与复现

本批指定 WSL Sage 的相关原有回归 **111 passed，0 failed/errors/skipped**：

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_psf_bridge.py tests/test_srgg_public_pairs.py tests/test_srgg_seeded_xof.py tests/test_srgg_service_budget.py --junitxml=build/outputs/srgg-joint-law-2026-10-16/sage-joint-basis.junit.xml
python docs/research/team-b-delivery/2026-10-16-srgg-joint-law/verify-image-precision.py --output build/outputs/srgg-joint-recheck/image.json
python -O docs/research/team-b-delivery/2026-10-16-srgg-joint-law/verify-image-precision.py --output build/outputs/srgg-joint-recheck/image-optimized.json
python experiments/research/srgg_proof_followup_delivery_check.py --delivery docs/research/team-b-delivery/2026-10-16-srgg-joint-law
python -O experiments/research/srgg_proof_followup_delivery_check.py --delivery docs/research/team-b-delivery/2026-10-16-srgg-joint-law
```

精确算术收据为 [image-precision.json](image-precision.json)，normal/-O 逐字节
相同；完整模数文稿内嵌算术也已执行。一般证明由 root 与三位 AI 代理交叉审查，
不是机器形式化验证或外部人类审计。完整命令、环境、原始收据和准确计数见
[validation.json](validation.json)，文件/冻结依赖见 [MANIFEST.json](MANIFEST.json)。

这些 111 项与以前的测试有重叠，不能加到旧 1266/37 项宣称新的全集；本批没有
重跑整个 SRGG 测试集。没有新生成密钥、签名、Gaussian 样本，没有运行量子
设备/模拟器，也没有大维新候选或重型困难性估计。零熵计算不使用身份/消息，
长度与随机重复次数不适用；有限测试不能替代安全证明。

原始输出保存于 ignored `build/outputs/srgg-joint-law-2026-10-16/`。本地镜像与
提交清单另保存到两工作目录的 ignored checkpoint；旧冻结包不覆盖。
