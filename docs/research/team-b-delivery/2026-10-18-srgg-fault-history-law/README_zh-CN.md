# SRGG 发钥、签名与故障完整历史审计（WIP）

本包只审计原论文参数下的独立 IBS；不涉及 HIBE，也未改变原论文算法、Table 4、后端或持久服务。[证明与代码路径](proof.md)、[六组回执](fault-history-law.json)和[可执行审计](../../../../experiments/research/candidates/srgg/paper_fault_history_law.py)共同界定结果。原论文为 Jia、Liu、Tang、Wang，*Constructing Efficient Identity-Based Signatures on Lattices*；仓库 PDF 的 SHA-256 为 `258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152`。论文没有定义这里的持久发钥服务或磁盘故障游戏，因此本包的概率命题是实现审计，不归作论文定理。

完整历史需要比较全部可影响未来的状态和可观察故障。若每个匹配历史上的完整微转移核都有统一 TV 界、全部签名所用密钥落在已认证 `Good` 集合之外的概率有界、并且初始根与持久状态的联合分布也有界，可用首次分歧耦合把这些误差相加；前提与条件式见证明。当前没有足够证据为 SRGG 填入这些数。特别是外部磁盘／锁／崩溃故障可插在采样中，不能把无故障的单次发钥界当成包含故障的转移界。

两个精确有限反例说明缺口：发钥分布完全一样，冻结密钥签名分布也一样，随机发钥后签名的完整历史 TV 仍可为 `7/8`；两侧无故障行为完全一样，若一侧确定发生可见读盘故障，完整历史 TV 为 `1`。这些是概率推理反例，**不是 SRGG 攻击**。原 PARAM-I 参数下另构造了一把能通过当前严格对象编码、却使签名 Schur 二次型严格为负的密钥。这把密钥不是实际 `Extract` 的输出证据，只说明“线缆对象有效”不足以替代随机发钥后的好密钥质量界。

现有服务的缓存重复请求、待处理标记、规范状态、无故障重启，以及既有测试覆盖的崩溃／损坏拒绝路径仍成立于各自范围。六组原表配置的**完整随机发钥／签名／外部故障历史界均为 `null`**。本审计按“主路线加最多两次换路”结束本问题：同带确定性重放、条件微转移耦合、精确反例；不继续盲试。保留前批无故障固定根发钥和单把 Alice 密钥签名的局部结果，不拼接成完整界。

复核环境为规定的 WSL Sage；审计程序只读取仓库中冻结论文和既有回执，不写私钥。参数共同部分：`n=512,p=16383,b=31,w=2,Q=15744063,d=2/3/4`，三组原论文 Table 4 宽度与 `γ` 不变，两种 Gaussian 解释分列。身份 Alice 为 5 B；本包不运行新的消息签名，证明中对合规消息作条件论证。它不是教学参数替换，但仍未经正式安全准入。`security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`；功能测试和有限反例不能替代原语安全证明。

运行：

```text
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_fault_history_law.py
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_fault_history_law --output build/fault-history-law-new.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-fault-history-law/verify_delivery.py
```

复算写入新路径，不覆盖冻结回执。`MANIFEST.json` 校验本批选定来源、测试与交付文件；它不声称包含完整 Python/Sage 导入闭包。
