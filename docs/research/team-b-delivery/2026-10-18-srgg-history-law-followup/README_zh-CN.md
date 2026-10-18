> **v3 current (2026-10-18)**: the separate unguarded path has been removed. SourceSchurBackend now enforces the complete gate set (Setup root rejection/retry; signing-key abort), and srgg_paper_service.FixedIssuer defaults to it. The six roots below are deterministic witnesses; every bound in this package is for every plan that passes the complete gate set. Remaining nulls: P(A\\B), P(B\\G), accepted-root distribution, beta_bad, faulty histories. Security claim: none.

# SRGG 原表固定根：自适应历史概率界续审（WIP）

本批只处理 SRGG 独立 IBS，不改 HIBE、原论文算法、Table 4 参数或已有后端。新增 [证明与界限](proof.md)、[计算回执](history-law.json) 和 [证书程序](../../../../experiments/research/candidates/srgg/paper_history_law_followup.py)。原论文 PDF 的 SHA-256 为 258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152。使用 n=512、p=16383、b=31、w=2、Q=15744063、d=2/3/4，并保留表标准差与字面密度宽度两种解释。测试身份 Alice 为 5 B；本回执不实际签消息，证明中允许任意合规消息；签名历史示例计两次调用。

固定一把已验收 Setup 根，标准差解释下，首发钥界可对同根所有合规身份目标统一应用。按现有持久服务最坏情况字节包络，PARAM-I/II/III 最多可分别容纳 3/2/1 个身份。对最多这些首次发钥请求，用自适应核耦合得到发钥专属逻辑历史 TV 上界分别为 2^-24、2^-24、2^-24；重复请求、规范状态序列化及无故障重启只作共同确定性处理。字面密度解释的首发钥界仍为 null，不能推出小的发钥历史界。

同一冻结根的 Alice 密钥经过重新生成，签名 Schur 计划与已有有限链回执逐字段一致。对这**一把固定密钥**的所有合规自适应消息，单次签名调用的 TV 上界在标准差三组分别为 2^-19、2^-18、2^-18；两次调用分别为 2^-18、2^-17、2^-17。比较器保留原 Algorithm 7 的 64 次范数重试和中止；这些 TV 上界**不**给出范数耗尽本身的概率上界。字面密度三组当前的签名调用上界为平凡值 1。

两个界不能相加为“随机发钥后签名”的完整服务界：签名证书只对冻结的一把密钥成立，尚无对随机发出的所有可达密钥的统一 Schur 界或坏密钥质量界。所有可接受 Setup 根、磁盘故障、锁时序、回滚与完整签名历史分布也未闭合。原生 strong 已知同消息替换问题、论文符号冲突、结构困难性与 NIST 等级仍单列。标记持续为 security_claim=none、backend_admitted=false、parameters_are_formal=false、nist_security_category=null；功能与局部概率界都不是完整 IBS 安全证明。

回执使用冻结的六组确定性种子仅标识测试根；概率结论另需新鲜独立均匀字节、所述 MPFR 算术语义和无外部故障。系统环境写在回执中。运行：

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_history_law_followup.py
    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_history_law_followup --output build/new-history-law.json
    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python docs/research/team-b-delivery/2026-10-18-srgg-history-law-followup/verify_delivery.py

最后一条在指定 WSL Sage 环境运行；复算使用新的输出路径，不覆盖冻结回执。
