# SRGG 原文验证矩阵的像与核：独立代数核验

本交付只核验原文算法 7–8 的完整模 2Q 线性映射，不计算短向量、伪造成本或安全强度。依据是仓库冻结的 Jia 等人论文（SHA-256：258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152），算法 7–8 见 PDF 第 7–8 页；共同参数见第 9 页和表 4。代码与 17 项小环测试分别在 ../../../../experiments/research/candidates/srgg/paper_verification_image.py 和 ../../../../tests/test_srgg_paper_verification_image.py。

原文取 A=[I_d | Â | B]，列数 (2+w)d，w=2；验证矩阵为 [2A | Q ζ* e1 − 2h] 模 2Q，其中 ζ*=1−X^(n/2)。算法 7 第 5 行定义 b=Qj−2H(id)，算法 8 第 2 行直接使用 b 而没有重写其计算；这里按前一算法的定义展开，不把这处省略当作新的协议步骤。n=512、p=16383、q=31²=961、Q=pq=15744063，故 2Q=31488126；d=2、3、4 分别对应原文 PARAM-I、II、III。

因为 Q 为奇数，系数 CRT 给出 R_(2Q) ≅ R_2 × R_Q。模 Q 时 2 可逆且 A 含 I_d，像为整个 R_Q^d，与 Â、B、h 无关。模 2 时 2A 和 −2h 消失，剩下 ζ*e1；在 R_2=F_2[X]/((X+1)^n) 中，ζ*=(X+1)^(n/2)，其像理想与零化子都具有 n/2=256 个 F_2 维度。由此得到：

| 原文行 | d | A 列数 | 模 2 像维数 | 完整余域中的像指数 | 核大小 |
| --- | ---: | ---: | ---: | ---: | --- |
| PARAM-I | 2 | 8 | 256 | 2^768 | Q^3584 × 2^4352 |
| PARAM-II | 3 | 12 | 256 | 2^1280 | Q^5120 × 2^6400 |
| PARAM-III | 4 | 16 | 256 | 2^1792 | Q^6656 × 2^8448 |

这些“像指数”和“核大小”针对所有模 2Q 的响应，并未加原文签名范数界。回执中的模 Q coefficient_image_dimension 和 coefficient kernel exponent 是模 Q 的系数个数或自由模秩，不是复合模数 Q 上的向量空间维数；只有模 2 项使用 F_2 向量空间维数。很大的像指数也不是攻击成本或安全位数。

复现方法：在仓库根目录的指定 WSL Sage 环境运行：

    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.paper_verification_image
    PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_paper_verification_image.py
    python docs/research/team-b-delivery/2026-10-18-srgg-verification-image/verify_delivery.py

本次 17 项测试通过，0 失败；测试包括 n=4/8、d=1/2、复合奇数 Q=15 的独立 Sage 整数矩阵 Smith 不变量核验。该回执与当前源码重新运行输出逐字节相同，SHA-256 为 be582a4920c703b3569f3e42349cd62f9e868acf80b244a80ef8fff9b5e3b17c。包内 MANIFEST.json 绑定回执、说明、校验器、源代码、测试和论文；自身不自哈希。

范围边界：原文定理的 q/Q/2Q 对应、可接受 Setup 根和带种子的实际公开矩阵分布、短核向量与伪造成本、环 HNF/MSIS/CRT/子域结构攻击成本及正式困难性位数、完整发钥/签名/故障历史、已知 native strong 同消息替换，都没有由本代数计算解决。原语仍为研究实现；security_claim=none、backend_admitted=false、parameters_are_formal=false、nist_security_category=null。功能测试不能替代安全归约。
