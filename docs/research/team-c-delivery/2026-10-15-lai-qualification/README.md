# C1 Lai：可执行资格核验（WIP，非 HIBE 后端）

基线 `8ba7ebfb560804481a0245f6e85621fe69c13511`。本批把上一轮临时观察改成可复验代码和15项测试。原文为用户提供的18页版本，SHA-256 `0985cb1d8cc760a18070a38d30b8de5b532bca52b5c06e05e65b2d712bdf338c`；未擅自补写作者未展开的两层算法。

## 原文与实物

| 位置 | 复核事实 / 执行结果 | 影响 |
|---|---|---|
| PDF5 §2.2 / Theorem1 | n为2的幂，q≡1 mod2n；环在模q下完全分裂 | 非零环元素不一定可逆 |
| PDF10 Algorithm4；PDF11 Algorithm5；PDF12 Algorithm7 | 输入只写非零tag，后两者实际使用h⁻¹ | 必须明确单位域或失败事件，不能默认为域除法 |
| PDF15 Decrypt | 仅排除h′=−hid；令hid=1、h′=(x−a)−1，零检查通过但标签和不可逆 | 原检查不能排除零因子 |
| PDF13 Algorithm9 | 输入长度m+k，打印R为(m+k)×k；方程aᵀR=h′gᵀ−a1ᵀ要求R为m×k | 输入/输出类型不一致；不能照印刷维度进行乘法 |
| PDF12 Algorithm7 | 输出x长度l+k，打印目标格却以a0（长度l）定义 | 必须先澄清目标格类型 |
| PDF14–15 §5.1–5.2 / Theorem10 | 原文解释INDr包含收件人匿名，但只展开IBE，HIBE以Derive=Extract概述 | 两层公开向量、身份编码、加密与噪声维度须落实后才可实现HIBE |

在R=F17[x]/(x⁸+1)中，x−3非零且不可逆，存在显式非零湮灭子；单位数为16⁸，总元素17⁸，非单位比例为2680790145/6975757441。测试还独立检查(n,q)=(2,5),(4,17),(16,97)。这些是代数输入域反例，不是对所有论文参数的安全攻击。

维度检查给出必要类型链：若根前缀l=2、gadget k=5，则根/父/叶公开向量长度7/12/17，相应陷门为2×5、7×5、12×5。它只说明真正两次扩展所需类型，不能将这张表称为已经实现Derive或匿名HIBE。
此l<k例子也不满足Algorithm4对R列线性独立的要求；它仅用于类型运算，不是可生成参数。

## 执行与下一步

```sh
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest tests/test_lai_qualification.py -q
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.lai.qualification
```

实际15 passed / 0 skipped；原始输出见evidence。无消息、身份、密钥或Gaussian生命周期；重复每用例1次，教学环参数；Sage10.9 / Python3.13.14、WSL2、Intel Core Ultra9 275HX。没有使用ROM或建立新的安全结论。保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`。

未采用“只采单位”、扩大q或补造身份扩展：前者改变分布，后者需要有限失败/查询预算和完整算法映射。所需原文/证明映射仍未闭合，本线不登记可用后端，不占完整HIBE数量；按总计划停止条件，主编码转无依赖的C3核验与研究实现。

修改：`experiments/research/candidates/lai/qualification.py`、`tests/test_lai_qualification.py`、本交付材料。CI仅将此路线标为qualification_only并注明范围；统一框架仍显示后端不可用。
