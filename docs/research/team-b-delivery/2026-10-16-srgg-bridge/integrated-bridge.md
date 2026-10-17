# SRGG：从实际整数采样到 HNF／查询账本

日期：2026-10-16。本项由 `integrated_bridge.py` 直接读取独立 `Execution` 的公开类证书，连接实际使用的 sampler，而不是把互不相接的工具数值相加。生成证书不取熵。所有界以列明的正确 MPFR／区间运算、独立均匀随机字节及公开 witness 类条件为前提；软件库、硬件或文件系统故障没有被赋予虚构的概率。

## 固定比较对象与逐步组成

令 `U~D_(Z^N),sI`，`S_h={u:h−Au mod Q∈[0,p)^dn}`，`Y=C_Q(U+JE)`，其中 E 独立均匀。由 [mixed-domain.md](mixed-domain.md)，`Y|AY=h` 恰好是 `U|S_h` 的 HNF 修复推前。公开输出范数门 G 作用于 Y，失败保留为 `⊥`；这个参考分布依赖公开 A、目标和固定参数，不依赖陷门。它尚未被证明是原文 SIG/PSF 安全归约所需的域。

发钥的误差链为：实际 joint SampleF → 理想 perturbation；实际 wide 标量 recurrence → 理想 recurrence；去掉 recurrence 的变化归一化分母 → 理想 spherical gadget fiber；完成平方及 C 归一化 → `U|S_h`；HNF 修复 → `Y|AY=h`；共同公开范数门。前两步的 finite law 包含 scalar、batch 和数值耦合坏事件，第三步与第四步各自承担不同的归一化操作，不能合并成一个未说明的误差项。

实际 `Execution` 还在修复前检查 `||raw||²<=R`。这个门不是 Y 的谓词：head aliases 使不同 raw 可以修复到同一 Y。移除这个额外门要另付理想 union 的 raw tail `t_R`，然后才能比较共同的公开 Y 门。因此最终 TV 为

```text
δE <= δmaster + δfinite-gadget + δrecurrence + δconvolution + t_R.
```

构造器要求 `Ucap>=2R+2dn(p−1)²`，所以 raw 门通过时，HNF 修复后必通过用户门。理想 Y 的用户门失败率也至多 `t_R`。模块保守输出实际发钥 abort `<=δE+t_R`：raw tail 被计入两次，换来统一且明确的共同输出门比较；这是充分界，未声称最紧。

签名写成 `v=u+ζ*c/2`、`z=p+Tζv`。给定 perturbation 和其决定的 c，v 是相应 shifted lattice 上的中心 Gaussian。`||ζ||²=2`、`||T||²<=1+(n/2)Ucap`，两项 MGF 范数尾界用半径分配和并集界组合；不假设 challenge 与 perturbation 独立，也不把最终签名宣称为一个已识别的球形 Gaussian。实际逐次范数拒绝率另加有限 sampler TV。

对每历史都成立的上界，令最多 L 次签名尝试：

```text
δtranscript <= qE δE + qS L δS;
asign <= L asampling + ρnorm^L;
aservice <= qE aE + qS asign.
```

新身份计一次真实发钥；固定服务命中缓存时不增加采样。`qE=qS=2^40` 是条件式调用账本，**没有实际建立能存储 2^40 用户的服务**。本批大维执行器也尚未接公共五方法／持久服务。基础设施模型未知时 `full_service_abort_upper=null`。

## n512/d2/w8 的已计算结果

参数由现有 `conditional_candidate` 固定算术点生成：`n=512,d=2,p=16383,b=31,w=8,r²=64`，`Q=13972913866395903`。master shape `s=1031865954433`；签名 shape `22159188660729268928705`；raw/user/signature 范数平方门分别为 `169060917974302720`、`338122385570209792`、`238255596480161099521436160`。不是论文 Table 4 参数，也不是正式安全参数。

| 数值配置 | qE=qS=2^40、L=16 的最终参考 TV 充分界 | 同调用量的条件算法 abort 充分界 | 2^-128 算术门 |
|---|---|---|---|
| default | 约 2^-69.9797 | 约 2^-69.9797 | 不通过 |
| query-bounded-deep | 约 2^-134.3759 | 约 2^-134.3759 | 通过 |

十进制指数只用于阅读，门判断由 JSON 内的精确 Fraction 完成。两列相近是有限采样保守项占主导的结果。该门不是 NIST 安全等级或密码学攻击优势界；未包含尚未建立的安全归约损失，也未含基础设施故障。

deep 配置为 MPFR1024、票据768、向量 dyadic384、series384、batch abort192，标量 tail192/mass256/precision384/Gaussian-abort192/uniform-trials256。选它来自三个公开配置的零熵预检；未按真实运行是否成功选择根或密钥。完整参数和原始分数见 [integrated-bridge.json](integrated-bridge.json)。

## 条件密钥熵：直接对 aliases 求和

对 isotropic 零中心 Gaussian，Poisson 零项给 `ρ_(sI)(Z^N)>=s^(N/2)`。单个 head 坐标的模 Q 格点和不超过 `1+sqrt(s)/Q`（单峰函数的峰值加积分/Q）；E 的独立平均不增加最大原子。结合 kernel smoothing 给出的逐目标像概率下界，有

```text
max_y Pr[Y=y|AY=h]
 <= min(1,(Q+ceil_sqrt(s))^H / s^(N/2) * (1+ε)/(1−ε)).
```

这是直接包含所有 aliases 的上界，不用先给全局 wrap 界再除以极小的目标像概率。`ε<=1/3`、`L0=floor log2(s)`、`B0=ceil log2(Q+ceil_sqrt(s))` 时，理想条件 min-entropy 至少 `max(0,L0*N/2−B0*H−1)` 位。本候选得到 **144383 位的理想分布下界**。

对实际成功发出的密钥，先用共同门参考的最大原子加 `δE`，再除实际成功概率下界 `1−aE`，得到 deep 配置 **至少177位的保守 min-entropy 下界**。这不是签名 commitment entropy，也不证明 one-wayness、碰撞困难或安全等级。运输证书只使用最多1024位的理想 atom 包络，保留完整理想位数供审查。

原文完整安全前提及新归约义务见 [theorem-obligations.md](theorem-obligations.md)。

## 复现与实验边界

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m experiments.research.candidates.srgg.integrated_bridge --output build/outputs/srgg-bridge-recheck/integrated-bridge.json
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q tests/test_srgg_integrated_bridge.py
```

本工具的两个配置为确定性零熵证书，各算一次，不取身份／消息，不进行 ROM 查询。一般界对每目标和所列公开类成立；具体真实身份37B、消息32B、1根/1身份/1签名的独立执行另见 [structured-execution.md](structured-execution.md)。环境、测试计数与交付哈希以本目录 validation/MANIFEST 为准。保持 `security_claim=none, backend_admitted=false, parameters_are_formal=false`。
