# 发钥参考、范数拒绝与固定服务总账本

日期：2026-10-16。实现：[oracle_ledger.py](../../../../experiments/research/candidates/srgg/oracle_ledger.py)，独立审查见 [psf-review.md](psf-review.md)。以下是分布与条件概率推导，不是密码学归约或 NIST 准入。

## 共同 HNF 门的参考不需要移位误差

令 `A=[I,Ahat,B]`，`k=dn`，`N=(2+w)dn`，`Σ` 为固定公开目标形状，

```text
S_h = {x in Z^N : h-Ax mod Q in {0,...,p-1}^k},
U_h = D_(Z^N,Σ) conditioned on S_h,
R_h = norm_gate(HNF_h(U_h)).
```

HNF 根据 tail 重建居中头部，norm_gate 返回合法完整向量或中止原子 `⊥`。参考 `R_h` 仅依赖公开 `A,Σ,h,p,Q`，没有使用陷门；压缩 tail 对象由同一个确定性编码得到。这个参考可用于精确陈述“同一公开 A 下实际发钥 law 对陷门的依赖受到控制”。如果两个合格见证对应同一 A，两者 law 距离至多分别到共同参考距离之和。

设实际有限 sampler 到理想 perturbation／gadget 顺序算法的 **raw 阶段** TV 至多 `δ_fin`，理想 raw 到 `U_h` 的卷积 TV 至多 `δ_conv`，则

```text
TV(actual_complete_key_law,R_h) <= δ_fin+δ_conv.
```

两边同时执行 HNF 和同一个 norm 门，故这是数据处理不等式，norm 拒绝不能在这条 TV 中再加一次。中止质量一直保留，没有成功条件化。代码从 perturbation 和 gadget 两个原始 hybrid 上界相加构造 `δ_fin`；没有从处理后的 TV 反推 raw TV。

这项结果不自动说明 `R_h` 等于冻结论文 `PSF.SampleDom | f=h`。零中心 exact-fiber Gaussian 是另一参考，其比较仍需修复移位、head-wrap 和相应范数门误差。工具同时报告二者，避免将约 `0.35` 的 n8 exact-Gaussian 上界混作较小的共同 HNF 门上界。另一个可研究的全局混合域见 [mixed-domain.md](mixed-domain.md)。

## 发钥的真实范数拒绝

对误差 `e in [0,p)^k`，修复及头部居中给确定性界

```text
||HNF_h(x)||² <= 2||x||²+2k(p-1)².
```

因此用户门 `||key||²<=B` 的理想拒绝概率至多是 `U_h` 满足
`||x||²>B/2-k(p-1)²` 的概率。`psf_bridge.norm_tail_upper` 在完整核格 smoothing 成立时，对每个 coset 和有限 union 用 Gaussian MGF 的相同 normalizer 比给界。于是

```text
P[actual issuance abort] <= δ_fin+δ_conv+P[ideal union HNF norm reject].
```

这给的是不含外部熵源、文件系统及硬件故障的算法中止上界。它不是观察到的失败率；某项上界为 1 表示该界无用，不表示系统必然失败。

## 自适应 challenge 下签名范数尾界

令 `pvec` 为理想 perturbation，`c=Hbar(commitment(pvec),message)`，
`u ~ D_(Z^n,r,-ζ*c/2)`。给定 `pvec,c` 后令 `v=u+ζ*c/2`，则 `v` 是中心为零、定义在 shifted `Z^n` 上的 Gaussian。由 `ζζ*=2I`，实际响应精确满足

```text
z = pvec+T ζ v,
||T ζ v||² <= 2β||v||²,  β>=||T||op².
```

选择 `α=j/32`，`j=1,...,31`，分别设
`Pcap=α² Bsig`、`Vcap=(1-α)² Bsig/(2β)`。两个 cap 同时成立时由三角不等式 `||z||²<=Bsig`。使用逐中心一致的 shifted Gaussian 尾界，故不要求 challenge 与 perturbation 独立。遍历 α 只是有限证明参数取最小，没有改变签名 law。

扰动形状 `Σp` 满足 `r²I≼Σp≼Σtarget`；标准整数格 smoothing 给 MGF normalizer 界，公开最大目标宽度给谱上界。加一次实际到 sequential ideal 的签名尝试 TV，便得到逐历史、逐合法密钥的实际范数拒绝上界 `ρ`。这不识别最终签名为独立目标 Gaussian，也不建立 HVZK、熵、UF-NMA 或 strong 前提。

## 查询和尝试预算

固定服务对每个新身份仅发钥一次，缓存命中不新增 sampler 调用。设至多 `qE` 个新身份、`qS` 次签名，每次最多 `L` 次 **仅因范数拒绝** 重试；内部 sampling/entropy abort 立即终止。逐历史实际采样 abort 界为 `aS`、范数拒绝界为 `ρ`，则

```text
P[one signature abort] <= L*aS+ρ^L,
P[service algorithmic abort] <= qE*aE+qS*(L*aS+ρ^L),
TV[transcripts] <= qE*δE+qS*L*δS.
```

这里使用的是每次尝试 fresh entropy 和任意过去历史下都成立的条件界，不需要假设用户、消息或查询独立。参考系统执行相同哈希、固定状态和重试策略，只替换已明确的采样核。它还不是已经证明可用的安全游戏模拟器。

原始两组 n8 profile 仍使用 legacy runtime 的 Gaussian abort 24 bits 默认值。width3 配置一次发钥到共同门参考 TV 约 `2.8613e-6`；16 新身份和 1 次最多 16 尝试签名时，条件算法中止界约 `1.0682e-4`。对 `2^20` 或 `2^40` 次签名，现有 transcript／中止上界均会成为 1。提高另一项 tail/ticket 位数不会消除 runtime 默认 abort 的这个问题。

完整数值见 [oracle-ledger.json](oracle-ledger.json)。`full_service_abort_upper=null` 明确表示基础设施概率模型未给出；锁、fsync 和故障恢复测试不能凭空提供这一概率。
