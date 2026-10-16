# SRGG 四算法研究执行器独立审查

日期：2026-10-16。审查对象是新命名空间
`experiments/research/candidates/srgg/structured_execution.py`，不是公共后端、
持久固定发钥服务或已准入参数。审查过程只读实现；测试运行只生成单独输出收据。

## 审查结论

本次逐段源码检查和小维独立测试没有发现阻塞四算法研究执行的算法偏差。
本审查已核读执行器的首次 n512 完整生命周期收据及其八个直接 SRGG 源码哈希，
均与当前文件一致；没有重复运行 n512 抽样，也不把此前两次公开 perturbation
夹具升级为完整 IBS 证据。
本结论不等于无漏洞保证或密码安全证明。

### 参数与规模门

`ExecutionParams` 是新的严格类型，不是绕过原 `Params` / `Config` 的对象构造。
它检查精确整数、n 的二次幂和上限、模块维度、奇且互素的 p/b、Q 与系数资源、
公开 HNF 范数修正和 `Q²>4*signature_norm_cap`。原 Params 的 n≤8 门保留。

执行器 constructor 还在读取秘密熵前，为整个 CBD1 master 支持类及声明的完整
user norm cap 建立两种 `StructuredSampleF` 计划。该步骤检查严格 contraction、
isotropic target、series 项数、环乘工作、有理数 reserve、完整随机字节预算等；
没有只验零见证的实测谱范数后将其当作整个支持类。正式参数安全估计仍未完成。

### 算法链

`ExactRing` 使用 Sage ZZ 的精确负循环乘法。公开矩阵、陷门关系、raw relation、
HNF reconstruction 和签验关系均以模 Q 或 2Q 的精确等式检查，没有用浮点 FFT
或均匀分布代替 Gaussian 输出。

真实 gadget 路径不是确定性 b 进制分解：对当前 `state` 取 `a=state mod b`，
实际采样 `k~D_Z,r²,-a/b`，映射 `z=a+b*k`，随后执行
`state=(state-z)//b`。初始误差为 `target mod p`，最终逐系数检查
`p*sum b^j*z_j = target-error mod Q`。有限 Z kernel 与旧 CDF tables 不相同；
证书明确披露该事实，并分别保留 finite/batch 和 ideal normalizer tilt 项。

发钥先真实 SampleF，再按公共矩阵计算 residual，再真实 gadget、构造 raw vector、
执行 raw norm 门，最后由公开 target 与 tail 重建 canonical head。重建后明确验证
`A*y=H1(ID) mod Q` 和完整 user norm cap。快照恢复不重新采样 head 或 tail。

签名使用 `zeta=1+X^(n/2)`、`zeta*=1-X^(n/2)`，因此 `zeta*zeta*=2`。
u 的中心是 `-zeta* * challenge/2`；扰动 shape 使用 factor2，签名矩阵、承诺和
恢复均在模 2Q 上。响应为 `p+(y,1)(zeta*u+c)`，恢复减去首块的 `Q*zeta* * c`。
这些关系与既有小维代数基线逐项比较，并独立检查恢复值等于原承诺。

### 哈希与失败语义

矩阵、H1 和 H2 有各自长度前缀、域分隔和独立研究版本。H1 绑定完整公钥与
identity；H2 绑定完整公钥、canonical commitment 和 message。H2 不额外包含
identity，与既有原语结构一致；identity 通过签名矩阵和 H1 参与恢复。不能把
H2 没有显式 identity 字段直接当作缺陷，也不能仅凭错误身份负控拒绝证明安全。

Setup 每次调用只取一个 root，没有按正定检查重选陷门。Extract 每次显式调用
只采一次；sampler、熵、raw norm 或 Key 验证失败向上传播。该原始算法没有缓存，
因此调用者主动再次调用 Extract 仍会再次采样；它不声称提供固定发钥语义。
Sign 唯一内部重试是 Algorithm 7 的 response norm 拒绝；SampleF、u sampler
和底层熵异常没有被转成 norm 重试。

`audit()` 使用系统 `SecureRandom`，单次根、单次发钥、一次签名请求；允许该
签名请求内的公开有限 norm 尝试数。全 audit 的 256 MiB cap 是额外工程中止门，
首次实跑收据明确标为 `audit_extra_abort_probability_certified=false`，没有在
实测时冒充已证明的整个服务中止预算。后续独立包络针对该固定单身份 audit
消除了全局 cap 的额外中止；它不推广为多查询持久服务的容量承诺。

### 快照与边界

Master/Key 快照仅在内存中往返。解析检查 canonical JSON、重复/多余字段、长度、
schema/kind、公钥和参数 context、checksum；恢复对象再次进行陷门关系或完整
重建/范数验证。checksum 仅检查意外损坏，不提供对恶意改写或回滚的认证。
本轮不声称磁盘 crash consistency、跨进程并发或持久服务恢复。

公钥和签名有研究序列化；没有把它们登记为公共 wire 接口。所有核心对象的 repr
遮蔽秘密值；audit 输出不含完整主私钥、用户密钥、随机种子或实际签名。

## 独立执行证据

指定 Sage 环境运行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_structured_execution.py \
  --junitxml=build/outputs/srgg-bridge-2026-10-16/structured-execution-independent-final-tests.junit.xml
```

最新独立结果为 **31 passed，0 failed，0 skipped，JUnit 4.913 s**。包括负循环乘法的独立
schoolbook 比较、小维旧代数方程比较、实际 randomized gadget、完整小维四算法
与两次内存恢复、错误 identity/message/context、非 binary challenge、维度、
损坏快照、重算 checksum 后错误 master 关系和过大 key 范数、错误公钥/参数、
非法独立参数、SampleF/gadget/u/熵失败不重试，以及仅 norm 失败最多重试到上限。
早期 27 项收据保留，没有覆盖或改写早期结果。

这是既有确定性测试夹具上的实现证据。负控未接受不证明一般不可伪造；小 n
挑战可枚举这一历史反例没有因此被删除。实际系统随机生命周期另由执行器
audit 收据给出，不能把测试夹具随机性改称生产随机性。

本次还重新核对 `structured-samplef-acceptance.md`：39 项独立 SampleF 测试的
JUnit 与描述一致；n16/n32-current 和 signature-n512 三份收据所列已加载项目
源码的当前 SHA-256 全部相符。n512 master 收据缺少事前源码快照这一限制也在
acceptance 中保留，没有向旧收据补造来源。

另核读 `structured-execution-n512-d2w8.json`：`completed=true`，诚实验证、
错身份/错消息/随机小响应与随机二元挑战负控、两种内存快照相等均为真；
仅一次发钥、一次签名尝试，实际消耗 `15099738 B`。KeyExt 14.021 s、恢复后
Sign 15.190 s；这一次系统随机性生命周期不是重复性能基准。

## 已反馈建议的落实与单次审计包络

已重新核对实现者对非阻塞覆盖建议的处理：

1. 已新增重算 checksum 后仍不满足 master 关系或 key 范数的拒绝测试。
2. 已新增 gadget 与 u 异常传播、不重抽，以及 norm-only 尝试上限测试。
3. audit 的随机负控已改为系统熵生成的 CBD1 小响应及随机二元 challenge；
   仍只是一种有限负控，不能称作覆盖所有随机签名攻击。
4. 执行收据已扩为八个直接 SRGG 源码哈希；其余公共 hash/randomness 等依赖仍需
   由最终完整 MANIFEST 冻结，不能仅凭八个哈希宣称冻结所有间接依赖。

保持格式合法的单个位 challenge 翻转及单个 response 系数篡改属于可继续补充的
定向覆盖，本审查没有把错误身份、错误消息和随机负控改称这两类测试已完成。

独立后验 `structured-execution-entropy-envelope.json` 的输入收据哈希、八个
源码哈希均已重算匹配；最大调用次数乘每次字节 cap 的和也已独立重算：

```text
32+32768+10503886+7651821+16*(11020294+642980)+11264
=204812155 < 268435456 B.
```

已核对读取路径：Setup 两次固定读取；joint SampleF 的 cap 已含 midpoint
tickets；gadget 与 u 各用读前检查的 AggregateByteSource；负控仅一次固定读取。
所有本地 abort 都结束 audit，只有签名 norm 拒绝最多重试 16 次。因此在源码
所述读取语义下，全局 cap 不会先于本地 cap 触发，本次单根、单身份 audit 的
额外全局 cap 中止上界为 0。原始收据保守 flag 原样保留；本地 sampler cap 的
中止仍在各自完整 TV 中。这不处理基础设施故障，也不是 2^40 查询服务包络。

## 结构化整数采样到 HNF/查询账本的独立核对

本次还只读复核 `integrated_bridge.py`，并执行：

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
  tests/test_srgg_integrated_bridge.py \
  --junitxml=build/outputs/srgg-bridge-2026-10-16/integrated-bridge-independent-tests.junit.xml
```

结果 **11 passed，0 failed，0 skipped，4.06 s**，包括零熵构造实际 n512
class plans 与完整 composition 账本；没有再采样密钥或签名。

实际发钥先对 raw vector 设范数门，再 HNF repair，最后对完整 user vector
设范数门。raw 门不是仅依赖输出 Y 的公共门。因此与仅使用公共 Y 范数门的
mixed-domain reference 比较时，须另付 ideal raw-tail，不能全部按共同门的
data processing 零代价处理。当前代码已如此修正：

```text
key TV <= finite SampleF/gadget-and-recurrence TV + convolution TV + raw-tail;
actual key abort <= finite TV + convolution TV + 2*raw-tail.
```

第二行保守重复计一次 tail，代码已明确披露。构造器检查的
`user_cap >= 2*raw_cap+2*dn*(p-1)^2` 保证 ideal raw 范数门通过时，HNF
后的 user 范数门也通过，故 public user-gate 的理想拒绝可由同一 raw-tail 控制。
完整 TV 保留 abort 原子；没有通过按成功条件化把 sampler 中止删掉。

mixed-domain atom 界计入 canonical head 的模 Q aliases；没有把全局 wrap
概率当成小原子误差。给定公开 target 的理想未过滤 atom 上界经公共 Y 门不会
增加，实际成功 key 的上界使用修正后的完整 TV，并明确除以实际成功下界。
这些只是 entropy/regularity 对应，不等于 source PSF one-wayness。

签名 norm 界对每个给定 perturbation 的适应 challenge 使用统一 shifted-lattice
scalar 尾界，再与 perturbation 尾界作 union；没有假设 challenge 和扰动独立，
也没有把最终 signature 认作 Gaussian。L 次全部 norm 拒绝使用逐可达历史的
统一条件界及新鲜熵，消息/密钥无需 iid。有限 sampler abort 被完整 coupling
TV 控制的结论以正确 MPFR 运算和公开 arithmetic invariant 假设为前提；库、
硬件及其它基础设施故障没有凭空赋一个小概率。查询 ledger 的条件算术模型
不表示对真实“基础设施/额外 cap 成功”事件事后条件化后仍维持旧输出 law。

独立命名空间与旧 finite law 的区别已披露。研究整数 sampler、公开 mixed-HNF
reference 及逐查询误差/算法中止账本可在所列假设下串联；source Gaussian-secret
SIG/PSF 与 mixed-domain one-wayness、适应 IBS/strong 安全归约、真实持久服务
容量/基础设施模型、正式困难性估计、公共接入和实际 HIBE 配对仍未由本审查
闭合。安全标志保持 `none/false/false`，没有 NIST 或 Kyber/ML-KEM 等级声明。
