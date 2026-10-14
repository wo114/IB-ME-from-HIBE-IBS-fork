# Falcon v1.2 与 BNN 转换对应

| 原文 / 来源 | 本实现及核验 | 未推出的结论 |
|---|---|---|
| Falcon v1.2 §3.6 / Algorithms4–7，NTRUGen/NTRUSolve | 作者 `keygen.c`，n512/1024，q12289，环Z[x]/(x^n+1)；编码f/g/F，h=g/f；每次调用一个新32 B CSPRNG种子，官方测试另用48 B输入 | 有限熵扩展、时间/流中止与底层定理全部参数条件仍需总体映射 |
| §3.9 Algorithm10，PDF39页 | `falcon_sign_dyn` / `sign_dyn_finish`，nonce40 B、HashToPoint、ffSampling、范数拒绝、固定padded重试 | 不把裸签名大小、一次采样或性能写成完整IBS/IBME收益 |
| §3.9.2–3.9.3 / Algorithms11–15 | 参考FFT、FPEMU、Gaussian0/BerExp/SamplerZ、ChaCha PRNG；未用uniform替换Gaussian；原作者21组×100000样本诊断及半高斯自检实际执行 | 统计通过不证明精确高斯、总体TV/RD、QROM或侧信道安全 |
| §3.10 Algorithm16，PDF45页 | `falcon_verify`，s1=c−s2h modq居中、平方范数≤34034726/70265242；另有Python负循环乘法/HashToPoint/范数独立对照 | 独立方程对照不是SIS/NTRU安全证明 |
| §3.11 Algorithms17/18 | 压缩整数/负零/补零和重编码；生产固定padded长度666/1280，头0x39/0x3a；不猜格式 | 可变长官方样本中1例超出padded预算，必须实际重采样，不截断为“相同向量” |
| 作者20211101包/API说明 | SHAKE种子初始化含flip；18文件/包hash冻结；MIT声明保留；纯C源码0补丁 | Falcon v1.2不是FN-DSA/FIPS206；参考代码存在不等于生产审计 |
| 私钥恢复扩展检查 | trim_i8_decode→规范重编码→complete_private→整数fG−gF=q→原keygen两范数→make_public→证书验证；全程零熵 | h=g/f不能单独验证F；检查不能认证快照或证明原生成分布 |
| Galindo–Herranz–Kiltz2006 §3 / Theorem1（BNN重述） | 唯一 `backend.py`：Setup机构签名；Extract用户钥+ID/用户PK证书；Sign绑定上下文/身份/用户PK/证书/消息；Verify双签链 | 经典条件性引用不自动完成量子/强UF、多用户/腐化、固定状态查询损失或Wang认证准入 |
| 共同固定状态规范 | 同身份返回同SK/证书；锁、容量、pending、回调异常/熵失败不重发；相同快照恢复不用keygen/sign | 外部认证、防回滚、跨快照多写者和硬断电持久性由存储层负责 |

参考源：[Falcon作者站](https://falcon-sign.info/)、[普通API文档](https://falcon-sign.info/impl/falcon.h.html)、本地[规范PDF](../../../../papers/2020_falcon_spec_fouque.pdf)、[转换PDF](../../../../papers/2006_generic_ibs_galindo.pdf)、[完整接口规格](../../../specs/certified-ibs.md)。

有限运行边界：跨单元SHAKE extract累计16MiB、PRNG refill65536；同单元内部调用不保证全部拦截。Python超时限定完整进程1..300s；失败直接报NativeFailure，Extract保留pending。成功路径不变，不重新取种子。边界驱动测试实际跨过最后可接受调用，核对下一次中止。尚无全查询预算的可忽略失败上界。

两档均为作者标准Falcon参数而非教学缩小值。认证IBS与任何组合仍 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`，没有NIST等级/认证、正式强UF或完整量子安全主张。参数档、两个普通签名适配和通用转换不是三个新密码学创新。
