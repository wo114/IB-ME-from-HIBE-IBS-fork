# 固定源码审查

基点10563a6；原语实现14c44a6，目录断言cf48c28。按源码、官方向量、负例和收据进行人工审查；不将测试写作形式安全证明或Code Review集成的自动审查结论。

- 18份MIT原文件及两个来源包固定hash，0 vendor补丁。编译固定FPEMU/非AVX/非FMA，keygen不用ChaCha变体，关闭OS熵；KAT driver与生产metadata区分。
- 直接调用作者keygen/sign/verify；BNN只有原一份backend.py，原ML-DSA/native字节不变。密钥由冻结算法ID、独立头/尺寸/解码与完整参数证书绑定区分；descriptor配置拒绝跨家族参数。
- 恢复核验完整整数fG−gF=q及原keygen两范数；F损坏而h不变必须失败。公共系数<q，签名解码拒绝负零/非零padding/其它格式，验证另查方程与范数。
- 发钥前检查engine，pending先于熵/生成；回调/熵/原生异常保留pending，禁止换seed自动重发。锁、同身份并发一次、容量和零熵恢复均实测。
- 生产32 B种子与官方48 B TEST输入分离，普通driver拒绝KAT操作。验证/恢复不取熵，不按wire导入模块；流计数和进程超时为中止，无隐式fallback。
- 237项Falcon、246项ML-DSA与公共框架已实跑；两档实物和仓库外五份已存状态通过。200例官方样本含1次必需的padded重采样。95个源码/工具/测试指纹与Git blob一致。

处理了描述符测试字段误写、CI仍将Falcon计为无测试的旧断言及WSL缺构建依赖。失败记录与最终收据分开。当前无已知阻断独立原语交付的问题。

保留限制：完整强UF/量子/腐化/固定服务游戏、整体TV/RD及中止查询损失、安全估计映射、侧信道/秘密擦除和外部状态认证/防回滚未完成。默认登记/实际HIBE组合未执行。继续none/false/false。远端检查须针对PR最终head，合并时匹配该head；最终状态在PR中核对。
