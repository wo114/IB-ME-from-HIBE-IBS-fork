# 显式进程内接收会话

`ibme.protocol.prepared.prepare_receiver(proto, public, receiver, sender_id)`适用于原始Baseline／BYTEAUTH和内置Suite装配的相同协议。未知子类拒绝，避免克隆时遗漏附加检查。原Lai后端及默认CLI保持无状态。

准备时先通过原后端的公共`validate_key_binding`检查根和第一层密钥，执行一次真实`derive`，再检查叶钥根及`(receiver, sender)`路径。Hybrid的公共绑定入口复用其原有内部绑定检查，并比对所请求根的上下文。准备成本包括验证、真实委派和额外叶钥编码长度统计。

会话固定一个公钥、接收者和声明发送者。`session.decrypt(wire)`调用相同协议类的原解密方法，仅将这条固定路径的Derive换成已准备叶钥；Suite输入／参数绑定、严格wire解析、BYTEAUTH、Hybrid解密、IBS验签及OTS承诺仍逐次执行。不会因为失败自动重新委派。

用`with prepare_receiver(...) as session:`或显式`close()`限制生命周期；关闭后再调用解密抛出异常。会话拒绝pickle持久化，`repr`隐藏秘密，公开`info()`只含作用域、叶钥编码字节、解密调用数及关闭标志。关闭会释放引用，Python／Sage不保证物理内存清零。会话保持原公钥／接收者对象的引用，调用者在其生命周期内不得修改这些组件。

这是应用层保留秘密状态的明确选择，不是新HIBE／IBS路线，也不能将其重复解密成本写成原无状态算法每次解密成本。报告必须单列首次准备成本、额外状态和累计摊销曲线；相关Suite保持`none/false/false`。

其它准备复用：CertifiedIBS最多保留256条完整公开证书验证语句的成功结果，默认64条；消息签名始终重新验证。SRGG论文后端默认最多保留2条、上限16条同一冻结签名密钥的SampleF计划，`clear_sign_plan_cache()`可释放引用。每次SampleF.sample仍创建新熵预算，不保留随机样本；清空不保证物理清零。两种缓存的配置入口以0关闭，供同源码消融使用。
