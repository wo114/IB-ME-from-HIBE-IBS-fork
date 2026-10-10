# 首套接入第二轮：不透明HIBE密钥与公钥绑定

日期：2026-10-10；基点 `f64b83d`。开工时工作树干净，远端无新增提交/开放PR，上轮CI run38032041344已成功。用户说明队友需要更久，本轮继续主AI可独立推进的首套适配工作。

**修复包装层接受同参数但不属于所声明公钥的秘密对象，以及未核验私钥方程的问题。** 修改前8项新增检查全部失败：三类秘密对象混入另一公钥的底层密钥仍能加载；一级/二级私钥系数损坏仍被接受；运行时没有在随机采样或胶囊解析前拒绝这些密钥。它们是接入/语义一致性缺口，不描述为新的HIBE密码攻击。

本轮新增28项检查；与上一轮状态组共46项，原Hybrid/两种IBME格式完整组88项，Windows与指定WSL各134 passed，无最终失败/XFAIL/跳过。实际JUnit摘要、源指纹与15个文件清单见 [验收记录](audit.json)。

## 1. 如何修复

原HIBE七个方法保持，引入独立公开能力 `HIBEKeyBindingValidator.validate_key_binding(public_key, secret_key) -> bool`。Hybrid构造时取得原语方法，或允许显式注入同形验证器；缺失、不可调用即拒绝。只有Python字面True允许继续，非True和异常都明确失败，没有默认放行。

协议层只传入不透明公钥/秘密对象，由原语在自己模块内处理。它不读取陷门、私有矩阵或自行重做原语代数。加载失败映射SerializationError，运行时InvalidParameterError；未通过检查时不产生后续采样或解析胶囊。

检查覆盖：Setup/Extract/Derive新产物；主密钥/两级私钥的绑定加载器；Extract/Derive/Decrypt运行输入。Generic数据类的规范解析不独立授权使用，实际绑定加载器和运行路径仍执行上述检查。

ABB10教学验证器复用既有Trapdoor.public_matrix、verify_level1_key及verify_level2_key：

- 主密钥：元数据/u匹配，内部重建公开A并与所声明公钥比较。
- 一级：同一根A/u/元数据，再检查A·R1+G=H(parent)。
- 二级：同一根A/u/元数据，再检查[A|H(parent)]·R2+G=H(parent,child)。

这些只是可核验的代数与公钥/身份一致性。它们不证明短向量范数条件、Gaussian来源、分布、匿名性或参数安全。未修改ABB10的生成/委派/加解密数学算法。

Mock仅配合接口回归：检查可验证的公开种子/限额及二级公开派生值；一级未使用的秘密链无法从公钥核验。Mock仍为TEST-ONLY，不能作为CHKP或安全实例证据。

合法旧wire、KDF/AAD、身份顺序、IBS输入/两种格式与同一串行操作序列的随机输入保持。先前可规范解析但不满足绑定关系的密钥现被拒绝。

## 2. CHKP接入约定

已更新[队友任务书T4](../../workplans/2026-10-08/队友任务-CHKP与格工具.md)。CHKP验证器应在原语内部核对根公钥、身份路径、完整基和解封装原像等可核验关系，不能只比较参数标签；不得消费随机性。可以采用方法或显式验证器，协议不需要了解其矩阵字段。

新能力是Hybrid接入要求，不改变原HIBE方法，也不要求队友重写基础安全证明。本轮只在已有ABB10教学/Mock组件增加验证入口，没有修改队友CHKP/格工具或把它们替代成空后端。

## 3. 验证证据

新增28项覆盖：同参数两组真实公钥/主密钥与两次委派；秘密对象跨公钥混装；私钥方程/公开u损坏；外层和底层一致修改身份后的方程失败；原语输出非法密钥；验证器缺失/非True/异常；CLI外层公钥一致而内层主钥不属于该公钥。全部使用同一合法编码类型，不以魔数/类型错误制造拒绝。

两组真实密钥生命周期各1次；每个替换/破坏/故障注入各1次；固定测试流仅供复现，私钥只在pytest临时对象/目录，没有写入验收JSON。没有新密码性能、格攻击估算或安全位数结果。

原88项回归覆盖Hybrid大载荷、KDF/AES已知向量、四种匹配、完整字节篡改、底层容错对照、reference/compact真实签名、公开新格式冒名、持接收密钥重签及CLI恢复。上轮状态18项同时回归。134=46+88，新增28已包含在46内，不重复相加。

```text
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_hybrid_key_binding.py tests/test_research_state_integrity.py
python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_hybrid_hibe.py tests/test_luo_hybrid_ibme.py tests/test_luo_compact_ibme.py
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_hybrid_key_binding.py tests/test_research_state_integrity.py"
wsl -- bash -lc "cd /mnt/d/zcode_projects/ibme && ~/miniconda3/envs/sage/bin/python -B -m pytest -p no:cacheprovider -q --tb=short tests/test_hybrid_hibe.py tests/test_luo_hybrid_ibme.py tests/test_luo_compact_ibme.py"
```

环境：Intel Core Ultra9 275HX；Windows Python3.14.6/pytest9.1.1/cryptography49.0.0；WSL指定Sage10.9/Python3.13.14/pytest9.1.1/cryptography49.0.0。

## 4. 参数、范围与下一项

参数保持：HIBE n=8,m_matrix=168,m_bar=16,q=524288,s0=3,s=s_prime=1，编码身份86 B、种子32 B，仍教学；Luo N=256,(k,l)=(11,10),q=274877844481,κ=64等前轮研究配置；外部身份≤64 B、应用≤3924 B。来源为已有研究配置，没有继承论文/NIST等级。ROM/QROM声明没有提升。

跨HIBE公开验证能力、协议、测试及文档，是为了保持适配层不读取私有矩阵；旧原语内部本来已有对应代数辅助。本轮15个文件的精确路径在audit.json；未修改HIBE采样算法、Luo算法或队友保留源文件。

下一项继续首套必要接入/持久化条件，尤其正式HIBE的固定地址/解封装状态与CLI恢复衔接；队友交接到达时优先审阅并真实集成。其它候选深入与独立优化继续后置。

WIP：CHKP真实实现/合法选参、Luo模拟与分叉引用条件、首套安全准入；旧education两项认证反例仍存在。密钥一致性检查和功能回归不替代安全证明，全部security_claim:none/backend_admitted:false。
