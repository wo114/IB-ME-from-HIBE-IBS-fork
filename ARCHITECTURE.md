# IB-ME from HIBE + IBS：项目总体架构

## 1. 项目目标

本项目固定采用指导论文第三章、Wang 等论文 §4 的两层匿名 HIBE + IBS 身份基匹配加密通用构造。2026-10-03 团队决定不实施 Boyen–Li 增强隐私。具体原语、正式参数和完整性包装通过核验后确定，进度见 [重建工作记录](docs/PROJECT_RESTART.md)。

2026-10-06 经用户向老师确认，多实例同时覆盖不同格困难假设和不同具体算法。矩阵 LWE/SIS 为首套研究主线，环格与模格为假设扩展方向；同一矩阵 SIS 下的 Foo–Li、Wang + Pan–Wagner 则可作为不同算法实例。分别记录假设类别、原语算法与完整组合，不把同族算法计为新假设，也不把参数扫描计为新算法。具体组件须各自准入，混合组合如实标注，详见 [实例化口径与验收](docs/research/2026-10-06/多困难假设实例化口径与验收.md)。

主线方案的解密条件为：

$$
\rho = rcv \quad\land\quad \phi = snd.
$$

其中 $\phi$ 是真实发送者身份，$\rho$ 是真实接收者身份，`rcv` 是加密时指定的接收者，`snd` 是解密时尝试的发送者。

项目的安全口径必须分开：

| 版本 | 组件 | 应声明的性质 |
|---|---|---|
| 已确认通用构造 | 两层匿名 HIBE + 自适应安全 IBS | 普通隐私与加强认证；具体实现仍需证明映射与参数核验 |
| 工程认证包装 | 对头部、胶囊与消息体的完整绑定 | 独立论证的密文完整性；基本构造不自动保证全部篡改拒绝 |

`978-3-031-51476-0_21` 仅作为增强隐私定义的背景资料，不是待实现组件或现成代码库。普通隐私不能宣称保护持有目标接收密钥、尚未匹配发送者的恶意用户；加强认证仍须覆盖持有目标接收密钥的自我伪造攻击。

## 2. 总体分层

```text
应用层
  └── CLI / Demo / Benchmark

协议层
  └── IBMEBaseline 与经论证的认证包装

原语层
  ├── HIBEBackend
  └── IBSBackend

格工具层
  ├── Zq 矩阵
  ├── gadget 矩阵
  ├── TrapGen / DelTrap / SamplePre
  └── 离散高斯采样

基础设施层
  ├── 身份、消息、密文的规范编码
  ├── SHAKE-256 域分隔哈希
  ├── 安全随机数与测试随机数
  └── 参数配置与版本管理
```

任何上层模块不得直接操作底层 Python 列表或自行实现序列化。矩阵、随机性和编码都必须经过基础设施层提供的接口。

## 3. 推荐目录

```text
ibme/
  pyproject.toml
  README.md
  ARCHITECTURE.md
  IMPLEMENTATION_SPEC.md
  DELEGATION_PROMPTS.md
  src/ibme/
    core/
      types.py
      encoding.py
      hashing.py
      randomness.py
      errors.py
    lattice/
      params.py
      modmat.py
      gadget.py
      gaussian.py
      trapdoor.py
    hibe/
      api.py
      abb10.py
      mock.py
    ibs/
      api.py
      sis_ibs.py
      mock.py
    protocol/
      baseline.py
    cli.py
  tests/
    test_encoding.py
    test_lattice_core.py
    test_hibe_contract.py
    test_ibs_contract.py
    test_baseline_ibme.py
    test_security_properties.py
  experiments/
    benchmark.py
    parameter_sweep.py
    test_vectors/
  params/
    education.yaml
    competition.yaml
```

第一版使用 Python + SageMath。需要 Sage 的代码在 WSL 中使用环境 `~/miniconda3/envs/sage` 运行。性能优化可另建 C++/Rust 后端，但不能改变 Python 参考实现的协议接口。

## 4. 原语接口

### HIBE

```python
class HIBEBackend(Protocol):
    def setup(self, params) -> tuple[HIBEPublicKey, HIBEMasterSecret]: ...
    def extract(self, msk, parent_id: bytes) -> HIBELevel1SecretKey: ...
    def derive(self, sk_parent, child_id: bytes) -> HIBELevel2SecretKey: ...
    def encrypt(self, pk, parent_id: bytes, child_id: bytes,
                payload: bytes) -> HIBECiphertext: ...
    def decrypt(self, sk_child, ct: HIBECiphertext) -> bytes | None: ...
```

身份顺序固定为 `(parent_id, child_id) = (rcv, phi)`。HIBE 密文不能明文携带身份，否则会破坏匿名性。

2026-10-10 适配层接入补充：HybridHIBE要求原语提供或显式注入公开的validate_key_binding能力，在原语内部验证秘密对象属于所声明公钥并满足可检查的私钥关系。协议层只调用验证器，不读取陷门；原七个HIBE方法和协议语义保持。详见 IMPLEMENTATION_SPEC 的密钥绑定补充。

### IBS

```python
class IBSBackend(Protocol):
    def setup(self, params) -> tuple[IBSPublicKey, IBSMasterSecret]: ...
    def key_extract(self, msk, identity: bytes) -> IBSSigningKey: ...
    def sign(self, sk: IBSSigningKey, message: bytes) -> IBSSignature: ...
    def verify(self, pk, identity: bytes, message: bytes,
               signature: IBSSignature) -> bool: ...
```

签名密钥对象应保存规范化后的身份摘要，避免调用者在 `sign` 时误传另一个身份。

## 5. 协议组合

基线版加密过程：

$$
t\gets\mathsf{IBS.Sign}(sk_\phi,\mathsf{EncID}(rcv)\mathbin\Vert m),
$$

$$
ct\gets\mathsf{HIBE.Enc}(hpk,rcv,\phi,\mathsf{EncSig}(t)\mathbin\Vert m).
$$

基线版解密先派生 $\mathsf{sk}_{\rho|snd}$ 并调用 HIBE 解密，再验证：

$$
\mathsf{IBS.Verify}(ipk,snd,\mathsf{EncID}(\rho)\mathbin\Vert m',t)=1.
$$

协议层只能依赖接口，不能读取 HIBE 或 IBS 的内部矩阵。

## 6. 工程约束

2026-10-10 首套接收状态：[磁盘事务记录](docs/research/2026-10-10-receiver-persistence/README.md)覆盖解密期间的固定地址状态。CLI持有发钥共用锁，进入协议调用前建立非秘密pending标记，通过不透明密钥序列化提交成功/失败状态，提交完成后才输出结果。硬退出或不确定保存时保守阻止自动重试；已有研究接收密钥经验证复用。该职责在CLI/状态层，实际固定bit原像与采样由HIBE负责。

同日[PR #6交接核验](docs/research/2026-10-10-chkp-review/README.md)接收T1/T2/叶缓存研究实现，完整CHKP仍WIP。根生成、各级GS/宽度、资源/噪声与32 B种子的至少256个bit须在同组输入下验收；静态关系通过不直接改变后端或安全声明。

1. 身份、消息、签名都使用长度前缀和域分隔编码。
2. 所有哈希使用 SHAKE-256，并区分 `HIBE-ID`、`IBS-H1`、`IBS-H2` 等域。
3. 测试随机数可以固定种子，生产随机数必须来自系统 CSPRNG。
4. 所有模 $q$ 系数使用统一的 `[0, q)` 表示；范数计算使用明确的整数或高精度实现。
5. 不在代码中散落参数；所有参数从 `Params` 对象读取。
6. 大文件使用混合加密，IB-ME 只封装对称密钥。
7. 小参数只能用于功能调试，不能用于宣称安全等级。

## 7. 集成顺序

按以下顺序合并其他 AI 的工作：

1. `core` 编码、哈希、类型和错误处理；
2. `lattice` 矩阵、gadget、采样和陷门工具；
3. `HIBEBackend`，先通过 mock，再接 ABB10；
4. `IBSBackend`，先通过 mock，再接 SIS-IBS；
5. 基线协议组合；
6. 正确性、篡改、伪造和性能测试；
7. 同一通用构造下不同困难假设及不同算法的完整实例与公平评测；假设类别、算法及组合分别统计。

每个阶段都必须保留一组可复现测试向量。

## 8. 安全声明边界

最终报告必须明确：

- 方案是否在随机预言机模型中分析；
- 使用的是教学参数还是经过格安全估计的参数；
- 是否实现了完整的匿名 HIBE，而不是普通 HIBE 的功能替代品；
- 明确不实施、不宣称 Boyen–Li 增强隐私；
- 密文完整性包装的认证范围和独立安全依据。

没有完成相应组件和证明映射时，不得使用“增强隐私”“达到 NIST Level X”或“标准模型安全”等表述。
