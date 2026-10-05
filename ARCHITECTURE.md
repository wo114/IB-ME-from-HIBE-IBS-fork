# IB-ME from HIBE + IBS：项目总体架构

## 1. 项目目标

本项目固定采用指导论文第三章、Wang 等论文 §4 的两层匿名 HIBE + IBS 身份基匹配加密通用构造。2026-10-03 团队决定不实施 Boyen–Li 增强隐私。具体原语、正式参数和完整性包装通过核验后确定，进度见 [重建工作记录](docs/PROJECT_RESTART.md)。

2026-10-06 确认多实例按不同格困难假设组织：矩阵 LWE/SIS 为首套研究主线，Ring-LWE/Ring-SIS、Module-LWE/Module-SIS 为扩展研究方向。具体组件须各自准入；矩阵 LWE + Ring-SIS 等混合组合单独标注其真实依赖。Foo–Li 与 Wang + Pan–Wagner 等同属矩阵 SIS 的算法对照不计为两个困难假设实例，详见 [实例化口径与验收](docs/research/2026-10-06/多困难假设实例化口径与验收.md)。

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
7. 同一通用构造下引入其他困难假设的完整实例与公平评测；同一假设下的算法对照单独报告。

每个阶段都必须保留一组可复现测试向量。

## 8. 安全声明边界

最终报告必须明确：

- 方案是否在随机预言机模型中分析；
- 使用的是教学参数还是经过格安全估计的参数；
- 是否实现了完整的匿名 HIBE，而不是普通 HIBE 的功能替代品；
- 明确不实施、不宣称 Boyen–Li 增强隐私；
- 密文完整性包装的认证范围和独立安全依据。

没有完成相应组件和证明映射时，不得使用“增强隐私”“达到 NIST Level X”或“标准模型安全”等表述。
