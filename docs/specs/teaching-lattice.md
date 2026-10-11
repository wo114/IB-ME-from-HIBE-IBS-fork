# 教学格后端与公共格工具的兼容规范

本文件只记录旧参考实现的参数与数学约束，不作为 CHKP、Luo、环或 NTRU 后端的统一算法要求。通用接口见 [实现规范](../../IMPLEMENTATION_SPEC.md)，已知反例见 [安全缺口](../KNOWN_SECURITY_GAPS.md)。教学、mock 与研究后端不得据功能测试申报安全等级。

## 1. 旧 Params 形状

```python
@dataclass(frozen=True)
class Params:
    name: str
    security_parameter: int
    n: int
    m_matrix: int
    q: int
    s0: float
    s: float
    s_prime: float
    identity_bytes: int
    max_message_bytes: int
```

该类型位于 `src/ibme/lattice/params.py`，保留字段与旧 uint32 wire 兼容。整数字段拒绝 bool 并取正值，q 满足 2≤q<2^32；采样宽度为有限正实数。`identity_bytes` 是身份最大字节长度，`m_matrix` 表示矩阵列数，`message` 表示消息。新后端可以独立定义参数类型，不得将大模数截断塞入旧 wire。

## 2. 模矩阵

`ModMatrix` 至少支持：

- 创建和维度检查；
- 模 $q$ 加、减、乘；
- 矩阵拼接；
- 固定长度序列化；
- 从规范字节串反序列化；
- 与整数向量相乘。

所有操作都必须检查模数和维度一致性，失败时抛出项目自定义异常。

### gadget 矩阵

现有教学后端对 $q$ 使用二进制 gadget 矩阵：

$$
G\in\mathbb{Z}_q^{n\times n\lceil\log_2q\rceil}.
$$

### SIS-IBS 关键关系

$$
H_1(mpk,id)=A\widehat R_{id}+G,
\qquad
F_{id}=[A\mid H_1(mpk,id)] .
$$

该教学 SIS-IBS 的签名关系为：

$$
F_{id}z=H_2(mpk,id,message)\pmod q.
$$

该后端验证还检查 $z\neq 0$ 和其配置范数界；这些检查不消除已经记录的教学参数伪造。

### 随机性

离散高斯采样器必须提供：

```python
sample_integer_gaussian(sigma, center=0) -> int
sample_vector_gaussian(length, sigma) -> list[int]
```

实现者必须提供采样统计测试，报告均值、方差和尾部计数。不能把均匀随机数伪装成离散高斯。

公共格工具按其实际用途维护，后端可选择复用；不用 gadget 或离散高斯的算法无需实现这些函数。使用离散高斯的后端必须说明传入参数是标准差还是论文宽度，以及离散化/截断/拒绝预算，统计检验不能替代理论分布或采样来源证明。
