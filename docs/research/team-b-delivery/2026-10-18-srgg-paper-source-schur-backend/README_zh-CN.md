# Paper source-Schur SRGG IBS：后端收口（caller-owned adapter）

本包把 paper source-Schur 方向补成可注册、可持久化、可跑完整生命周期的后端路径。
**Table 4 的数值、宽度、factor、范数、对象编码和算法步骤均未修改。**

## 新增内容

| 文件 | 作用 |
|---|---|
| `src/ibme/ibs/srgg_paper/registration.py` | caller-owned `BackendSpec`，ID `srgg2025-source-schur`，六个 Table 4 preset（三行 × 两种解释），factory 为 `SourceSchurBackend` |
| `src/ibme/ibs/srgg_paper/service.py` | `SourceSchurFixedIssuer`，默认 backend 为 `SourceSchurBackend`；`GuardedSourceSchurFixedIssuer`，默认 backend 为 `GuardedSourceSchurBackend` |
| `src/ibme/ibs/srgg_paper/guarded.py` | 可选 guarded 接受集：Setup 门失败抛 `RootGateRejection`（可重试），签名计划失败抛 `SigningKeyGateRejection`（固定密钥中止） |
| `src/ibme/ibs/srgg_paper/__init__.py` | 显式导出 `backend_spec`、`SourceSchurBackend`、`GuardedSourceSchurBackend`、两个固定 issuer 和 paper 对象 |
| `tests/test_srgg_paper_source_schur_registration.py` | 描述符、六 preset、Table 4 不变、真实 Setup/Extract/Sign/Verify、篡改/身份不匹配、序列化、服务重启缓存、guarded 生命周期与根门重试 |
| `validation.json` | 测试命令/结果、Table 4 不变声明、默认路由不变说明、guarded 语义和剩余 null |

## 设计边界

- **不**修改默认注册表 `srgg2025`，也**不**修改 `srgg2025` 的 `Config` degree-8 profile。
- **不**修改原 `srgg_paper_service.FixedIssuer` 的默认 backend；需要 source-Schur 持久服务时显式使用 `SourceSchurFixedIssuer`；需要分布链 guard 时使用 `GuardedSourceSchurFixedIssuer`。
- 这是 caller-owned adapter，和 `srgg2025-structured` 的边界一致：调用方把它加入自己的 `BackendRegistry`，不会在 import 时改变全局默认。
- `GuardedSourceSchurBackend` 是服务/接受集策略：Setup 门失败按 `WitnessGeometryError` 重试，坏签名密钥直接中止；它不改变 Table 4 或对象格式。
- 仍保持 `security_claim=none`、`backend_admitted=false`、`parameters_are_formal=false`、`nist_security_category=null`。这是研究执行后端，不是安全准入。

## 用法

```python
from ibme.assembly.registry import BackendRegistry
from ibme.core.randomness import DeterministicRandom
from ibme.ibs.srgg_paper.registration import backend_spec
from experiments.research.candidates.srgg.paper_parameters import PaperParams

registry = BackendRegistry([backend_spec()])
spec = registry.get("ibs", "srgg2025-source-schur")
params = spec.presets["PARAM-I-literal-density-width"]
backend = spec.factory(DeterministicRandom(b"paper-source-schur"), "canonical-json-v1")
pk, msk = backend.setup(params)
sk = backend.key_extract(msk, b"Alice")
sig = backend.sign(sk, b"message")
assert backend.verify(pk, b"Alice", b"message", sig)
```

持久服务：

```python
from ibme.ibs.srgg_paper.service import SourceSchurFixedIssuer
issuer = SourceSchurFixedIssuer(path)
issuer.initialize(PaperParams("PARAM-I", "literal-density-width"), max_users=2)
key = issuer.key_extract(b"Alice")
```

需要分布链 guard 时把 `SourceSchurFixedIssuer` 换成
`GuardedSourceSchurFixedIssuer`；Setup 门失败会重试根，签名计划失败会中止该固定密钥。

## 验证

```bash
PYTHONPATH=src:. ~/miniconda3/envs/sage/bin/python -m pytest -q \
    tests/test_srgg_paper_source_schur_registration.py \
    tests/test_srgg_paper_backend.py \
    tests/test_srgg_paper_service.py
```

结果见最终交付信息；功能测试和真实生命周期不是安全证明。

始终：`security_claim=none`、`backend_admitted=false`、
`parameters_are_formal=false`、`nist_security_category=null`。
