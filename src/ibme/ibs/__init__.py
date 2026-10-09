"""IBS 原语层公共 API（owner: DELEGATION_PROMPTS.md 任务 D，M2）。

公共面：

* 冻结接口与对象基类：``ibme.ibs.api``；
* TEST-ONLY mock 后端：``ibme.ibs.mock``（**测试组件，不得用于生产**）；
* SIS-IBS 后端（指导论文构造 3.4.1）：``ibme.ibs.sis_ibs``，含教学参数
  预设 ``IBS_EDUCATION_PARAMS``（security_claim: none）。
* Luo 2024 矩阵/模格研究后端：``ibme.ibs.luo``、``ibme.ibs.luo_module``，
  各自有专用契约检查，均未通过安全准入。

mock 与 SIS 后端共用 tests/test_ibs_contract.py；研究版本沿用冻结接口。
"""

from ibme.ibs.api import (
    IBSError,
    IBSBackend,
    IBSMasterSecret,
    IBSPublicKey,
    IBSSignature,
    IBSSigningKey,
)
from ibme.ibs.mock import (
    MockIBSBackend,
    MockMasterSecret,
    MockPublicKey,
    MockSignature,
    MockSigningKey,
)
from ibme.ibs.sis_ibs import (
    IBS_EDUCATION_PARAMS,
    SisIBSBackend,
    SisMasterSecret,
    SisPublicKey,
    SisSignature,
    SisSigningKey,
    f_id_matrix,
    h1_matrix,
    h2_vector,
    signature_bound,
)
from ibme.ibs.luo import (
    LuoIBSBackend, LuoMatrixParams, LuoMasterSecret, LuoPublicKey,
    LuoSamplingAbort, LuoSignature, LuoSigningKey,
)
from ibme.ibs.luo_module import (
    LuoModuleIBSBackend, LuoModuleParams, LuoModuleMasterSecret, LuoModulePublicKey,
    LuoModuleSamplingAbort, LuoModuleSignature, LuoModuleSigningKey,
)

__all__ = [
    # api
    "IBSBackend",
    "IBSError",
    "IBSMasterSecret",
    "IBSPublicKey",
    "IBSSignature",
    "IBSSigningKey",
    # mock（TEST-ONLY）
    "MockIBSBackend",
    "MockMasterSecret",
    "MockPublicKey",
    "MockSignature",
    "MockSigningKey",
    # sis
    "IBS_EDUCATION_PARAMS",
    "SisIBSBackend",
    "SisMasterSecret",
    "SisPublicKey",
    "SisSignature",
    "SisSigningKey",
    "f_id_matrix",
    "h1_matrix",
    "h2_vector",
    "signature_bound",
    # Luo 2024 matrix research adapter (not admitted as secure)
    "LuoIBSBackend",
    "LuoMatrixParams",
    "LuoMasterSecret",
    "LuoPublicKey",
    "LuoSamplingAbort",
    "LuoSignature",
    "LuoSigningKey",
    # Luo 2024 module research backend (not admitted as secure)
    "LuoModuleIBSBackend",
    "LuoModuleParams",
    "LuoModuleMasterSecret",
    "LuoModulePublicKey",
    "LuoModuleSamplingAbort",
    "LuoModuleSignature",
    "LuoModuleSigningKey",
]
