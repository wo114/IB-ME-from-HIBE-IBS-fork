"""IBS 原语层公共 API（owner: DELEGATION_PROMPTS.md 任务 D，M2）。

公共面：

* 冻结接口与对象基类：``ibme.ibs.api``；
* TEST-ONLY mock 后端：``ibme.ibs.mock``（**测试组件，不得用于生产**）；
* SIS-IBS 后端（指导论文构造 3.4.1）：``ibme.ibs.sis_ibs``，含教学参数
  预设 ``IBS_EDUCATION_PARAMS``（security_claim: none）。

两个后端通过同一组 contract tests（tests/test_ibs_contract.py）。
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
]
