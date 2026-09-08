"""HIBE 原语层：冻结接口（api）、TEST-ONLY mock 后端与 ABB10 格基后端。

模块所有权与修改边界见仓库 AGENTS.md 与 DELEGATION_PROMPTS.md 任务 C。
安全口径：本包不宣称任何安全级别；``ibme.hibe.mock`` 是测试组件，
``ibme.hibe.abb10`` 使用教学参数（security_claim: none，仅调试）。
"""

from ibme.hibe.api import (
    HIBECiphertext,
    HIBEBackend,
    HIBEMasterSecret,
    HIBEPublicKey,
    HIBELevel1SecretKey,
    HIBELevel2SecretKey,
    HIBESerializable,
)
from ibme.hibe.mock import (
    MockHIBE,
    MockHIBECiphertext,
    MockHIBEMasterSecret,
    MockHIBEPublicKey,
    MockHIBELevel1SecretKey,
    MockHIBELevel2SecretKey,
)
from ibme.hibe.abb10 import (
    ABB10HIBE,
    ABB10_DEBUG_PARAMS,
    ABB10Ciphertext,
    ABB10Level1SecretKey,
    ABB10Level2SecretKey,
    ABB10MasterSecret,
    ABB10PublicKey,
)

__all__ = [
    # 冻结接口（api）
    "HIBEBackend",
    "HIBESerializable",
    "HIBEPublicKey",
    "HIBEMasterSecret",
    "HIBELevel1SecretKey",
    "HIBELevel2SecretKey",
    "HIBECiphertext",
    # TEST-ONLY mock 后端
    "MockHIBE",
    "MockHIBEPublicKey",
    "MockHIBEMasterSecret",
    "MockHIBELevel1SecretKey",
    "MockHIBELevel2SecretKey",
    "MockHIBECiphertext",
    # ABB10 格基后端（教学参数，security_claim: none）
    "ABB10HIBE",
    "ABB10_DEBUG_PARAMS",
    "ABB10PublicKey",
    "ABB10MasterSecret",
    "ABB10Level1SecretKey",
    "ABB10Level2SecretKey",
    "ABB10Ciphertext",
]
