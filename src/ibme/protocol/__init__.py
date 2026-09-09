"""协议层：基线 IB-ME 组合（M3）。

公共面：

* :class:`ibme.protocol.baseline.BaselineIBME` —— 五个算法
  ``setup/skgen/rkgen/encrypt/decrypt``（IMPLEMENTATION_SPEC.md §4）；
* :data:`BOTTOM` —— 解密失败哨兵（falsy 单例）；
* 协议数据结构 ``PublicKey/MasterSecret/SenderKey/ReceiverKey/Ciphertext``
  与冻结的组帧常量（``DOMAIN_SIGNATURE``、``MAGIC_*``）；
* 调试参数预设 ``BASELINE_DEBUG_PARAMS``/``BASELINE_DEBUG_IBS_PARAMS``/
  ``BASELINE_MOCK_PARAMS``（**security_claim: none，仅调试**）。

安全口径：组合层不产生新的安全性质；基线版仅声明正确性、原始隐私与
强可认证性，且以两个组件后端各自的安全声明为前提。
"""

from ibme.protocol.baseline import (
    BASELINE_DEBUG_IBS_PARAMS,
    BASELINE_DEBUG_PARAMS,
    BASELINE_MOCK_PARAMS,
    BOTTOM,
    BaselineIBME,
    Ciphertext,
    DOMAIN_SIGNATURE,
    MasterSecret,
    MAGIC_CIPHERTEXT,
    MAGIC_MASTER_SECRET,
    MAGIC_PUBLIC_KEY,
    MAGIC_RECEIVER_KEY,
    MAGIC_SENDER_KEY,
    PublicKey,
    ReceiverKey,
    SenderKey,
    encode_signature,
    is_bottom,
    parse_payload,
)

__all__ = [
    "BASELINE_DEBUG_IBS_PARAMS",
    "BASELINE_DEBUG_PARAMS",
    "BASELINE_MOCK_PARAMS",
    "BOTTOM",
    "BaselineIBME",
    "Ciphertext",
    "DOMAIN_SIGNATURE",
    "MasterSecret",
    "MAGIC_CIPHERTEXT",
    "MAGIC_MASTER_SECRET",
    "MAGIC_PUBLIC_KEY",
    "MAGIC_RECEIVER_KEY",
    "MAGIC_SENDER_KEY",
    "PublicKey",
    "ReceiverKey",
    "SenderKey",
    "encode_signature",
    "is_bottom",
    "parse_payload",
]
