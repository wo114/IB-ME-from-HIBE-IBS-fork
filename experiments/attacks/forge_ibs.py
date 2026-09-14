"""SIS-IBS 伪造攻击复现（线性代数，无需任何密钥）。

背景
----
``ibs-education`` 参数下验签范数界为 ``beta = s' * sqrt(m + n*k) = 64 * sqrt(152)
≈ 789``，而模数只有 ``q = 257``。当 ``beta`` 超过 ``q`` 时，``F_id * z = h2 (mod q)``
可以直接用线性代数求解：``F_id`` 是 ``n x cols`` 的满秩矩阵，任取 ``n`` 个线性无关
的列解方程、其余分量置零，即得一个满足等式且范数很小的 ``z``。

``params/ibs-education.yaml`` 对 ``s'=64`` 的论证只检查了**稠密**向量
（152 个分量全非零，范数可达 128*sqrt(152) ≈ 1578 > 789），漏掉了本脚本使用的
**稀疏**解。

本脚本做两级验证：

1. 原语级：为任意身份和任意消息伪造出能通过 ``SisIBSBackend.verify`` 的签名；
2. 协议级：仅用公钥 ``mpk`` 伪造一条完整 IB-ME 密文，接收者正常解密成功并将其
   归因于被冒充的发送者——即攻破论文定义 3.2.10 的强可认证性。

用法::

    python experiments/attacks/forge_ibs.py

安全声明：本脚本用于项目自查与回归验证，针对的是本仓库教学参数的实现缺陷，
不构成对论文构造 3.4.1 本身的攻击。
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from ibme.core.encoding import encode_bytes, encode_message  # noqa: E402
from ibme.core.randomness import DeterministicRandom  # noqa: E402
from ibme.hibe.abb10 import ABB10HIBE  # noqa: E402
from ibme.ibs.sis_ibs import (  # noqa: E402
    SisIBSBackend,
    IBS_EDUCATION_PARAMS,
    SisSignature,
    f_id_matrix,
    h2_vector,
)
from ibme.protocol.baseline import (  # noqa: E402
    BASELINE_DEBUG_IBS_PARAMS,
    BASELINE_DEBUG_PARAMS,
    BaselineIBME,
    Ciphertext,
    DOMAIN_SIGNATURE,
    is_bottom,
)


def solve_square(matrix, target, modulus):
    """高斯消元解 ``matrix @ x = target (mod modulus)``；无解返回 None。"""
    size = len(matrix)
    rows = [row[:] + [target[i]] for i, row in enumerate(matrix)]
    for col in range(size):
        pivot = next((r for r in range(col, size) if rows[r][col] % modulus), None)
        if pivot is None:
            return None
        rows[col], rows[pivot] = rows[pivot], rows[col]
        inverse = pow(rows[col][col] % modulus, -1, modulus)
        rows[col] = [(v * inverse) % modulus for v in rows[col]]
        for r in range(size):
            if r != col and rows[r][col] % modulus:
                factor = rows[r][col]
                rows[r] = [
                    (rows[r][k] - factor * rows[col][k]) % modulus
                    for k in range(size + 1)
                ]
    return [rows[i][size] % modulus for i in range(size)]


def forge_signature(public_key, identity: bytes, message: bytes) -> SisSignature:
    """仅用公钥伪造一个满足 ``F_id z = h2`` 且范数远低于验签界的签名。"""
    f_id = f_id_matrix(public_key, identity)
    target = h2_vector(public_key, identity, message)
    modulus, size, cols = public_key.q, f_id.rows, f_id.cols
    grid = f_id.to_lists()
    for start in range(cols - size + 1):
        columns = list(range(start, start + size))
        solution = solve_square(
            [[grid[i][j] for j in columns] for i in range(size)],
            target.to_list(),
            modulus,
        )
        if solution is None:
            continue
        vector = [0] * cols
        for column, value in zip(columns, solution):
            # 中心化代表元：|value| <= q/2，进一步压低范数
            vector[column] = value - modulus if value > modulus // 2 else value
        return SisSignature(vector)
    raise RuntimeError("未找到线性无关的列组合（理论上不应发生）")


def demo_primitive() -> bool:
    """原语级：对从未提取过签名密钥的身份伪造签名。"""
    print("=== 1. 原语级伪造 ===")
    backend = SisIBSBackend(rng=DeterministicRandom(b"forge-demo"))
    public_key, _ = backend.setup(IBS_EDUCATION_PARAMS)
    identity, message = b"Alice", b"forged: never signed by Alice"
    signature = forge_signature(public_key, identity, message)
    norm = math.sqrt(signature.norm_squared)
    accepted = backend.verify(public_key, identity, message, signature)
    print(f"  身份 {identity!r}（从未调用 key_extract）")
    print(f"  ||z||_2 = {norm:.2f}   验签界 beta = {public_key.norm_bound:.2f}")
    print(f"  verify() -> {accepted}")
    return accepted


def demo_protocol() -> bool:
    """协议级：仅用 mpk 伪造一条 IB-ME 密文，接收者解密成功。"""
    print("=== 2. 协议级端到端伪造（强可认证性）===")
    protocol = BaselineIBME(
        ABB10HIBE(), SisIBSBackend(rng=DeterministicRandom(b"e2e-ibs"))
    )
    public, master = protocol.setup(
        BASELINE_DEBUG_PARAMS,
        ibs_params=BASELINE_DEBUG_IBS_PARAMS,
        rng=DeterministicRandom(b"e2e-setup"),
    )
    sender, receiver = b"Alice", b"Bob"
    # 注意：全程不调用 protocol.skgen(master, sender) —— 攻击者拿不到 Alice 的 ek
    receiver_key = protocol.rkgen(master, receiver, rng=DeterministicRandom(b"e2e-rk"))

    forged_message = b"AUTHORIZED BY ALICE: release the funds"
    signature = forge_signature(
        public.ipk, sender, encode_message(receiver, forged_message)
    )
    payload = (
        DOMAIN_SIGNATURE
        + encode_bytes(signature.to_bytes())
        + encode_bytes(forged_message)
    )
    # HIBE 加密是公开算法，任何人都可以调用
    hibe_ct = protocol.hibe_backend.encrypt(
        public.hpk, receiver, sender, payload, rng=DeterministicRandom(b"e2e-enc")
    )
    recovered = protocol.decrypt(
        public,
        receiver_key,
        sender,
        Ciphertext(hibe_ct=hibe_ct),
        rng=DeterministicRandom(b"e2e-dec"),
    )
    if is_bottom(recovered):
        print("  接收者得到 BOTTOM —— 伪造失败")
        return False
    print(f"  接收者解密出: {recovered.decode()}")
    print(f"  并会认为该消息来自 {sender.decode()}")
    return True


def main() -> int:
    primitive_ok = demo_primitive()
    print()
    protocol_ok = demo_protocol()
    print()
    if primitive_ok and protocol_ok:
        print("结论：在当前教学参数下，IBS 不可伪造性与 IB-ME 强可认证性均不成立。")
        return 0
    print("结论：伪造未成功（参数或实现已修复）。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
