"""基线 IB-ME 最小 CLI（IMPLEMENTATION_SPEC.md §1/§7 验收场景）。

子命令::

    setup --params education --state <dir> [--mock]
    issue-sender-key <NAME> --state <dir> [--mock]
    issue-receiver-key <NAME> --state <dir> [--mock]
    encrypt --sender <NAME> --receiver <NAME> --state <dir> --in <file> [--out <file>] [--mock]
    decrypt --receiver <NAME> --sender <NAME> --state <dir> --in <file> [--out <file>] [--mock]

身份编码策略（M3 整改，与 SPEC §1 一致）：

* 身份参数接受任意非空 UTF-8 字符串，进入密码算法前统一
  ``.encode("utf-8")`` 转成字节串（密码层只见到 bytes）；
* 仅做两类检查：非空，且 UTF-8 字节长度不超过所用 HIBE 参数的
  ``Params.identity_bytes``（SPEC §2：身份的**最大**字节长度）。上限从
  ``<state>/state.json`` 读取（见下）；
* 含控制字符或其它不可打印字符（换行、制表符、NUL、孤立代理对等）
  的身份被拒绝；空格、中文、重音字母、emoji 等可打印 Unicode 均允许。

文件名与 state 策略（M3 整改）：

* 密钥文件名不内嵌身份原文，改由身份 UTF-8 字节的 SHA-256 前 16 个
  hex 字符派生：``<state>/sender-<digest>.bin``、
  ``<state>/receiver-<digest>.bin``（身份原文不再出现在任何路径中）；
* ``setup`` 写入 ``<state>/state.json``（版本 1）：记录后端、参数预设
  名、HIBE/IBS 参数名、``identity_bytes``/``max_message_bytes`` 与
  security_claim。issue/encrypt/decrypt 从中读取 ``identity_bytes``
  做长度上限检查；
* **旧 state 目录（无 state.json）被拒绝**并提示重跑 setup：密钥文件
  名方案已从 ``sender-<NAME>.bin`` 改为摘要派生，旧 state 本就不可用，
  因此不做向后兼容而是直接升版拒绝；
* 签发与加解密时在命令输出中打印身份与其摘要的对应关系（issue-* 与
  encrypt 打到 stdout；decrypt 打到 stderr，因为 stdout 可能承载原始
  明文字节流）。

行为约定（其余不变）：

* 状态以规范序列化存文件：``<state>/mpk.bin``、``<state>/msk.bin``；
* ``decrypt`` 失败打印 ``BOTTOM`` 并以非零码（1）退出；参数/IO/状态
  错误退出码 2；成功 0；
* 重建协议对象需要组件类，因此 CLI 按 ``--mock`` 开关导入对应后端的
  公共类（协议层自身不假设后端）；
* ``--mock`` 使用 TEST-ONLY mock 后端（无任何安全性），仅用于联调；
* ``--params education`` 目前映射到基线调试参数对
  （HIBE: ``BASELINE_DEBUG_PARAMS``，IBS: ``BASELINE_DEBUG_IBS_PARAMS``，
  **security_claim: none，教学/调试参数**）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from ibme.core.errors import IBMEError
from ibme.protocol.baseline import (
    BASELINE_DEBUG_IBS_PARAMS,
    BASELINE_DEBUG_PARAMS,
    BASELINE_MOCK_PARAMS,
    BaselineIBME,
    MasterSecret,
    PublicKey,
    ReceiverKey,
    SenderKey,
    is_bottom,
)

#: 参数预设名 -> (HIBE 参数, IBS 参数)；均为教学/调试参数（无安全声明）。
_PRESETS = {"education": (BASELINE_DEBUG_PARAMS, BASELINE_DEBUG_IBS_PARAMS)}

_MPK_FILE = "mpk.bin"
_MSK_FILE = "msk.bin"

#: state 元数据文件（setup 写入；身份长度上限等参数信息的唯一记录处）。
_META_FILE = "state.json"

#: state 元数据版本；bump 即拒绝旧 state（密钥文件名方案随之变更）。
_STATE_VERSION = 1

#: 身份摘要取 SHA-256 hex 的前 16 个字符（64 bit，用于派生文件名）。
_DIGEST_HEX_CHARS = 16


# ---------------------------------------------------------------------------
# 身份解析与摘要派生
# ---------------------------------------------------------------------------


def _identity_digest(identity: bytes) -> str:
    """身份 UTF-8 字节的 SHA-256 前 16 hex（文件名派生 + 输出对号用）。"""
    return hashlib.sha256(identity).hexdigest()[:_DIGEST_HEX_CHARS]


def _parse_identity(text: str, *, max_bytes: int, role: str) -> bytes:
    """UTF-8 身份字符串 -> 规范字节串（SPEC §1：进密码层前必须是 bytes）。

    检查：非空；不含控制/不可打印字符（``str.isprintable``，拒绝换行、
    制表符、NUL、孤立代理对等；空格与可打印 Unicode 均合法）；UTF-8
    字节长度不超过 ``max_bytes``（来自 state 元数据记录的 HIBE
    ``Params.identity_bytes``，SPEC §2 的最大字节长度语义）。
    """
    if not isinstance(text, str):
        raise ValueError(
            f"{role} must be a UTF-8 string, got {type(text).__name__}"
        )
    if not text:
        raise ValueError(f"{role} must be a non-empty UTF-8 string")
    if not text.isprintable():
        raise ValueError(
            f"{role} contains control or non-printable characters "
            "(newlines, tabs, NUL, lone surrogates, ...); printable "
            "Unicode only (spaces, letters, CJK, emoji are fine)"
        )
    try:
        identity = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{role} is not encodable as UTF-8: {exc}") from exc
    if len(identity) > max_bytes:
        raise ValueError(
            f"{role} is {len(identity)} bytes in UTF-8, exceeding the "
            f"identity_bytes limit {max_bytes} recorded for this state "
            "(Params.identity_bytes, SPEC section 2)"
        )
    return identity


def _sender_key_path(state: Path, identity: bytes) -> Path:
    return state / f"sender-{_identity_digest(identity)}.bin"


def _receiver_key_path(state: Path, identity: bytes) -> Path:
    return state / f"receiver-{_identity_digest(identity)}.bin"


# ---------------------------------------------------------------------------
# state 元数据（setup 写入，其余子命令读取）
# ---------------------------------------------------------------------------


def _write_state_meta(
    state: Path, *, mock: bool, preset: str, hibe_params, ibs_params
) -> None:
    meta = {
        "version": _STATE_VERSION,
        "backend": "mock" if mock else "abb10+sis",
        "params_preset": preset,
        "hibe_params_name": hibe_params.name,
        "ibs_params_name": ibs_params.name,
        # 身份最大字节长度（SPEC section 2）；HIBE 层入口同样强制该上限。
        "identity_bytes": hibe_params.identity_bytes,
        "max_message_bytes": hibe_params.max_message_bytes,
        "security_claim": "none",  # 教学参数，无任何安全声明
    }
    (state / _META_FILE).write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _load_state_meta(state: Path) -> dict:
    """读取并校验 ``<state>/state.json``；缺失/版本不符/损坏都报参数错误。"""
    path = state / _META_FILE
    if not path.is_file():
        raise ValueError(
            f"state metadata not found: {path}; run 'setup' first "
            "(state directories created before digest-based key "
            "filenames are not supported and must be re-created)"
        )
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"corrupt state metadata {path}: {exc}") from exc
    if not isinstance(meta, dict) or meta.get("version") != _STATE_VERSION:
        found = meta.get("version") if isinstance(meta, dict) else None
        raise ValueError(
            f"unsupported state metadata in {path}: expected version "
            f"{_STATE_VERSION}, found {found!r}; re-run 'setup'"
        )
    limit = meta.get("identity_bytes")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError(f"invalid identity_bytes recorded in {path}: {limit!r}")
    return meta


# ---------------------------------------------------------------------------
# 后端选择与公共 IO
# ---------------------------------------------------------------------------


def _make_runtime(mock: bool):
    """按 --mock 选择后端与组件类（组件 from_bytes 是 api 层冻结接口）。"""
    if mock:
        # TEST-ONLY 路径：mock 后端没有任何安全性。
        from ibme.hibe.mock import (
            MockHIBE,
            MockHIBEMasterSecret,
            MockHIBELevel1SecretKey,
            MockHIBEPublicKey,
        )
        from ibme.ibs.mock import (
            MockIBSBackend,
            MockMasterSecret,
            MockPublicKey,
            MockSigningKey,
        )

        return (
            BaselineIBME(MockHIBE(), MockIBSBackend()),
            {
                "hpk": MockHIBEPublicKey,
                "hmsk": MockHIBEMasterSecret,
                "sk1": MockHIBELevel1SecretKey,
                "ipk": MockPublicKey,
                "imsk": MockMasterSecret,
                "sk": MockSigningKey,
            },
        )
    from ibme.hibe.abb10 import (
        ABB10HIBE,
        ABB10MasterSecret,
        ABB10Level1SecretKey,
        ABB10PublicKey,
    )
    from ibme.ibs.sis_ibs import (
        SisIBSBackend,
        SisMasterSecret,
        SisPublicKey,
        SisSigningKey,
    )

    return (
        BaselineIBME(ABB10HIBE(), SisIBSBackend()),
        {
            "hpk": ABB10PublicKey,
            "hmsk": ABB10MasterSecret,
            "sk1": ABB10Level1SecretKey,
            "ipk": SisPublicKey,
            "imsk": SisMasterSecret,
            "sk": SisSigningKey,
        },
    )


def _params_pair(preset: str, mock: bool):
    if mock:
        return BASELINE_MOCK_PARAMS, BASELINE_MOCK_PARAMS
    return _PRESETS[preset]


def _read(path: Path) -> bytes:
    if not path.is_file():
        raise ValueError(f"required file not found: {path}")
    return path.read_bytes()


def _load_msk(state: Path, mock: bool) -> tuple[MasterSecret, BaselineIBME, dict]:
    proto, classes = _make_runtime(mock)
    msk = MasterSecret.from_bytes(
        _read(state / _MSK_FILE), classes["hmsk"], classes["imsk"]
    )
    return msk, proto, classes


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------


def cmd_setup(args) -> int:
    hibe_params, ibs_params = _params_pair(args.params, args.mock)
    proto, _ = _make_runtime(args.mock)
    pk, msk = proto.setup(hibe_params, ibs_params=ibs_params)
    args.state.mkdir(parents=True, exist_ok=True)
    (args.state / _MPK_FILE).write_bytes(pk.to_bytes())
    (args.state / _MSK_FILE).write_bytes(msk.to_bytes())
    _write_state_meta(
        args.state,
        mock=args.mock,
        preset=args.params,
        hibe_params=hibe_params,
        ibs_params=ibs_params,
    )
    print(
        f"setup complete: preset={args.params} "
        f"({'TEST-ONLY mock backends' if args.mock else 'abb10+sis debug backends'}, "
        f"security_claim: none)"
    )
    print(f"  wrote {args.state / _MPK_FILE} ({len(pk.to_bytes())} bytes)")
    print(f"  wrote {args.state / _MSK_FILE} ({len(msk.to_bytes())} bytes)")
    print(
        f"  wrote {args.state / _META_FILE} "
        f"(identity_bytes={hibe_params.identity_bytes}, "
        f"max_message_bytes={hibe_params.max_message_bytes})"
    )
    return 0


def cmd_issue_sender_key(args) -> int:
    meta = _load_state_meta(args.state)
    identity = _parse_identity(
        args.name, max_bytes=meta["identity_bytes"], role="sender identity"
    )
    digest = _identity_digest(identity)
    msk, proto, classes = _load_msk(args.state, args.mock)
    ek = proto.skgen(msk, identity)
    out = _sender_key_path(args.state, identity)
    out.write_bytes(ek.to_bytes())
    print(
        f"issued sender key: identity={args.name!r} utf8={len(identity)}B "
        f"digest={digest} (sha256[:{_DIGEST_HEX_CHARS}] of UTF-8 bytes)"
    )
    print(f"  wrote {out} ({len(ek.to_bytes())} bytes)")
    return 0


def cmd_issue_receiver_key(args) -> int:
    meta = _load_state_meta(args.state)
    identity = _parse_identity(
        args.name, max_bytes=meta["identity_bytes"], role="receiver identity"
    )
    digest = _identity_digest(identity)
    msk, proto, classes = _load_msk(args.state, args.mock)
    dk = proto.rkgen(msk, identity)
    out = _receiver_key_path(args.state, identity)
    out.write_bytes(dk.to_bytes())
    print(
        f"issued receiver key: identity={args.name!r} utf8={len(identity)}B "
        f"digest={digest} (sha256[:{_DIGEST_HEX_CHARS}] of UTF-8 bytes)"
    )
    print(f"  wrote {out} ({len(dk.to_bytes())} bytes)")
    return 0


def cmd_encrypt(args) -> int:
    meta = _load_state_meta(args.state)
    sender = _parse_identity(
        args.sender, max_bytes=meta["identity_bytes"], role="sender identity"
    )
    receiver = _parse_identity(
        args.receiver, max_bytes=meta["identity_bytes"], role="receiver identity"
    )
    proto, classes = _make_runtime(args.mock)
    pk = PublicKey.from_bytes(
        _read(args.state / _MPK_FILE), classes["hpk"], classes["ipk"]
    )
    ek = SenderKey.from_bytes(_read(_sender_key_path(args.state, sender)), classes["sk"])
    if ek.identity != sender:
        raise ValueError(f"sender key file does not belong to {args.sender!r}")
    message = _read(args.in_path)
    ct = proto.encrypt(pk, ek, receiver, message)
    out = args.out or Path(str(args.in_path) + ".ibme-ct")
    out.write_bytes(ct.to_bytes())
    print(
        f"sender identity={args.sender!r} "
        f"digest={_identity_digest(sender)}, "
        f"receiver identity={args.receiver!r} "
        f"digest={_identity_digest(receiver)}"
    )
    print(f"encrypted {len(message)}B -> {out} ({len(ct.to_bytes())} bytes)")
    return 0


def cmd_decrypt(args) -> int:
    meta = _load_state_meta(args.state)
    receiver = _parse_identity(
        args.receiver, max_bytes=meta["identity_bytes"], role="receiver identity"
    )
    sender = _parse_identity(
        args.sender, max_bytes=meta["identity_bytes"], role="sender identity"
    )
    proto, classes = _make_runtime(args.mock)
    pk = PublicKey.from_bytes(
        _read(args.state / _MPK_FILE), classes["hpk"], classes["ipk"]
    )
    dk = ReceiverKey.from_bytes(
        _read(_receiver_key_path(args.state, receiver)), classes["sk1"]
    )
    if dk.identity != receiver:
        raise ValueError(f"receiver key file does not belong to {args.receiver!r}")
    data = _read(args.in_path)
    # 身份/摘要信息打到 stderr：stdout 缺省承载原始明文字节流。
    print(
        f"receiver identity={args.receiver!r} "
        f"digest={_identity_digest(receiver)}, "
        f"sender identity={args.sender!r} "
        f"digest={_identity_digest(sender)}",
        file=sys.stderr,
    )
    message = proto.decrypt(pk, dk, sender, data)
    if is_bottom(message):
        print("BOTTOM")
        return 1
    if args.out:
        args.out.write_bytes(message)
        print(f"decrypted {len(message)}B -> {args.out}")
    else:
        sys.stdout.buffer.write(message)
        sys.stdout.buffer.flush()
    return 0


# ---------------------------------------------------------------------------
# 参数解析与入口
# ---------------------------------------------------------------------------

_IDENTITY_HELP = (
    "身份（任意非空可打印 UTF-8 字符串，如 Alice、小明的钥匙、Zoë、🔑；"
    "进入算法前转 UTF-8 字节，字节长度上限为该 state 参数的 identity_bytes；"
    "含换行/制表符等控制字符的身份被拒绝）"
)


def _add_common(sub) -> None:
    sub.add_argument("--state", type=Path, required=True, help="状态目录")
    sub.add_argument(
        "--mock",
        action="store_true",
        help="TEST-ONLY：使用 mock 后端（无任何安全性，仅联调用）",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ibme",
        description="基线 IB-ME（两层格基 HIBE + SIS-IBS）最小 CLI；"
        "教学/调试参数，security_claim: none。身份接受任意非空可打印 "
        "UTF-8 字符串（进算法前转字节）；密钥文件名由身份的 SHA-256 "
        "前 16 hex 派生，不内嵌身份原文。",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("setup", help="生成 mpk/msk 与 state.json 元数据")
    p.add_argument(
        "--params",
        choices=sorted(_PRESETS),
        default="education",
        help="参数预设（当前仅 education：教学/调试参数）",
    )
    _add_common(p)
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("issue-sender-key", help="为发送者身份签发 ek")
    p.add_argument("name", help=_IDENTITY_HELP)
    _add_common(p)
    p.set_defaults(func=cmd_issue_sender_key)

    p = sub.add_parser("issue-receiver-key", help="为接收者身份签发 dk")
    p.add_argument("name", help=_IDENTITY_HELP)
    _add_common(p)
    p.set_defaults(func=cmd_issue_receiver_key)

    p = sub.add_parser("encrypt", help="加密消息（--sender 的 ek + --receiver 身份）")
    p.add_argument("--sender", required=True, help=f"发送者{_IDENTITY_HELP}")
    p.add_argument("--receiver", required=True, help=f"接收者{_IDENTITY_HELP}")
    p.add_argument("--in", dest="in_path", type=Path, required=True, help="明文文件")
    p.add_argument("--out", dest="out", type=Path, default=None, help="密文输出文件")
    _add_common(p)
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="解密密文（--receiver 的 dk + --sender 身份）")
    p.add_argument("--receiver", required=True, help=f"接收者{_IDENTITY_HELP}（需已签发 dk）")
    p.add_argument("--sender", required=True, help=f"声称的发送者{_IDENTITY_HELP}")
    p.add_argument("--in", dest="in_path", type=Path, required=True, help="密文文件")
    p.add_argument("--out", dest="out", type=Path, default=None, help="明文输出文件（缺省写 stdout）")
    _add_common(p)
    p.set_defaults(func=cmd_decrypt)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse 用法错误（已打印 usage）
        return int(exc.code or 0)
    try:
        return args.func(args)
    except (IBMEError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
