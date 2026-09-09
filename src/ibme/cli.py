"""基线 IB-ME 最小 CLI（IMPLEMENTATION_SPEC.md §7 验收场景）。

子命令::

    setup --params education --state <dir> [--mock]
    issue-sender-key <NAME> --state <dir> [--mock]
    issue-receiver-key <NAME> --state <dir> [--mock]
    encrypt --sender <NAME> --receiver <NAME> --state <dir> --in <file> [--out <file>] [--mock]
    decrypt --receiver <NAME> --sender <NAME> --state <dir> --in <file> [--out <file>] [--mock]

行为约定：

* 身份从命令行以 UTF-8 转 bytes 后进入密码算法（SPEC §1）；
* 状态以规范序列化存文件：``<state>/mpk.bin``、``<state>/msk.bin``、
  ``<state>/sender-<NAME>.bin``、``<state>/receiver-<NAME>.bin``；
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
import re
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

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

#: 参数预设名 -> (HIBE 参数, IBS 参数)；均为教学/调试参数（无安全声明）。
_PRESETS = {"education": (BASELINE_DEBUG_PARAMS, BASELINE_DEBUG_IBS_PARAMS)}

_MPK_FILE = "mpk.bin"
_MSK_FILE = "msk.bin"


def _require_name(name: str) -> str:
    """身份名同时用作文件名成分：限制为安全的短标识符。"""
    if not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"invalid identity name {name!r}: allowed are 1-64 chars of "
            "[A-Za-z0-9._-] starting with an alphanumeric"
        )
    return name


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
    print(
        f"setup complete: preset={args.params} "
        f"({'TEST-ONLY mock backends' if args.mock else 'abb10+sis debug backends'}, "
        f"security_claim: none)"
    )
    print(f"  wrote {args.state / _MPK_FILE} ({len(pk.to_bytes())} bytes)")
    print(f"  wrote {args.state / _MSK_FILE} ({len(msk.to_bytes())} bytes)")
    return 0


def cmd_issue_sender_key(args) -> int:
    identity = _require_name(args.name).encode("utf-8")
    msk, proto, classes = _load_msk(args.state, args.mock)
    ek = proto.skgen(msk, identity)
    out = args.state / f"sender-{args.name}.bin"
    out.write_bytes(ek.to_bytes())
    print(f"sender key issued for {args.name!r} -> {out} ({len(ek.to_bytes())} bytes)")
    return 0


def cmd_issue_receiver_key(args) -> int:
    identity = _require_name(args.name).encode("utf-8")
    msk, proto, classes = _load_msk(args.state, args.mock)
    dk = proto.rkgen(msk, identity)
    out = args.state / f"receiver-{args.name}.bin"
    out.write_bytes(dk.to_bytes())
    print(f"receiver key issued for {args.name!r} -> {out} ({len(dk.to_bytes())} bytes)")
    return 0


def cmd_encrypt(args) -> int:
    sender = _require_name(args.sender).encode("utf-8")
    receiver = _require_name(args.receiver).encode("utf-8")
    proto, classes = _make_runtime(args.mock)
    pk = PublicKey.from_bytes(
        _read(args.state / _MPK_FILE), classes["hpk"], classes["ipk"]
    )
    ek = SenderKey.from_bytes(
        _read(args.state / f"sender-{args.sender}.bin"), classes["sk"]
    )
    if ek.identity != sender:
        raise ValueError(f"sender key file does not belong to {args.sender!r}")
    message = _read(args.in_path)
    ct = proto.encrypt(pk, ek, receiver, message)
    out = args.out or Path(str(args.in_path) + ".ibme-ct")
    out.write_bytes(ct.to_bytes())
    print(f"encrypted {len(message)}B -> {out} ({len(ct.to_bytes())} bytes)")
    return 0


def cmd_decrypt(args) -> int:
    sender = _require_name(args.sender).encode("utf-8")
    receiver = _require_name(args.receiver).encode("utf-8")
    proto, classes = _make_runtime(args.mock)
    pk = PublicKey.from_bytes(
        _read(args.state / _MPK_FILE), classes["hpk"], classes["ipk"]
    )
    dk = ReceiverKey.from_bytes(
        _read(args.state / f"receiver-{args.receiver}.bin"), classes["sk1"]
    )
    if dk.identity != receiver:
        raise ValueError(f"receiver key file does not belong to {args.receiver!r}")
    data = _read(args.in_path)
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
        "教学/调试参数，security_claim: none",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("setup", help="生成 mpk/msk 并存入状态目录")
    p.add_argument(
        "--params",
        choices=sorted(_PRESETS),
        default="education",
        help="参数预设（当前仅 education：教学/调试参数）",
    )
    _add_common(p)
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("issue-sender-key", help="为发送者身份签发 ek")
    p.add_argument("name", help="身份名（UTF-8，进入算法前转 bytes）")
    _add_common(p)
    p.set_defaults(func=cmd_issue_sender_key)

    p = sub.add_parser("issue-receiver-key", help="为接收者身份签发 dk")
    p.add_argument("name", help="身份名（UTF-8，进入算法前转 bytes）")
    _add_common(p)
    p.set_defaults(func=cmd_issue_receiver_key)

    p = sub.add_parser("encrypt", help="加密消息（--sender 的 ek + --receiver 身份）")
    p.add_argument("--sender", required=True, help="发送者身份名（需已签发 ek）")
    p.add_argument("--receiver", required=True, help="接收者身份名")
    p.add_argument("--in", dest="in_path", type=Path, required=True, help="明文文件")
    p.add_argument("--out", dest="out", type=Path, default=None, help="密文输出文件")
    _add_common(p)
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="解密密文（--receiver 的 dk + --sender 身份）")
    p.add_argument("--receiver", required=True, help="接收者身份名（需已签发 dk）")
    p.add_argument("--sender", required=True, help="声称的发送者身份名")
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
