"""Interactive local demo for the IB-ME assembly.

This is a *demonstration* front end, not a production service. It keeps one
ephemeral session in process memory, never writes private key material to disk,
and never exposes the master secret to the browser. All suites retain
``security_claim=none``, ``backend_admitted=false`` and
``parameters_are_formal=false``.

Run in the prescribed WSL Sage environment::

    PYTHONPATH=src python -m ibme.webui --port 8765

The browser page is served from the same origin, so no CORS or external
JavaScript is required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
import traceback
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ibme.assembly import build_runtime, list_backends, make_suite, validate_suite
from ibme.core.errors import IBMEError
from ibme.protocol.baseline import is_bottom

STATIC = Path(__file__).resolve().parent / "static"
MAX_BODY = 1 << 20
_LOCK = threading.RLock()
_SESSION: "Session | None" = None

SECURITY = {
    "claim": "none",
    "backend_admitted": False,
    "parameters_are_formal": False,
    "note": "研究/函数性参数；功能与性能演示不构成安全证明或 NIST 等级声明。",
}

RECOMMENDED_HIBE = {"latte"}
RECOMMENDED_IBS = {"cert-ml-dsa", "cert-falcon", "luo-module"}
# The interactive demo intentionally exposes one HIBE engine. Other research
# HIBEs (ABB-ROM, CHKP, MP12 variants) remain available through the CLI and the
# report matrix; some have minute-scale Setup or need optional runtimes, which
# would block a single-threaded demo server.
DEMO_HIBE = {"latte"}
# Only IBS routes that have a short, runnable demonstration path here. The
# remaining research IBS backends stay reachable through the CLI and tests.
DEMO_IBS = {"cert-ml-dsa", "cert-falcon", "luo-module"}

PRESETS = [
    {
        "id": "primary",
        "label": "LATTE-3 + ML-DSA-44",
        "note": "推荐主演示：NTRU/RLWE HIBE + MLWE/MSIS 认证 IBS，Hybrid + BYTEAUTH。",
        "hibe": "latte",
        "ibs": "cert-ml-dsa",
        "transport": "hybrid",
        "protocol": "byteauth-v1",
        "signature_format": "reference",
        "tone": "primary",
    },
    {
        "id": "compact",
        "label": "LATTE-3 + Falcon-512",
        "note": "紧凑签名对照：Falcon v1.2 padded-512，完整密文通常略小。",
        "hibe": "latte",
        "ibs": "cert-falcon",
        "transport": "hybrid",
        "protocol": "byteauth-v1",
        "signature_format": "reference",
        "tone": "blue",
    },
    {
        "id": "native",
        "label": "LATTE-3 + Luo 模格",
        "note": "原生格 IBS 对照：MLWE/MSIS，compact 编码，签名较长。",
        "hibe": "latte",
        "ibs": "luo-module",
        "transport": "hybrid",
        "protocol": "byteauth-v1",
        "signature_format": "compact",
        "tone": "teal",
    },
]


class DemoError(Exception):
    """A user-facing input or state error."""


@dataclass
class Session:
    config: Any
    runtime: Any
    public: Any
    master: Any
    sender_key: Any
    receiver_key: Any
    wrong_receiver_key: Any
    sender_id: bytes
    receiver_id: bytes
    wrong_id: bytes
    timings: dict[str, float] = field(default_factory=dict)
    sizes: dict[str, int] = field(default_factory=dict)
    wire: bytes | None = None
    message: bytes | None = None
    ciphertext_sha256: str = ""
    created_at: float = field(default_factory=time.time)


def _suite_summary(config) -> dict[str, Any]:
    data = config.to_dict()
    return {
        "hibe": data["hibe"],
        "hibe_version": data["hibe_version"],
        "ibs": data["ibs"],
        "ibs_version": data["ibs_version"],
        "transport": data["transport"],
        "protocol": data["protocol"],
        "signature_format": data["signature_format"],
        "digest": config.digest,
        "security_claim": data["security_claim"],
        "backend_admitted": data["backend_admitted"],
        "parameters_are_formal": data["parameters_are_formal"],
    }


def _selection(payload: dict[str, Any]) -> tuple[str, str, str, str, str]:
    def text(name: str, default: str) -> str:
        value = payload.get(name, default)
        if not isinstance(value, str) or not value or len(value) > 128:
            raise DemoError(f"字段 {name} 不合法")
        return value

    def choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
        value = text(name, default)
        if value not in allowed:
            raise DemoError(f"字段 {name} 不支持：{value!r}")
        return value

    hibe = text("hibe", "latte")
    if hibe not in DEMO_HIBE:
        raise DemoError("交互演示仅开放 LATTE-3 HIBE；其它 HIBE 后端请使用 CLI 或报告矩阵。")
    ibs = text("ibs", "cert-ml-dsa")
    if ibs not in DEMO_IBS:
        raise DemoError("交互演示仅开放 ML-DSA、Falcon、Luo 三种 IBS；其它 IBS 后端请使用 CLI 或报告矩阵。")
    return (
        hibe,
        ibs,
        choice("transport", "hybrid", ("direct", "hybrid")),
        choice("protocol", "byteauth-v1", ("byteauth-v1", "baseline-v1")),
        choice("signature_format", "reference", ("reference", "compact")),
    )


def _make_config(payload: dict[str, Any]):
    hibe, ibs, transport, protocol, signature_format = _selection(payload)
    try:
        return make_suite(
            hibe=hibe,
            ibs=ibs,
            transport=transport,
            protocol=protocol,
            signature_format=signature_format,
            allow_mock=False,
        )
    except IBMEError as exc:
        raise DemoError(str(exc)) from exc


def _identity_bytes(text: Any, label: str, capacity: int) -> bytes:
    if not isinstance(text, str):
        raise DemoError(f"{label}必须是字符串")
    if not text.strip():
        raise DemoError(f"{label}不能为空")
    raw = text.encode("utf-8")
    if len(raw) > capacity:
        raise DemoError(f"{label} UTF-8 长度 {len(raw)} B，超过上限 {capacity} B")
    if any(byte < 0x20 or byte == 0x7F for byte in raw):
        raise DemoError(f"{label}不能包含控制字符")
    return raw


def _message_bytes(text: Any, capacity: int) -> bytes:
    if not isinstance(text, str):
        raise DemoError("消息必须是字符串")
    raw = text.encode("utf-8")
    if not raw:
        raise DemoError("消息不能为空")
    if len(raw) > capacity:
        raise DemoError(f"消息 UTF-8 长度 {len(raw)} B，超过上限 {capacity} B")
    return raw


def _display(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()


def _state_summary(session: Session) -> dict[str, Any]:
    return {
        "active": True,
        "suite": _suite_summary(session.config),
        "capacity": dict(session.runtime.capacity),
        "identities": {
            "sender": _display(session.sender_id),
            "receiver": _display(session.receiver_id),
            "wrong_receiver": _display(session.wrong_id),
        },
        "sizes": dict(session.sizes),
        "timings": dict(session.timings),
        "last_message": _display(session.message) if session.message is not None else None,
        "has_ciphertext": session.wire is not None,
        "ciphertext_sha256": session.ciphertext_sha256,
        "security": SECURITY,
        "created_at": session.created_at,
    }


def _available_rows(rows: list[dict[str, Any]], role: str) -> list[dict[str, Any]]:
    recommended = RECOMMENDED_HIBE if role == "hibe" else RECOMMENDED_IBS
    result = []
    for row in rows:
        if not row.get("available") or row.get("test_only"):
            continue
        if role == "hibe" and row["id"] not in DEMO_HIBE:
            continue
        if role == "ibs" and row["id"] not in DEMO_IBS:
            continue
        result.append(
            {
                "id": row["id"],
                "version": row.get("version", ""),
                "reason": row.get("reason", ""),
                "presets": row.get("parameter_presets", []),
                "signature_formats": row.get("signature_formats", ["reference"]),
                "runtime_available": row.get("runtime_available", False),
                "runtime_reason": row.get("runtime_reason", ""),
                "recommended": row["id"] in recommended,
            }
        )
    result.sort(key=lambda item: (not item["recommended"], item["id"]))
    return result


def api_backends() -> dict[str, Any]:
    try:
        listing = list_backends()
    except Exception as exc:  # optional research packages can be absent
        raise DemoError(f"无法读取后端目录：{type(exc).__name__}: {exc}") from exc
    return {
        "ok": True,
        "hibe": _available_rows(listing.get("hibe", []), "hibe"),
        "ibs": _available_rows(listing.get("ibs", []), "ibs"),
        "presets": PRESETS,
        "scope": {
            "hibe": sorted(DEMO_HIBE),
            "ibs": sorted(DEMO_IBS),
            "note": "交互演示开放 LATTE-3 HIBE 与 ML-DSA / Falcon / Luo 三种 IBS；其它后端请使用 CLI 或报告矩阵。",
        },
        "security": SECURITY,
    }


def api_state() -> dict[str, Any]:
    with _LOCK:
        if _SESSION is None:
            return {"ok": True, "active": False, "state": None, "security": SECURITY}
        return {"ok": True, "active": True, "state": _state_summary(_SESSION), "security": SECURITY}


def api_check(payload: dict[str, Any]) -> dict[str, Any]:
    config = _make_config(payload)
    report = validate_suite(config)
    return {
        "ok": report.ok,
        "errors": list(report.errors),
        "capacity": dict(report.capacity),
        "metadata": report.metadata,
        "suite": _suite_summary(config),
        "suite_config": config.to_dict(),
        "security": SECURITY,
    }


def api_bootstrap(payload: dict[str, Any]) -> dict[str, Any]:
    global _SESSION
    with _LOCK:
        config = _make_config(payload)
        report = validate_suite(config)
        if not report.ok:
            raise DemoError("；".join(report.errors))
        capacity = int(report.capacity.get("identity_bytes", 0))
        if capacity <= 0:
            raise DemoError("该组合没有可用的身份容量")
        sender_id = _identity_bytes(payload.get("sender", "Alice"), "发送者身份", capacity)
        receiver_id = _identity_bytes(payload.get("receiver", "Bob"), "接收者身份", capacity)
        wrong_id = _identity_bytes(payload.get("wrong_receiver", "Carol"), "错误接收者身份", capacity)
        if len({sender_id, receiver_id, wrong_id}) != 3:
            raise DemoError("发送者、接收者和错误接收者必须是三个不同的身份")

        events: list[dict[str, Any]] = []
        start = time.perf_counter()
        try:
            runtime = build_runtime(config)
        except IBMEError as exc:
            raise DemoError(f"构建运行时失败：{exc}") from exc
        build_seconds = time.perf_counter() - start
        events.append({"label": "构建运行时", "seconds": build_seconds})

        start = time.perf_counter()
        public, master = runtime.proto.setup(runtime.hibe_params, ibs_params=runtime.ibs_params)
        setup_seconds = time.perf_counter() - start
        events.append({"label": "Setup", "seconds": setup_seconds})

        start = time.perf_counter()
        sender_key = runtime.proto.skgen(master, sender_id)
        sender_seconds = time.perf_counter() - start
        events.append({"label": "签发发送者密钥", "seconds": sender_seconds})

        start = time.perf_counter()
        receiver_key = runtime.proto.rkgen(master, receiver_id)
        receiver_seconds = time.perf_counter() - start
        events.append({"label": "签发接收者密钥", "seconds": receiver_seconds})

        start = time.perf_counter()
        wrong_receiver_key = runtime.proto.rkgen(master, wrong_id)
        wrong_seconds = time.perf_counter() - start
        events.append({"label": "签发错误接收者密钥", "seconds": wrong_seconds})

        session = Session(
            config=config,
            runtime=runtime,
            public=public,
            master=master,
            sender_key=sender_key,
            receiver_key=receiver_key,
            wrong_receiver_key=wrong_receiver_key,
            sender_id=sender_id,
            receiver_id=receiver_id,
            wrong_id=wrong_id,
        )
        session.timings = {
            "build": build_seconds,
            "setup": setup_seconds,
            "sender_key": sender_seconds,
            "receiver_key": receiver_seconds,
            "wrong_receiver_key": wrong_seconds,
        }
        session.sizes = {
            "mpk": len(public.to_bytes()),
            "msk": len(master.to_bytes()),
            "sender_key": len(sender_key.to_bytes()),
            "receiver_key": len(receiver_key.to_bytes()),
            "wrong_receiver_key": len(wrong_receiver_key.to_bytes()),
        }
        _SESSION = session
        return {
            "ok": True,
            "state": _state_summary(session),
            "events": events,
            "security": SECURITY,
        }


def api_encrypt(payload: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        session = _SESSION
        if session is None:
            raise DemoError("请先初始化演示会话")
        capacity = int(session.runtime.capacity["max_application_bytes"])
        message = _message_bytes(payload.get("message", ""), capacity)
        start = time.perf_counter()
        try:
            ciphertext = session.runtime.proto.encrypt(
                session.public, session.sender_key, session.receiver_id, message
            )
        except IBMEError as exc:
            raise DemoError(f"加密失败：{exc}") from exc
        seconds = time.perf_counter() - start
        wire = ciphertext.to_bytes()
        session.wire = wire
        session.message = message
        session.ciphertext_sha256 = hashlib.sha256(wire).hexdigest()
        session.timings["encrypt"] = seconds
        session.sizes["ciphertext"] = len(wire)
        session.sizes["message"] = len(message)
        return {
            "ok": True,
            "ciphertext": {
                "bytes": len(wire),
                "sha256": session.ciphertext_sha256,
                "seconds": seconds,
                "message_bytes": len(message),
            },
            "state": _state_summary(session),
            "security": SECURITY,
        }


def _decrypt_detail(mode: str, session: Session) -> str:
    sender = _display(session.sender_id)
    receiver = _display(session.receiver_id)
    wrong = _display(session.wrong_id)
    if mode == "normal":
        return f"接收者 {receiver} 与声称发送者 {sender} 同时匹配密文身份 ({receiver}, {sender})。"
    if mode == "wrong_sender":
        return f"{receiver} 的密钥只能派生 ({receiver}, {sender})；声称发送者为 {wrong} 时无法恢复。"
    if mode == "wrong_receiver":
        return f"{wrong} 的密钥对应 ({wrong}, {sender})，与密文身份 ({receiver}, {sender}) 不匹配。"
    if mode == "both_wrong":
        return f"{wrong} 的密钥与声称发送者 {wrong} 都不匹配密文身份 ({receiver}, {sender})。"
    if mode == "tamper":
        return "完整外层字节被翻转 1 bit；BYTEAUTH 的字节认证拒绝该密文。"
    if mode == "truncate":
        return "密文末尾被截断；严格解析与字节认证拒绝该密文。"
    return "未知解密模式"


def api_decrypt(payload: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        session = _SESSION
        if session is None:
            raise DemoError("请先初始化演示会话")
        if session.wire is None:
            raise DemoError("请先加密一条消息")
        mode = payload.get("mode", "normal")
        if mode not in {"normal", "wrong_sender", "wrong_receiver", "both_wrong", "tamper", "truncate"}:
            raise DemoError("未知解密模式")
        wire = session.wire
        if mode == "normal":
            receiver_key, claimed_sender = session.receiver_key, session.sender_id
        elif mode == "wrong_sender":
            receiver_key, claimed_sender = session.receiver_key, session.wrong_id
        elif mode == "wrong_receiver":
            receiver_key, claimed_sender = session.wrong_receiver_key, session.sender_id
        elif mode == "both_wrong":
            receiver_key, claimed_sender = session.wrong_receiver_key, session.wrong_id
        elif mode == "tamper":
            receiver_key, claimed_sender = session.receiver_key, session.sender_id
            raw = bytearray(wire)
            position = len(raw) // 2
            raw[position] ^= 0x01
            wire = bytes(raw)
        else:  # truncate
            receiver_key, claimed_sender = session.receiver_key, session.sender_id
            wire = wire[:-1]
        start = time.perf_counter()
        try:
            result = session.runtime.proto.decrypt(
                session.public, receiver_key, claimed_sender, wire
            )
        except IBMEError as exc:
            if mode in {"tamper", "truncate"}:
                result = None
            else:
                raise DemoError(f"解密失败：{exc}") from exc
        seconds = time.perf_counter() - start
        bottom = result is None or is_bottom(result)
        text = None if bottom else _display(result)
        session.timings[f"decrypt_{mode}"] = seconds
        return {
            "ok": True,
            "mode": mode,
            "bottom": bottom,
            "message": text,
            "seconds": seconds,
            "detail": _decrypt_detail(mode, session),
            "claimed_sender": _display(claimed_sender),
            "receiver": _display(receiver_key.identity),
            "state": _state_summary(session),
            "security": SECURITY,
        }


def api_reset() -> dict[str, Any]:
    global _SESSION
    with _LOCK:
        _SESSION = None
    return {"ok": True, "active": False, "security": SECURITY}


class Handler(BaseHTTPRequestHandler):
    server_version = "IBMEdemo/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib name
        print(f"[webui] {self.address_string()} {fmt % args}", flush=True)

    def _send(self, status: int, body: Any, content_type: str = "application/json; charset=utf-8") -> None:
        if isinstance(body, bytes):
            data = body
        else:
            data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - stdlib name
        path = urlparse(self.path).path
        try:
            if path in ("/", "/index.html"):
                self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif path == "/api/backends":
                self._send(200, api_backends())
            elif path == "/api/state":
                self._send(200, api_state())
            elif path == "/favicon.ico":
                self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
            else:
                self._send(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
        except DemoError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        except Exception as exc:  # pragma: no cover - defensive boundary
            traceback.print_exc()
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        path = urlparse(self.path).path
        routes = {
            "/api/check": api_check,
            "/api/bootstrap": api_bootstrap,
            "/api/encrypt": api_encrypt,
            "/api/decrypt": api_decrypt,
        }
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length < 0 or length > MAX_BODY:
                raise DemoError("请求体过大")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DemoError("请求体不是合法 JSON") from exc
            if not isinstance(payload, dict):
                raise DemoError("请求体必须是 JSON 对象")
            if path == "/api/reset":
                self._send(200, api_reset())
                return
            handler = routes.get(path)
            if handler is None:
                self._send(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
                return
            self._send(200, handler(payload))
        except DemoError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        except IBMEError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        except Exception as exc:  # pragma: no cover - defensive boundary
            traceback.print_exc()
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IB-ME interactive demo UI (research parameters only)")
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: 0.0.0.0 for WSL2 localhost forwarding)")
    parser.add_argument("--port", type=int, default=8765, help="TCP port (default: 8765)")
    args = parser.parse_args(argv)
    # Sage's cysignals initialisation installs signal handlers and therefore
    # requires the main interpreter thread. Use the single-threaded HTTPServer
    # so every backend operation runs in that thread; the demo serialises
    # requests anyway and one browser session does not need concurrency.
    server = HTTPServer((args.host, args.port), Handler)
    print("IB-ME interactive demo", flush=True)
    print(f"  URL: http://127.0.0.1:{args.port}", flush=True)
    print("  security_claim=none; research/functional parameters only", flush=True)
    print("  press Ctrl+C to stop", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
