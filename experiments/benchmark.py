"""M3 基线 IB-ME 基准：耗时与尺寸（AI_WORKFLOW.md §6 M3 门槛）。

测量真实后端组合（ABB10 HIBE + SIS-IBS，教学/调试参数）的
setup / skgen(KeyExt) / rkgen(Extract) / derive / Sign / Verify /
Encrypt / Decrypt 的中位数与四分位数，以及 mpk / ek / dk / ct 的
序列化字节数。结果写入 ``experiments/results/baseline-benchmark.json``
与 ``baseline-benchmark.md``。

用法::

    python experiments/benchmark.py            # 完整运行
    python experiments/benchmark.py --reps-scale 0.3   # 快速冒烟（非正式结果）

可复现性：所有随机性来自固定种子的 DeterministicRandom（HIBE 侧经
方法级 ``rng`` 转发，IBS 侧经构造函数注入）；同版本代码 + 同 Python
下逐次运行得到相同计时样本序列（墙钟时间本身当然随机器波动）。

安全声明（AGENTS.md §7 口径）：

* 参数：``BASELINE_DEBUG_PARAMS``（HIBE，ABB10 调试预设放宽
  ``max_message_bytes=400``）与 ``BASELINE_DEBUG_IBS_PARAMS``
  （= ``IBS_EDUCATION_PARAMS``）；两者均为**教学/调试参数，
  security_claim: none**，未做任何格安全估计；
* HIBE 的身份矩阵 H(·) 与 IBS 的 H1/H2 用域分隔 SHAKE-256 实例化，
  属随机预言机（ROM）风格的工程实例，不是标准模型构造；
* 本基准是纯 Python 参考实现的性能测量，**不构成 LWE/SIS/HIBE/IBS/
  IB-ME 的安全性证明**，也不能外推为任何安全等级。
"""

from __future__ import annotations

import argparse
import datetime
import json
import platform
import statistics
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from ibme.core.encoding import encode_message  # noqa: E402
from ibme.core.randomness import DeterministicRandom  # noqa: E402
from ibme.hibe.abb10 import ABB10HIBE  # noqa: E402
from ibme.ibs.sis_ibs import SisIBSBackend  # noqa: E402
from ibme.protocol.baseline import (  # noqa: E402
    BASELINE_DEBUG_IBS_PARAMS,
    BASELINE_DEBUG_PARAMS,
    BaselineIBME,
)

SEED = b"baseline-benchmark-v1"
ALICE = b"benchmark-alice"  # 发送者身份（16B）
BOB = b"benchmark-bob-rho"  # 接收者身份（16B）
MESSAGE = bytes((i * 37 + 11) & 0xFF for i in range(32))  # 32B 定长消息

#: 操作 -> 重复次数（快操作 >= 30，慢操作 >= 10；AI_WORKFLOW M3 门槛）。
BASE_REPS = {
    "setup": 10,  # trapgen（慢）
    "skgen (KeyExt)": 30,
    "rkgen (Extract)": 30,
    "derive": 10,  # 第二层委派采样（慢）
    "sign": 30,
    "verify": 30,
    "encrypt": 10,  # 400B 级 payload 的 Regev 比特加密（慢）
    "decrypt": 10,  # 含一次 derive + 解码（慢）
}

ROM_NOTE = (
    "HIBE 身份矩阵 H(·) 与 IBS 的 H1/H2 均以域分隔 SHAKE-256 实例化，"
    "属随机预言机（ROM）风格的工程实例，不是标准模型构造。"
)


def _rng(tag: str) -> DeterministicRandom:
    return DeterministicRandom(SEED + b":" + tag.encode())


def _stats(samples: list[float]) -> dict:
    q = statistics.quantiles(samples, n=4, method="inclusive")
    return {
        "reps": len(samples),
        "min_s": round(min(samples), 6),
        "q1_s": round(q[0], 6),
        "median_s": round(statistics.median(samples), 6),
        "q3_s": round(q[2], 6),
        "max_s": round(max(samples), 6),
    }


def run_benchmark(reps_scale: float = 1.0) -> dict:
    timings: dict[str, dict] = {}
    reps = {k: max(2, int(v * reps_scale)) for k, v in BASE_REPS.items()}

    # -- setup（每代独立的协议实例与种子） --------------------------------
    samples = []
    for i in range(reps["setup"]):
        proto = BaselineIBME(ABB10HIBE(), SisIBSBackend(rng=_rng(f"ibs-setup-{i}")))
        t0 = time.perf_counter()
        pk, msk = proto.setup(
            BASELINE_DEBUG_PARAMS,
            ibs_params=BASELINE_DEBUG_IBS_PARAMS,
            rng=_rng(f"setup-{i}"),
        )
        samples.append(time.perf_counter() - t0)
    timings["setup"] = _stats(samples)

    # 基准对象（固定种子，供后续操作复用）
    proto = BaselineIBME(ABB10HIBE(), SisIBSBackend(rng=_rng("ibs-main")))
    pk, msk = proto.setup(
        BASELINE_DEBUG_PARAMS,
        ibs_params=BASELINE_DEBUG_IBS_PARAMS,
        rng=_rng("setup-main"),
    )

    # -- skgen（IBS KeyExt） ----------------------------------------------
    samples = []
    for i in range(reps["skgen (KeyExt)"]):
        t0 = time.perf_counter()
        ek = proto.skgen(msk, ALICE)
        samples.append(time.perf_counter() - t0)
    timings["skgen (KeyExt)"] = _stats(samples)

    # -- rkgen（HIBE Extract） --------------------------------------------
    samples = []
    for i in range(reps["rkgen (Extract)"]):
        t0 = time.perf_counter()
        dk = proto.rkgen(msk, BOB, rng=_rng(f"rk-{i}"))
        samples.append(time.perf_counter() - t0)
    timings["rkgen (Extract)"] = _stats(samples)

    # -- derive（HIBE 第二层委派，后端公共 API） --------------------------
    hibe = proto.hibe_backend
    samples = []
    for i in range(reps["derive"]):
        t0 = time.perf_counter()
        sk2 = hibe.derive(dk.level1_key, ALICE, rng=_rng(f"derive-{i}"))
        samples.append(time.perf_counter() - t0)
    timings["derive"] = _stats(samples)

    # -- sign / verify（IBS 公共 API，对协议的 encode_message 签名） -------
    ibs = proto.ibs_backend
    signed = encode_message(BOB, MESSAGE)
    samples = []
    for i in range(reps["sign"]):
        t0 = time.perf_counter()
        sig = ibs.sign(ek.signing_key, signed)
        samples.append(time.perf_counter() - t0)
    timings["sign"] = _stats(samples)

    samples = []
    for i in range(reps["verify"]):
        t0 = time.perf_counter()
        assert ibs.verify(pk.ipk, ALICE, signed, sig)
        samples.append(time.perf_counter() - t0)
    timings["verify"] = _stats(samples)

    # -- encrypt / decrypt（协议层） ---------------------------------------
    samples = []
    for i in range(reps["encrypt"]):
        t0 = time.perf_counter()
        ct = proto.encrypt(pk, ek, BOB, MESSAGE, rng=_rng(f"enc-{i}"))
        samples.append(time.perf_counter() - t0)
    timings["encrypt"] = _stats(samples)

    samples = []
    for i in range(reps["decrypt"]):
        t0 = time.perf_counter()
        out = proto.decrypt(pk, dk, ALICE, ct, rng=_rng(f"dec-{i}"))
        samples.append(time.perf_counter() - t0)
        assert out == MESSAGE, "benchmark sanity check failed"
    timings["decrypt"] = _stats(samples)

    sizes = {
        "mpk": len(pk.to_bytes()),
        "msk": len(msk.to_bytes()),
        "ek (sender key)": len(ek.to_bytes()),
        "dk (receiver key)": len(dk.to_bytes()),
        "ct (32B message)": len(ct.to_bytes()),
    }
    return {
        "meta": {
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "python_version": sys.version.split()[0],
            "python_implementation": platform.python_implementation(),
            "operating_system": platform.system() + " " + platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor() or "n/a",
            "reps_scale": reps_scale,
        },
        "parameters": {
            "hibe": {
                "name": BASELINE_DEBUG_PARAMS.name,
                "n": BASELINE_DEBUG_PARAMS.n,
                "m_matrix": BASELINE_DEBUG_PARAMS.m_matrix,
                "q": BASELINE_DEBUG_PARAMS.q,
                "s0": BASELINE_DEBUG_PARAMS.s0,
                "s": BASELINE_DEBUG_PARAMS.s,
                "s_prime": BASELINE_DEBUG_PARAMS.s_prime,
                "identity_bytes": BASELINE_DEBUG_PARAMS.identity_bytes,
                "max_message_bytes": BASELINE_DEBUG_PARAMS.max_message_bytes,
                "source": "ibme.hibe.abb10.ABB10_DEBUG_PARAMS（放宽 max_message_bytes）",
                "security_claim": "none（教学/调试参数，未做格安全估计）",
            },
            "ibs": {
                "name": BASELINE_DEBUG_IBS_PARAMS.name,
                "n": BASELINE_DEBUG_IBS_PARAMS.n,
                "m_matrix": BASELINE_DEBUG_IBS_PARAMS.m_matrix,
                "q": BASELINE_DEBUG_IBS_PARAMS.q,
                "s0": BASELINE_DEBUG_IBS_PARAMS.s0,
                "s": BASELINE_DEBUG_IBS_PARAMS.s,
                "s_prime": BASELINE_DEBUG_IBS_PARAMS.s_prime,
                "identity_bytes": BASELINE_DEBUG_IBS_PARAMS.identity_bytes,
                "max_message_bytes": BASELINE_DEBUG_IBS_PARAMS.max_message_bytes,
                "source": "ibme.ibs.sis_ibs.IBS_EDUCATION_PARAMS",
                "security_claim": "none（教学/调试参数，未做格安全估计）",
            },
            "backends": "ABB10 HIBE + SIS-IBS（真实格后端；mock 后端为测试组件，不参与基准）",
            "rom_note": ROM_NOTE,
        },
        "inputs": {
            "sender_identity_bytes": len(ALICE),
            "receiver_identity_bytes": len(BOB),
            "message_bytes": len(MESSAGE),
        },
        "timings_s": timings,
        "sizes_bytes": sizes,
    }


def _render_markdown(report: dict) -> str:
    meta = report["meta"]
    params = report["parameters"]
    inputs = report["inputs"]
    lines = [
        "# 基线 IB-ME 基准报告（M3：耗时与尺寸）",
        "",
        "生成时间（UTC）：{generated_utc}".format(**meta),
        "",
        "## 环境",
        "",
        f"- Python {meta['python_version']}（{meta['python_implementation']}），"
        f"{meta['operating_system']}，{meta['machine']}",
        "- 纯 Python 参考实现（标准库，无第三方依赖）；单线程。",
        "- 随机性：固定种子的 DeterministicRandom（可复现流程），"
        "见脚本 docstring。",
        "",
        "## 参数",
        "",
        "| 组件 | 预设 | n | m_matrix | q | s0 | s | s' | max_message_bytes |",
        "|---|---|---|---|---|---|---|---|---|",
        (
            f"| HIBE (ABB10) | {params['hibe']['name']} | {params['hibe']['n']} | "
            f"{params['hibe']['m_matrix']} | {params['hibe']['q']} | {params['hibe']['s0']} | "
            f"{params['hibe']['s']} | {params['hibe']['s_prime']} | "
            f"{params['hibe']['max_message_bytes']} |"
        ),
        (
            f"| IBS (SIS) | {params['ibs']['name']} | {params['ibs']['n']} | "
            f"{params['ibs']['m_matrix']} | {params['ibs']['q']} | {params['ibs']['s0']} | "
            f"{params['ibs']['s']} | {params['ibs']['s_prime']} | "
            f"{params['ibs']['max_message_bytes']} |"
        ),
        "",
        f"- 后端：{params['backends']}。",
        "- **安全声明**：两个预设均为教学/调试参数（**security_claim: none**，"
        "未做任何格安全估计），不得用于宣称任何安全等级。",
        f"- ROM 说明：{params['rom_note']}",
        "",
        "## 输入规模",
        "",
        f"- 发送者身份 {inputs['sender_identity_bytes']}B，接收者身份 "
        f"{inputs['receiver_identity_bytes']}B，消息 {inputs['message_bytes']}B。",
        "",
        "## 耗时（秒；快操作 >= 30 次，慢操作 >= 10 次）",
        "",
        "| 操作 | 次数 | min | Q1 | 中位数 | Q3 | max |",
        "|---|---|---|---|---|---|---|",
    ]
    for op, s in report["timings_s"].items():
        lines.append(
            f"| {op} | {s['reps']} | {s['min_s']:.6f} | {s['q1_s']:.6f} "
            f"| {s['median_s']:.6f} | {s['q3_s']:.6f} | {s['max_s']:.6f} |"
        )
    lines += [
        "",
        "## 序列化尺寸（字节）",
        "",
        "| 对象 | 字节数 |",
        "|---|---|",
    ]
    for name, size in report["sizes_bytes"].items():
        lines.append(f"| {name} | {size} |")
    lines += [
        "",
        "## 限制",
        "",
        "- 本报告是功能基准：**测试与基准不替代安全性证明**（LWE/SIS/HIBE/"
        "IBS/IB-ME 均未证明），教学参数下也不对应任何论文安全等级。",
        "- 计时为墙钟时间，受机器负载影响；流程（密钥/密文字节）在同版本"
        "代码与同 Python 下逐次可复现。",
        "- HIBE/IBS 采样链为简化分布（无 MP12 扰动），性能数字不代表证明级"
        "参数下的表现（见各后端模块的已知限制声明）。",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--reps-scale",
        type=float,
        default=1.0,
        help="重复次数缩放（默认 1.0 = 正式口径；<1 仅用于快速冒烟）",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "results",
    )
    args = parser.parse_args(argv)

    report = run_benchmark(reps_scale=args.reps_scale)
    args.results_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.results_dir / "baseline-benchmark.json"
    md_path = args.results_dir / "baseline-benchmark.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md_path.write_text(_render_markdown(report), encoding="utf-8")

    print(f"benchmark complete (reps_scale={args.reps_scale})")
    for op, s in report["timings_s"].items():
        print(f"  {op:<18} median {s['median_s']:.4f}s  (n={s['reps']})")
    for name, size in report["sizes_bytes"].items():
        print(f"  size {name:<18} {size} bytes")
    print(f"results: {json_path}")
    print(f"results: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
