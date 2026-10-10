"""Validate candidate handoff records and render cards; no backend dispatcher.

Metadata availability, algebra checks, working primitives and parameter
admission remain separate. There is no synthetic performance ranking here.
"""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "docs/research/2026-10-10-foundations/catalog.json"
FITS = {"conditional", "unknown", "comparison-only"}
BACKENDS = {"none", "research", "research-lifecycle", "legacy-demo"}
SCENARIOS = {"compact-client", "online-service", "many-identities", "model-comparison"}


def safe_path(root, relative):
    if type(relative) is not str or not relative or "\\" in relative or ":" in relative:
        raise ValueError("repository-relative POSIX path required")
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise ValueError("path escapes the repository")
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root.resolve()): raise ValueError("resolved path escapes repository")
    return resolved


def validate(data, root=ROOT):
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("unknown foundation schema")
    if data.get("security_claim") != "none" or data.get("backend_admitted") is not False:
        raise ValueError("foundation metadata cannot promote a security claim")
    sources, candidates = data.get("sources"), data.get("candidates")
    if not isinstance(sources, dict) or not isinstance(candidates, list) or not candidates:
        raise ValueError("source/candidate registry required")
    for source in sources.values():
        if not isinstance(source, dict) or not isinstance(source.get("url"), str) or not source["url"].startswith("https://"):
            raise ValueError("primary HTTPS source required")
        if source.get("path") is not None:
            path = safe_path(root, source["path"])
            if not path.is_file(): raise ValueError(f"cached source missing: {source['path']}")
            with path.open("rb") as handle:
                if handle.read(4) != b"%PDF": raise ValueError("cached source is not a PDF")
    seen = set()
    for candidate in candidates:
        required = {"id", "role", "label", "family", "sources", "assumptions", "paper_model", "review", "backend",
                    "parameters", "fit", "algorithm_location", "interface_mapping", "assets", "next_steps", "work_area",
                    "probe", "scenario_hypotheses"}
        if not isinstance(candidate, dict) or set(candidate) != required:
            raise ValueError("incomplete/unknown candidate fields")
        identity = candidate["id"]
        if type(identity) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{1,47}", identity) or identity in seen:
            raise ValueError("invalid/duplicate candidate ID")
        seen.add(identity)
        if candidate["role"] not in {"HIBE", "IBS"} or candidate["fit"] not in FITS or candidate["backend"] not in BACKENDS:
            raise ValueError("unknown role/fit/backend state")
        if candidate["parameters"] not in {"not-admitted", "unsafe-teaching", "research-screened"}:
            raise ValueError("unsupported parameter status")
        for key in ("sources", "assumptions", "interface_mapping", "next_steps", "scenario_hypotheses"):
            values = candidate[key]
            if not isinstance(values, list) or not values or any(type(value) is not str or not value for value in values):
                raise ValueError(f"nonempty {key} required")
        if any(source not in sources for source in candidate["sources"]): raise ValueError("unknown source ID")
        if any(scenario not in SCENARIOS for scenario in candidate["scenario_hypotheses"]): raise ValueError("unknown scenario")
        if not isinstance(candidate["assets"], list) or any(not safe_path(root, path).is_file() for path in candidate["assets"]):
            raise ValueError(f"existing asset missing for {identity}")
        area = candidate["work_area"]
        safe_path(root, area)
        if not area.startswith("experiments/research/candidates/"): raise ValueError("foundation work area must stay isolated")
        for key in ("label", "family", "paper_model", "review", "algorithm_location"):
            if type(candidate[key]) is not str or not candidate[key]: raise ValueError("missing candidate description")
    return data


def load(path=CATALOG, root=ROOT):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError("duplicate catalog field")
            result[key] = value
        return result
    if path.stat().st_size > 2**20: raise ValueError("catalog exceeds metadata budget")
    return validate(json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique), root)


def summary(data, root=ROOT):
    validate(data, root)
    cached = {}
    for identity, source in data["sources"].items():
        if source["path"] is not None:
            path = safe_path(root, source["path"])
            cached[identity] = dict(path=source["path"], bytes=path.stat().st_size, sha256=sha256(path.read_bytes()).hexdigest())
    return dict(candidate_entries=len(data["candidates"]), roles=dict(Counter(c["role"] for c in data["candidates"])),
                cached_sources=len(cached), source_records=cached,
                research_backend_entries=[c["id"] for c in data["candidates"] if c["backend"] == "research"],
                admitted_secure_combinations=0, selected_representatives=[], security_claim="none", backend_admitted=False,
                scenario_performance="unknown until common complete-IBME measurements",
                note="Entries include distinct models/instantiations and two certification reserves. Entry count is not an implemented algorithm, hypothesis or combination count.")


def render_cards(data):
    lines = ["# 候选基础卡与接手任务", "", "由 catalog.json 生成；修改目录后使用 candidate_catalog.py 重建。每张卡记录实际调查深度，全部仍 none/false。", "",
             "用户已要求先覆盖全部候选，再完成首套，再按场景选择三套；这些卡没有预先指定获胜方案。数学公共探针不能当原语实例。", ""]
    for c in data["candidates"]:
        lines += [f"## {c['id']}：{c['label']}", "",
                  f"类型：{c['role']}；原文模型：{c['paper_model']}；调查深度：{c['review']}。", "",
                  f"实际后端状态：{c['backend']}；参数状态：{c['parameters']}；组合适配：{c['fit']}。", "",
                  "来源：" + "，".join(f"[{s}]({data['sources'][s]['url']})" for s in c["sources"]) + "。", "",
                  "本地原稿：" + "、".join(data["sources"][s]["path"] or "尚无缓存" for s in c["sources"]) + "。", "",
                  f"算法/引用入口：{c['algorithm_location']}。", "", "假设记录：" + "；".join(c["assumptions"]) + "。", "",
                  "接口与对象：", ""]
        lines += [f"- {item}。" for item in c["interface_mapping"]]
        lines += ["", "已有可复用材料：", ""] + [f"- `{item}`" for item in c["assets"]]
        lines += ["", "接手后先做：", ""] + [f"{i}. {item}。" for i, item in enumerate(c["next_steps"], 1)]
        lines += ["", f"建议基础实验文件范围：`{c['work_area']}`；进入 src 前冻结该方案独立参数/编码并通过单体契约。", "",
                  f"本轮关联探针：{c['probe'] or '仅来源/依赖/接口准备，无真实算法实验'}；公共预检查见 preflight.json 和参数单位账本，候选后续实验见上列可复用材料。", "",
                  "待检验场景优势：" + "、".join(c["scenario_hypotheses"]) + "；这不是性能结论。", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cards", type=Path)
    args = parser.parse_args()
    data = load(args.catalog)
    report = summary(data)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    if args.cards:
        args.cards.parent.mkdir(parents=True, exist_ok=True)
        args.cards.write_text(render_cards(data), encoding="utf-8", newline="\n")
    print(json.dumps({key: report[key] for key in ("candidate_entries", "roles", "cached_sources", "security_claim")}, ensure_ascii=False))


if __name__ == "__main__": main()
