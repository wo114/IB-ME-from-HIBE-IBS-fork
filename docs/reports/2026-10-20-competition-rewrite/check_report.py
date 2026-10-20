"""Validate the first competition-report rewrite without running cryptography."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "作品设计报告.tex"
PDF = SOURCE.with_suffix(".pdf")
OLD_SOURCE = ROOT / "docs/reports/2026-10-19-research-draft/研究报告初稿.tex"
OLD_PDF = OLD_SOURCE.with_suffix(".pdf")
REVIEW_FACTS = ROOT / "docs/reports/2026-10-20-revision-review/evidence-facts.json"
SELECTION = ROOT / "docs/deliveries/2026-10-19-report-three-selection/selection.json"
TEMPLATE_FACTS = ROOT / "docs/competition/2026/template-facts.json"


class Checks:
    def __init__(self) -> None:
        self.count = 0
        self.failures: list[str] = []

    def expect(self, label: str, condition: bool, detail: str = "") -> None:
        self.count += 1
        if not condition:
            self.failures.append(label + (f": {detail}" if detail else ""))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-pdf", action="store_true")
    parser.add_argument(
        "--submission-ready",
        action="store_true",
        help="apply final-release checks; expected to fail during the first rewrite batch",
    )
    args = parser.parse_args()

    checks = Checks()
    text = SOURCE.read_text(encoding="utf-8")
    selection = json.loads(SELECTION.read_text(encoding="utf-8"))
    template = json.loads(TEMPLATE_FACTS.read_text(encoding="utf-8"))
    review = json.loads(REVIEW_FACTS.read_text(encoding="utf-8"))

    checks.expect("official template schema", template.get("schema") == "IBME-OFFICIAL-COMPETITION-TEMPLATE/1")
    checks.expect("selection schema", selection.get("schema") == "IBME-REPORT-THREE-SELECTION/1")
    checks.expect("confirmed work number source", review.get("confirmed_work_number") == "CACR2026T4PMR7")
    checks.expect(
        "work number written once as a macro",
        text.count(r"\newcommand{\worknumber}{CACR2026T4PMR7}") == 1,
    )
    checks.expect("work number used on two official fields", text.count(r"\worknumberfield{") == 2)

    for side in ("top", "bottom", "left", "right"):
        checks.expect(f"official {side} margin", f"{side}=20mm" in text)
    checks.expect("official running header", r"\newcommand{\reportheader}{全国密码技术竞赛作品设计报告}" in text)
    logo = ROOT / template["report_template_layout"]["logo_repository_path"]
    checks.expect("official logo exists", logo.is_file(), str(logo))
    if logo.is_file():
        checks.expect(
            "official logo digest",
            hashlib.sha256(logo.read_bytes()).hexdigest()
            == template["report_template_layout"]["logo_sha256"],
        )

    expected_chapters = [
        "研究背景、问题与作品贡献",
        "方案原理与完整协议设计",
        "已实现原语与三组实例化",
        "面向目标规模与重复使用的关键优化",
        "实验设计、对照结果与分析",
        "系统实现与应用展示",
        "总结",
    ]
    chapters = re.findall(r"^\\chapter\{([^}]+)\}", text, flags=re.MULTILINE)
    checks.expect("new seven-chapter structure", chapters == expected_chapters, repr(chapters))
    checks.expect("no numbered appendix", r"\appendix" not in text)
    checks.expect("Chinese abstract", r"\chapter*{摘要}" in text)
    checks.expect("English abstract", r"\chapter*{Abstract}" in text)
    checks.expect("Chinese keywords", "关键词：" in text)
    checks.expect("English keywords", "Keywords:" in text)
    checks.expect("table of contents", r"\tableofcontents" in text)
    checks.expect("subsection hierarchy introduced", text.count(r"\subsection{") >= 7)

    required_fragments = (
        "LATTE-3＋BNN/ML-DSA-44",
        "LATTE-3＋SRGG PARAM-I compact",
        "Lai C2＋Sageloli RSIS v3 PARAM-I",
        "可替换HIBE与IBS的通用装配",
        "从短种子到完整密文的协议工程",
        "面向真实瓶颈的结构、编码与复用优化",
        "NIST安全类别2",
        "目标为100 bit",
        "量子密钥恢复与伪造强度分别为95 bit和93 bit",
        "509.55秒准备",
        "约34.73 MiB",
        "18.87和4.59",
    )
    for fragment in required_fragments:
        checks.expect(f"required report fact: {fragment}", fragment in text)

    forbidden_fragments = (
        "候选路线",
        "十九路线",
        "工作前提",
        "用户决定",
        "准入",
        "registry",
        "profile",
        r"security\_claim",
        r"backend\_admitted",
        r"parameters\_are\_formal",
        "WSL",
        "收据",
    )
    for fragment in forbidden_fragments:
        checks.expect(f"internal process language absent: {fragment}", fragment not in text)
    checks.expect("PR numbers absent", re.search(r"\bPR\s*#?\d+\b", text) is None)
    checks.expect("evidence IDs absent", re.search(r"\bE\d{2}\b", text) is None)

    for token in ("github.com/youzi258", "youzi258", "/home/", "C:\\Users\\"):
        checks.expect(f"anonymous source excludes {token}", token not in text)

    reference_numbers = [
        int(number)
        for number in re.findall(r"^\\noindent\[(\d+)\]", text, flags=re.MULTILINE)
    ]
    checks.expect("eight ordered references", reference_numbers == list(range(1, 9)), repr(reference_numbers))
    checks.expect("balanced TeX groups", text.count(r"\begingroup") == text.count(r"\endgroup"))
    for environment in ("document", "titlepage", "minipage", "tabularx", "table", "tabular"):
        checks.expect(
            f"balanced {environment}",
            text.count(f"\\begin{{{environment}}}") == text.count(f"\\end{{{environment}}}"),
        )

    expected_old_hashes = review["original_report_sha256"]
    for path in (OLD_SOURCE, OLD_PDF):
        relative = path.relative_to(ROOT).as_posix()
        checks.expect(
            f"old report preserved: {relative}",
            hashlib.sha256(path.read_bytes()).hexdigest() == expected_old_hashes[relative],
        )

    if args.require_pdf or args.submission_ready:
        checks.expect("PDF exists", PDF.is_file(), str(PDF))
        if PDF.is_file():
            payload = PDF.read_bytes()
            checks.expect("PDF header", payload.startswith(b"%PDF-"))
            checks.expect("PDF has nontrivial size", len(payload) > 100_000, str(len(payload)))
            checks.expect("PDF is current", PDF.stat().st_mtime_ns >= SOURCE.stat().st_mtime_ns)
            for token in (b"github.com/youzi258", b"youzi258", b"/home/"):
                checks.expect(f"anonymous PDF excludes {token!r}", token not in payload)

    if args.submission_ready:
        checks.expect("all six rewrite batches complete", False, "only batch 1 is complete")

    if checks.failures:
        print(f"Competition report rewrite validation failed: {len(checks.failures)}/{checks.count} checks")
        for failure in checks.failures:
            print(f"- {failure}")
        return 1

    print(f"Competition report rewrite validation passed: {checks.count} checks")
    if not args.require_pdf:
        print("PDF validation not requested; use --require-pdf after compiling")
    return 0


if __name__ == "__main__":
    sys.exit(main())
