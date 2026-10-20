"""Check the LaTeX report against the frozen suites and official 2026 template.

This is a read-only consistency and release-hygiene check.  It does not run
cryptographic code, replace a manual anonymity review, or turn functional
evidence into a security proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE / "研究报告初稿.tex"
PDF = SOURCE.with_suffix(".pdf")
SELECTION = (
    ROOT
    / "docs"
    / "deliveries"
    / "2026-10-19-report-three-selection"
    / "selection.json"
)
TEMPLATE_FACTS = ROOT / "docs" / "competition" / "2026" / "template-facts.json"


class Checks:
    def __init__(self) -> None:
        self.count = 0
        self.failures: list[str] = []

    def expect(self, label: str, condition: bool, detail: str = "") -> None:
        self.count += 1
        if not condition:
            suffix = f": {detail}" if detail else ""
            self.failures.append(label + suffix)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-pdf",
        action="store_true",
        help="also require a nontrivial PDF no older than the LaTeX source",
    )
    parser.add_argument(
        "--submission-ready",
        action="store_true",
        help="require the platform work number and a current PDF in addition to draft checks",
    )
    args = parser.parse_args()

    checks = Checks()
    text = SOURCE.read_text(encoding="utf-8")
    raw_selection = SELECTION.read_bytes()
    selection = json.loads(raw_selection)
    template_facts = json.loads(TEMPLATE_FACTS.read_text(encoding="utf-8"))

    checks.expect(
        "official template schema",
        template_facts.get("schema") == "IBME-OFFICIAL-COMPETITION-TEMPLATE/1",
        str(template_facts.get("schema")),
    )
    imported_templates = template_facts.get("imported_files", [])
    checks.expect("two official blank templates", len(imported_templates) == 2)
    for item in imported_templates:
        relative = item.get("repository_path", "")
        path = ROOT / relative
        checks.expect(f"official file exists: {relative}", path.is_file(), str(path))
        if not path.is_file():
            continue
        payload = path.read_bytes()
        checks.expect(
            f"official file size: {relative}",
            len(payload) == item.get("bytes"),
            f"{len(payload)} != {item.get('bytes')}",
        )
        checks.expect(
            f"official file digest: {relative}",
            hashlib.sha256(payload).hexdigest() == item.get("sha256"),
        )

    official_layout = template_facts.get("report_template_layout", {})
    logo_path = ROOT / official_layout.get("logo_repository_path", "missing")
    checks.expect("official report logo exists", logo_path.is_file(), str(logo_path))
    if logo_path.is_file():
        logo_bytes = logo_path.read_bytes()
        checks.expect(
            "official report logo size",
            len(logo_bytes) == official_layout.get("logo_bytes"),
            str(len(logo_bytes)),
        )
        checks.expect(
            "official report logo digest",
            hashlib.sha256(logo_bytes).hexdigest() == official_layout.get("logo_sha256"),
        )

    checks.expect(
        "selection schema",
        selection.get("schema") == "IBME-REPORT-THREE-SELECTION/1",
        str(selection.get("schema")),
    )
    scope = selection.get("scope", {})
    checks.expect("three selected combinations", scope.get("selected_full_combinations") == 3)
    checks.expect("two HIBE algorithms", scope.get("distinct_hibe_algorithms") == 2)
    checks.expect("three IBS algorithms", scope.get("distinct_ibs_algorithms") == 3)
    checks.expect("five primitive backends", scope.get("distinct_primitive_backends") == 5)
    checks.expect("no cross-environment ranking", scope.get("cross_environment_timing_ranking") is False)
    checks.expect("project admission claim", scope.get("security_claim") == "project-admitted")
    checks.expect("project backend admission", scope.get("backend_admitted") is True)
    checks.expect("project formal parameter flag", scope.get("parameters_are_formal") is True)

    representatives = selection.get("representatives", [])
    expected_ids = [
        "A-latte-mldsa44",
        "B-latte-srgg-I-compact",
        "C-lai-c2-sageloli-I",
    ]
    checks.expect(
        "representative order and IDs",
        [item.get("id") for item in representatives] == expected_ids,
    )
    reps = {item["id"]: item for item in representatives if "id" in item}

    suite_expectations = {
        "A-latte-mldsa44": ("latte", "cert-ml-dsa", "reference"),
        "B-latte-srgg-I-compact": ("latte", "srgg2025-paper", "compact"),
        "C-lai-c2-sageloli-I": ("lai-ideal-hibe", "sageloli-rsis", "reference"),
    }
    for rep_id, expected in suite_expectations.items():
        rep = reps.get(rep_id, {})
        suite_path = SELECTION.parent / rep.get("suite_file", "missing")
        checks.expect(f"{rep_id} suite exists", suite_path.is_file(), str(suite_path))
        if not suite_path.is_file():
            continue
        suite = json.loads(suite_path.read_text(encoding="utf-8"))
        actual = (suite.get("hibe"), suite.get("ibs"), suite.get("signature_format"))
        checks.expect(f"{rep_id} exact backends", actual == expected, repr(actual))
        checks.expect(
            f"{rep_id} exact project admission",
            (
                suite.get("security_claim"),
                suite.get("backend_admitted"),
                suite.get("parameters_are_formal"),
            )
            == ("project-admitted", True, True),
        )
        checks.expect(
            f"{rep_id} records current and evidence digests",
            bool(rep.get("suite_digest")) and bool(rep.get("evidence_suite_digest")),
        )

    def contains(label: str, fragment: str) -> None:
        checks.expect(label, fragment in text, fragment)

    contains("representative A in report", "LATTE-3＋BNN/ML-DSA-44")
    contains("representative B in report", "LATTE-3＋SRGG PARAM-I compact")
    contains("representative C in report", "Lai C2＋Sageloli RSIS v3 PARAM-I")
    contains("project admission in report", "project-admitted/true/true")
    contains("external certification caveat", "不等同于完整 IB-ME 获得外部 NIST 认证")
    contains("different-environment comparison caveat", "不计算跨组加速比")
    contains("Lai paper reference", "Trapdoors for Ideal Lattices with Applications")
    contains("competition cover title", r"\competitiontitle")
    contains("basic information sheet", "基本信息表")
    contains("software-design category", r"\boxtimes\)软件设计")
    contains("table of contents", r"\tableofcontents")
    contains("list of figures", r"\listoffigures")
    contains("list of tables", r"\listoftables")
    contains("competition-style running header", r"\fancypagestyle{mainmatter}")
    contains(
        "official generic running header",
        r"\newcommand{\reportheader}{全国密码技术竞赛作品设计报告}",
    )
    for side in ("top", "bottom", "left", "right"):
        contains(f"official {side} margin", f"{side}=20mm")
    checks.expect("official page-only footer", r"\pageref*{LastPage}" not in text)
    checks.expect("obsolete last-page marker absent", r"\label{LastPage}" not in text)
    checks.expect(
        "work number used on cover and information sheet",
        text.count(r"\worknumberfield{") == 2,
    )

    work_number_match = re.search(
        r"\\newcommand\{\\worknumber\}\{([^{}]*)\}",
        text,
    )
    checks.expect("work number macro exists", work_number_match is not None)
    if args.submission_ready:
        work_number = work_number_match.group(1).strip() if work_number_match else ""
        checks.expect(
            "platform work number filled",
            bool(work_number) and work_number not in {"待填写", "TODO", "TBD"},
        )

    anonymous_forbidden = (
        "github.com/youzi258",
        "youzi258",
        "/home/",
        r"C:\\Users\\",
        "单位名称",
        "领队老师",
        "指导老师",
        "团队成员",
    )
    for fragment in anonymous_forbidden:
        checks.expect(
            f"anonymous source excludes: {fragment}",
            fragment not in text,
        )
    checks.expect(
        "figures numbered within chapters",
        r"\counterwithout{figure}{chapter}" not in text,
    )
    checks.expect(
        "tables numbered within chapters",
        r"\counterwithout{table}{chapter}" not in text,
    )

    if all(rep_id in reps for rep_id in expected_ids):
        a, b, c = (reps[rep_id] for rep_id in expected_ids)
        for label, rep in (("A", a), ("B", b), ("C", c)):
            contains(
                f"{label} application capacity",
                f"{rep['capacity']['max_application_bytes']}B",
            )
        contains(
            "A warm encryption time",
            f"{a['observations']['timing_seconds']['warm-encrypt']['median']:.6f}",
        )
        contains(
            "A warm decryption time",
            f"{a['observations']['timing_seconds']['warm-decrypt']['median']:.6f}",
        )
        contains(
            "B warm encryption time",
            f"{b['observations']['timing_seconds']['warm-encrypt']['median']:.6f}",
        )
        contains(
            "B warm decryption time",
            f"{b['observations']['timing_seconds']['warm-decrypt']['median']:.6f}",
        )
        contains(
            "C encryption observation",
            f"{c['observations']['encrypt_seconds_observation']:.6f}",
        )
        contains(
            "C decryption observation",
            f"{c['observations']['decrypt_seconds_observation']:.6f}",
        )
        contains(
            "C derive observation",
            f"{c['observations']['derive_seconds_observation']:.6f}",
        )
        for label, rep in (("A", a), ("B", b)):
            wire = rep["observations"]["full_ciphertext_bytes"]
            contains(
                f"{label} ciphertext range",
                f"{wire['minimum']}--{wire['maximum']}",
            )
        contains("C ciphertext size", str(c["observations"]["full_ciphertext_bytes"]))
        contains("LATTE dimension", f"N={a['parameter_notes_not_an_alternative_config']['hibe']['N']}")
        contains("LATTE modulus", f"q={a['parameter_notes_not_an_alternative_config']['hibe']['q']}")
        contains("SRGG author target", "原文标称目标100 bit")
        contains("Lai C2 dimension", f"n={c['parameter_notes_not_an_alternative_config']['hibe']['n']}")
        contains("Lai C2 modulus", f"q={c['parameter_notes_not_an_alternative_config']['hibe']['q']}")

    chapters = re.findall(r"^\\chapter\{([^}]+)\}", text, flags=re.MULTILINE)
    expected_chapters = [
        "作品概述",
        "总体方案与安全依据",
        "多算法实例化与参数选择",
        "系统实现与关键技术",
        "实验设计结果与分析",
        "应用展示与技术贡献",
        "总结与后续工作",
        "候选路线与实现状态",
        "参数与公开证据索引",
    ]
    checks.expect("seven body chapters and two appendices", chapters == expected_chapters, repr(chapters))
    checks.expect("eleven longtables", text.count("\\begin{longtable}") == 11)
    checks.expect("six figures", text.count("\\begin{figure}") == 6)
    checks.expect("eleven table labels", text.count(r"\label{tab:") == 11)
    checks.expect("six figure labels", text.count(r"\label{fig:") == 6)
    checks.expect(
        "no hard-coded figure or table references",
        re.search(r"(?:图|表)\d+", text) is None,
    )
    checks.expect("balanced TeX groups", text.count("\\begingroup") == text.count("\\endgroup"))
    for environment in (
        "document",
        "titlepage",
        "minipage",
        "tabularx",
        "longtable",
        "figure",
    ):
        checks.expect(
            f"balanced {environment} environment",
            text.count(f"\\begin{{{environment}}}")
            == text.count(f"\\end{{{environment}}}"),
        )

    figure_paths = re.findall(r"\\includegraphics(?:\[[^]]*\])?\{([^}]+)\}", text)
    checks.expect(
        "cover logo and six body graphic references",
        len(figure_paths) == 7 and figure_paths[0] == "figures/cacr-logo.jpg",
        repr(figure_paths),
    )
    for relative in figure_paths:
        checks.expect(f"figure exists: {relative}", (HERE / relative).is_file())

    evidence_rows = re.findall(r"^(E\d{2})\s*&", text, flags=re.MULTILINE)
    checks.expect(
        "E01 through E17 evidence rows",
        evidence_rows == [f"E{i:02d}" for i in range(1, 18)],
        repr(evidence_rows),
    )
    evidence_paths = re.findall(
        r"\\evidenceitem\{[^{}]*\}\{([^{}]+)\}",
        text,
    )
    checks.expect("twenty-two repository-relative evidence paths", len(evidence_paths) == 22)
    for relative in evidence_paths:
        checks.expect(
            f"evidence path exists: {relative}",
            relative.startswith("docs/") and (ROOT / relative).is_file(),
        )
    bibliography = [
        int(number)
        for number in re.findall(
            r"^\\begingroup\\small\\noindent \[(\d+)\]",
            text,
            flags=re.MULTILINE,
        )
    ]
    checks.expect("fifteen ordered references", bibliography == list(range(1, 16)), repr(bibliography))

    stale_phrases = (
        "最终三代表尚未锁定",
        "最终三代表未选定",
        "当前展示组合的安全元数据为",
        "独立论文参数路线尚未登记",
        "SRGG未配对",
        "Lai理想格HIBE & 无",
        "13个研究后端",
    )
    for phrase in stale_phrases:
        checks.expect(f"stale phrase absent: {phrase}", phrase not in text)

    if args.require_pdf or args.submission_ready:
        checks.expect("PDF exists", PDF.is_file(), str(PDF))
        if PDF.is_file():
            pdf_bytes = PDF.read_bytes()
            checks.expect("PDF header", pdf_bytes.startswith(b"%PDF-"))
            checks.expect("PDF has nontrivial size", len(pdf_bytes) > 100_000, str(len(pdf_bytes)))
            pdf_inputs = [SOURCE]
            pdf_inputs.extend(HERE / relative for relative in figure_paths)
            checks.expect(
                "PDF no older than LaTeX and figures",
                PDF.stat().st_mtime_ns
                >= max(path.stat().st_mtime_ns for path in pdf_inputs if path.is_file()),
            )
            for fragment in (b"github.com/youzi258", b"youzi258", b"/home/"):
                checks.expect(
                    f"PDF bytes exclude anonymous token: {fragment.decode()}",
                    fragment not in pdf_bytes,
                )

    if checks.failures:
        print(f"LaTeX report validation failed: {len(checks.failures)}/{checks.count} checks")
        for failure in checks.failures:
            print(f"- {failure}")
        return 1

    digest = hashlib.sha256(raw_selection).hexdigest()
    print(f"LaTeX report validation passed: {checks.count} checks")
    print(f"selection.json sha256: {digest}")
    if not args.require_pdf:
        print("PDF validation not requested; use --require-pdf after compiling")
    return 0


if __name__ == "__main__":
    sys.exit(main())
