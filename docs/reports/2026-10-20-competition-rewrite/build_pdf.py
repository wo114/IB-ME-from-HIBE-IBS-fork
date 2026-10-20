"""Compile the active competition-report rewrite directly from LaTeX to PDF."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "作品设计报告.tex"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", help="path/name of tectonic, latexmk, or xelatex")
    args = parser.parse_args()
    engine = args.engine or next(
        (
            path
            for name in ("tectonic", "latexmk", "xelatex")
            if (path := shutil.which(name))
        ),
        None,
    )
    if engine is None:
        parser.error("install Tectonic or XeLaTeX/latexmk, or supply --engine")
    engine = shutil.which(engine) or str(Path(engine).expanduser().resolve())
    name = Path(engine).stem.lower()

    with tempfile.TemporaryDirectory(prefix="ibme-report-rewrite-") as build:
        if name == "tectonic":
            command = [engine, "--keep-logs", "--outdir", build, SOURCE.name]
            passes = 1
        elif name == "latexmk":
            command = [
                engine,
                "-xelatex",
                "-halt-on-error",
                "-interaction=nonstopmode",
                "-outdir=" + build,
                SOURCE.name,
            ]
            passes = 1
        elif name == "xelatex":
            command = [
                engine,
                "-halt-on-error",
                "-interaction=nonstopmode",
                "-output-directory=" + build,
                SOURCE.name,
            ]
            passes = 3
        else:
            parser.error("supported engine names: tectonic, latexmk, xelatex")

        for _ in range(passes):
            subprocess.run(command, cwd=HERE, check=True)
        built_pdf = Path(build) / SOURCE.with_suffix(".pdf").name
        if not built_pdf.is_file() or not built_pdf.read_bytes().startswith(b"%PDF-"):
            raise RuntimeError("engine did not produce a valid PDF")
        target = SOURCE.with_suffix(".pdf")
        shutil.copyfile(built_pdf, target)
        print(target)


if __name__ == "__main__":
    main()
