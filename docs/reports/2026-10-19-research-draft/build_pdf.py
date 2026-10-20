"""Compile the editable LaTeX report directly to PDF, without using Word.

Requires Tectonic, latexmk with XeLaTeX, or XeLaTeX on PATH. Fandol fonts
and the packages named in the source must be available to the TeX engine.
Compilation intermediates stay in a temporary directory. A failed build
does not replace the existing PDF.
"""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE / '研究报告初稿.tex'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', help='path/name of tectonic, latexmk or xelatex')
    args = parser.parse_args()
    engine = args.engine or next(
        (path for name in ('tectonic', 'latexmk', 'xelatex')
         if (path := shutil.which(name))), None)
    if engine is None:
        parser.error('install Tectonic or XeLaTeX/latexmk, or supply --engine')
    engine = shutil.which(engine) or str(Path(engine).expanduser().resolve())
    name = Path(engine).stem.lower()
    with tempfile.TemporaryDirectory(prefix='ibme-report-pdf-') as build:
        if name == 'tectonic':
            command = [engine, '--keep-logs', '--outdir', build, SOURCE.name]
        elif name == 'latexmk':
            command = [engine, '-xelatex', '-halt-on-error', '-interaction=nonstopmode',
                       '-outdir=' + build, SOURCE.name]
        elif name == 'xelatex':
            command = [engine, '-halt-on-error', '-interaction=nonstopmode',
                       '-output-directory=' + build, SOURCE.name]
        else:
            parser.error('supported engine names: tectonic, latexmk, xelatex')
        for _ in range(3 if name == 'xelatex' else 1):
            subprocess.run(command, cwd=HERE, check=True)
        pdf = Path(build) / SOURCE.with_suffix('.pdf').name
        if not pdf.exists() or not pdf.read_bytes().startswith(b'%PDF-'):
            raise RuntimeError('engine did not produce a PDF')
        target = SOURCE.with_suffix('.pdf')
        shutil.copyfile(pdf, target)
        print(target)


if __name__ == '__main__':
    main()
