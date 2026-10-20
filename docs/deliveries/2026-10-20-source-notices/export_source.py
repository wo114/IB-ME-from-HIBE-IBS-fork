"""Export a separate lean source ZIP without changing GitHub/CI source archives."""
import argparse
import io
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[3]
ROOT_REFERENCES = {
    "支持特定功能的格基函数加密研究.pdf", "978-3-031-51476-0_21.pdf", "ib-me.pptx",
}


def export(revision, output):
    revision = subprocess.check_output(
        ["git", "rev-parse", "--verify", revision + "^{commit}"], cwd=ROOT).decode().strip()
    raw = subprocess.check_output(["git", "archive", "--format=zip", revision], cwd=ROOT)
    excluded, retained = [], 0
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(output, "x") as target:
        target.comment = revision.encode()
        for info in source.infolist():
            name = info.filename
            if name in ROOT_REFERENCES or (name.startswith("papers/") and name.lower().endswith(".pdf")):
                excluded.append(name)
                continue
            target.writestr(info, source.read(name))
            if not name.endswith("/"):
                retained += 1
    return dict(status="exported", source_commit=revision, files=retained,
                excluded_reference_files=excluded)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.revision, args.output), indent=2, sort_keys=True))
