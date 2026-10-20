"""Read-only upstream Git-source and release archive checks; no crypto execution."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[3]
INDEX = "docs/third-party-code.json"
ROOT_REFERENCES = {
    "支持特定功能的格基函数加密研究.pdf", "978-3-031-51476-0_21.pdf", "ib-me.pptx",
}
REQUIRED = {
    "LICENSE", "NOTICE.md", INDEX, "papers/index.md",
    "src/ibme/cli.py", "src/ibme/assembly/registry.py",
    "docs/reports/2026-10-19-research-draft/研究报告初稿.pdf",
    "docs/competition/2026/附件二-作品设计报告模板.docx",
    "docs/competition/2026/附件三-审批及签字页.docx",
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def blob(revision, name):
    return git("show", revision + ":" + name)


def require(value, message):
    if not value:
        raise ValueError(message)


def verify(revision, archive=None, wheel=None):
    revision = git("rev-parse", "--verify", revision + "^{commit}").decode().strip()
    index = json.loads(blob(revision, INDEX))
    sources, groups = {}, []
    for group in index["components"]:
        manifest_name = group["manifest"]
        parent = PurePosixPath(manifest_name).parent
        manifest = json.loads(blob(revision, manifest_name))
        for name, record in manifest["files"].items():
            path = PurePosixPath(name)
            require(not path.is_absolute() and ".." not in path.parts and str(path) == name,
                    "noncanonical upstream file name")
            target = str(parent / path)
            raw = blob(revision, target)
            require(hashlib.sha256(raw).hexdigest() == record["sha256"], "upstream mismatch: " + target)
            sources[target] = raw
        groups.append(dict(component=group["component"], files=len(manifest["files"])))
    result = dict(status="passed", source_commit=revision, upstream_files=len(sources), groups=groups,
                  crypto_executed=False, private_state_opened=False)
    if archive:
        with zipfile.ZipFile(archive) as zipped:
            require(zipped.comment == revision.encode(), "source archive commit mismatch")
            names = set(zipped.namelist())
            forbidden = sorted(n for n in names if n in ROOT_REFERENCES
                               or (n.startswith("papers/") and n.lower().endswith(".pdf")))
            require(not forbidden, "reference material remains in source archive: " + repr(forbidden))
            required = REQUIRED | set(sources)
            require(required <= names, "source archive missing required files: " + repr(sorted(required - names)))
            for name in required:
                expected = sources[name] if name in sources else blob(revision, name)
                require(zipped.read(name) == expected, "archive source mismatch: " + name)
            result["archive"] = dict(files=len([n for n in names if not n.endswith("/")]),
                                     retained_files_checked=len(required), excluded_reference_pdfs=True,
                                     sha256=hashlib.sha256(Path(archive).read_bytes()).hexdigest(),
                                     bytes=Path(archive).stat().st_size)
    if wheel:
        with zipfile.ZipFile(wheel) as zipped:
            names = zipped.namelist()
            count = 0
            for name, raw in sources.items():
                if name.startswith("src/"):
                    package_name = name.removeprefix("src/")
                    require(package_name in names and zipped.read(package_name) == raw,
                            "wheel upstream missing or changed: " + package_name)
                    count += 1
            for name in ("LICENSE", "NOTICE.md"):
                matches = [n for n in names if n.endswith(".dist-info/licenses/" + name)]
                require(len(matches) == 1 and zipped.read(matches[0]) == blob(revision, name),
                        "wheel root notice missing or changed: " + name)
            result["wheel"] = dict(upstream_files_checked=count, root_notices_checked=2,
                                   sha256=hashlib.sha256(Path(wheel).read_bytes()).hexdigest(),
                                   bytes=Path(wheel).stat().st_size)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--wheel", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.revision, args.archive, args.wheel), indent=2, sort_keys=True))
