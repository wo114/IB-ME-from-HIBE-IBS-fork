"""Verify the frozen source-Schur package against the merged main checkout.

Three unrelated main-branch files changed after the package was frozen. Their
original bytes are retained here, and every other manifest entry must match
the current checkout exactly. This does not extend the old research claim.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from io import StringIO
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = ROOT / "docs/research/team-b-delivery/2026-10-18-srgg-source-schur"
SOURCE_MANIFEST_SHA256 = "cb763a00b8f3c71dd27767ac05721abf61138e4fc9bc302471330e38d95cb081"
SOURCE_VALIDATION_SHA256 = "4757218ca76254b97a17c685e8c8714c1e52675fec2c7963d4c56e62e3533e6f"
CHANGED = {
    "ci/suites.json": {
        "snapshot": "snapshots/ci-suites-7353770.json",
        "old_bytes": 12074,
        "old_sha256": "a494aa2ef60fa9dd4238ad14eda24b4ce7d61e10ec09f1d840c816ee67b81587",
        "current_bytes": 12473,
        "current_sha256": "251bffb7d8306aee12241c4002daa6d01ae36b14f853e91b27f7857ec5b583bd",
    },
    "src/ibme/lattice/matrix_sampling/mp12_extension.py": {
        "snapshot": "snapshots/mp12-extension-7353770.py",
        "old_bytes": 5834,
        "old_sha256": "efa967995e83fcc2c7dd3ac5030e760ee0b863d9b7858996299d8f1e66b03d0f",
        "current_bytes": 5910,
        "current_sha256": "0bd6b2fc8e7c9cf46ee76530d302ab884658d0af39dedc97bbec55270f27d13f",
    },
    "src/ibme/lattice/matrix_sampling/prime_gadget.py": {
        "snapshot": "snapshots/prime-gadget-frozen.py",
        "old_bytes": 5536,
        "old_sha256": "f936c51e407c11f7d0f13c102f03a77fdebab900b449496c806f9cb156b90311",
        "current_bytes": 6321,
        "current_sha256": "c98d894655f69b7713bb0b8f576a9a5431277e152c799aa1ac5b799c7d7bbabf",
    },
}
SELF_FILES = {
    "README.md", "validation.json", "verify_publication.py", "verify_all_publication.py",
    "snapshots/ci-suites-7353770.json",
    "snapshots/mp12-extension-7353770.py",
    "snapshots/prime-gadget-frozen.py",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def file_bytes(path: Path) -> bytes:
    require(path.is_file(), "missing file: " + str(path))
    return path.read_bytes()


def verify_self() -> None:
    manifest = json.loads(file_bytes(HERE / "MANIFEST.json"))
    require(manifest.get("schema") == "IBME/SRGG-PR-INTEGRATION-MANIFEST/1", "overlay schema")
    require(set(manifest.get("files", {})) == SELF_FILES, "overlay coverage")
    for relative, expected in manifest["files"].items():
        path = (HERE / relative).resolve()
        require(path.is_relative_to(HERE) and path.is_file(), "overlay path")
        data = path.read_bytes()
        require(len(data) == expected.get("bytes") and digest(data) == expected.get("sha256"),
                "overlay byte mismatch: " + relative)


def verify() -> dict:
    verify_self()
    manifest_bytes = file_bytes(SOURCE / "MANIFEST.json")
    validation_bytes = file_bytes(SOURCE / "validation.json")
    require(digest(manifest_bytes) == SOURCE_MANIFEST_SHA256, "frozen source manifest changed")
    require(digest(validation_bytes) == SOURCE_VALIDATION_SHA256, "frozen validation changed")
    manifest = json.loads(manifest_bytes)
    validation = json.loads(validation_bytes)
    entries = manifest.get("files")
    selected = validation.get("selected_current_source_sha256")
    require(type(entries) is dict and len(entries) == 246, "frozen selected-file count")
    require(type(selected) is dict and len(selected) == 204, "frozen source count")
    require(set(CHANGED) <= set(entries) and set(CHANGED) <= set(selected), "changed-file coverage")
    require(validation.get("security_claim") == "none" and
            validation.get("backend_admitted") is False and
            validation.get("parameters_are_formal") is False and
            validation.get("nist_security_category") is None, "security marker drift")
    for relative, expected in entries.items():
        current = file_bytes(ROOT / relative)
        if relative in CHANGED:
            change = CHANGED[relative]
            frozen = file_bytes(HERE / change["snapshot"])
            require(expected == {"bytes": change["old_bytes"], "sha256": change["old_sha256"]},
                    "frozen entry differs: " + relative)
            require(len(frozen) == change["old_bytes"] and digest(frozen) == change["old_sha256"],
                    "historical snapshot differs: " + relative)
            require(len(current) == change["current_bytes"] and digest(current) == change["current_sha256"],
                    "merged-main source differs: " + relative)
            require(selected[relative] == change["old_sha256"], "frozen source map differs")
        else:
            require(len(current) == expected["bytes"] and digest(current) == expected["sha256"],
                    "unexpected source/package drift: " + relative)
    for relative, expected in selected.items():
        require(relative in entries and expected == entries[relative]["sha256"],
                "selected source/manifest mismatch: " + relative)

    # Execute the original verifier with only the three documented original
    # files substituted. All other package and source checks remain live.
    spec = spec_from_file_location("srgg_frozen_source_schur_verifier", SOURCE / "verify_delivery.py")
    require(spec is not None and spec.loader is not None, "original verifier import")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    original_safe_path = module.safe_path

    def frozen_safe_path(relative: str) -> Path:
        if relative in CHANGED:
            return HERE / CHANGED[relative]["snapshot"]
        return original_safe_path(relative)

    module.safe_path = frozen_safe_path
    output = StringIO()
    with redirect_stdout(output):
        module.main()
    original_result = json.loads(output.getvalue().strip())
    require(original_result.get("status") == "verified" and
            original_result.get("manifest_files") == 246 and
            original_result.get("security_claim") == "none", "original verifier result")
    return {
        "schema": "IBME/SRGG-PR-INTEGRATION-VERIFY/1",
        "status": "verified",
        "frozen_manifest_entries": len(entries),
        "unchanged_current_entries": len(entries) - len(CHANGED),
        "upstream_changed_entries": len(CHANGED),
        "selected_source_entries": len(selected),
        "historical_verifier": "verified with three pinned original-source snapshots",
        "security_claim": "none",
        "backend_admitted": False,
        "parameters_are_formal": False,
        "nist_security_category": None,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
