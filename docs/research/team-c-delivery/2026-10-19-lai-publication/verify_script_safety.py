"""Exercise the wrong-identity driver's workspace handling with a fake CLI.

Run under WSL Python. This checks shell control flow only; it never executes
Lai, creates keys, or counts the fake CLI as cryptographic evidence.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    root = Path(__file__).resolve().parents[4]
    script = root / "experiments/research/candidates/lai/target_wrong_identity.sh"
    subprocess.run(["bash", "-n", str(script)], check=True)
    with tempfile.TemporaryDirectory(prefix="lai-script-check-") as temporary:
        base = Path(temporary)
        state = base / "state"
        state.mkdir()
        (state / "sentinel").write_text("fixture only\n", encoding="utf-8")
        ciphertext = base / "ciphertext"
        ciphertext.write_bytes(b"fixture only")
        fake = base / "fake-python"
        fake.write_text("#!/usr/bin/env bash\nprintf 'BOTTOM\\n'\nexit 1\n", encoding="utf-8")
        fake.chmod(0o700)
        environment = dict(os.environ, PYTHON=str(fake))
        existing = base / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_bytes(b"preserve me")
        environment["WORK"] = str(existing)
        result = subprocess.run(["bash", str(script), str(state), str(ciphertext)],
                                env=environment, capture_output=True, text=True)
        require(result.returncode != 0, "existing WORK was accepted")
        require(sentinel.read_bytes() == b"preserve me", "existing WORK was changed")
        require(sorted(path.name for path in existing.iterdir()) == ["sentinel"],
                "existing WORK gained files")
        environment["WORK"] = str(base / "missing-input-output")
        result = subprocess.run(["bash", str(script), str(base / "missing"), str(ciphertext)],
                                env=environment, capture_output=True, text=True)
        require(result.returncode == 2, "missing input did not reject explicitly")
        require(not Path(environment["WORK"]).exists(), "missing inputs created WORK")
        environment["WORK"] = str(base / "fresh")
        result = subprocess.run(["bash", str(script), str(state), str(ciphertext)],
                                env=environment, capture_output=True, text=True)
        require(result.returncode == 0, "fake CLI control-flow run failed")
        require("WRONG_IDENTITY_MATRIX_OK" in result.stdout, "missing flow result")
        for name in ("recv", "send", "both"):
            require((Path(environment["WORK"]) / name / "sentinel").read_text(
                encoding="utf-8") == "fixture only\n", "state fixture copy differs")
            require((Path(environment["WORK"]) / (name + ".rc")).read_text().strip() == "1",
                    "nonzero CLI return code was swallowed")
        del environment["WORK"]
        environment["TMPDIR"] = str(base)
        result = subprocess.run(["bash", str(script), str(state), str(ciphertext)],
                                env=environment, capture_output=True, text=True)
        require(result.returncode == 0, "default mktemp flow failed")
        paths = list(base.glob("lai-wrong-identity.*"))
        require(len(paths) == 1 and paths[0].is_dir(), "unique run folder missing")
        require((state / "sentinel").read_text(encoding="utf-8") == "fixture only\n",
                "input state was changed")
    print(json.dumps({"status": "passed", "cases": 4,
                      "scope": "shell workspace handling with fake CLI; no cryptographic execution"}))


if __name__ == "__main__":
    main()
