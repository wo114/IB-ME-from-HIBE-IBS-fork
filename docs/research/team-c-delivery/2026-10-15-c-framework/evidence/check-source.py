"""Verify public receipts against the frozen Git source; never load private states."""
import hashlib
import json
from pathlib import Path
import subprocess


COMMIT = "9c9fd5aeac2fee68556d980dd0f5e328e530fbdd"
PROFILE_COMMIT = "30aebdf9d0b54a48644e1d69febe1019d5d6b802"
evidence = Path(__file__).resolve().parent
root = Path(subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True
).strip())
profiles = ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
            "falcon-padded-512", "falcon-padded-1024"]
files = {}
recorded = 0


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_sha(path, commit=COMMIT):
    return sha(subprocess.check_output(["git", "show", commit + ":" + path], cwd=root))


def provider_records(value):
    if isinstance(value, dict):
        if set(value) == {"path", "sha256"}:
            yield value
        else:
            for child in value.values():
                yield from provider_records(child)
    elif isinstance(value, list):
        for child in value:
            yield from provider_records(child)


for name in [*("cli-" + profile + ".json" for profile in profiles), "installed.json"]:
    receipt = json.loads((evidence / name).read_bytes())
    assert receipt["status"] == "passed", name
    if name == "installed.json":
        assert receipt["original_instances"] == receipt["restored_decryptions"] == 5
        assert receipt["entropy_bytes"] == receipt["new_roots_or_keys_or_signatures"] == 0
        assert receipt["original_state_unchanged"]
    else:
        assert receipt["source_commit"] == COMMIT
        assert receipt["repetitions"] == 1 and len(receipt["commands"]) == 15
    for value in provider_records(receipt):
        actual = value["path"].replace("\\", "/")
        if name == "installed.json":
            assert actual.startswith(receipt["site"] + "/"), actual
        # Some historical experiments modules alias src/ibme/lattice files.
        # Bind the actual provider path, rather than its logical import name.
        if "/src/ibme/" in actual:
            path = "src/ibme/" + actual.split("/src/ibme/", 1)[1]
        elif "/experiments/" in actual:
            path = "experiments/" + actual.split("/experiments/", 1)[1]
        elif name == "installed.json" and actual.startswith(receipt["site"] + "/ibme/"):
            path = "src/ibme/" + actual[len(receipt["site"] + "/ibme/"):]
        else:
            raise AssertionError((name, "unmapped provider", actual))
        if path not in files:
            files[path] = git_sha(path)
        assert files[path] == value["sha256"], (name, path)
        recorded += 1

extra = ["ci/run.py", "ci/suites.json", "ci/c-combinations.json",
         "experiments/run_combination_matrix.py",
         "experiments/research/c_framework_cli_probe.py",
         "tests/test_c_registration.py", "tests/test_latte_hibe.py",
         "tests/test_assembly.py", "tests/test_cli_selection.py"]
native = subprocess.check_output([
    "git", "ls-tree", "-r", "--name-only", COMMIT, "--",
    "src/ibme/hibe/latte/native/", "src/ibme/ibs/certified/native/",
    "src/ibme/ibs/certified/falcon_native/"
], cwd=root, text=True).splitlines()
for path in [*extra, *native]:
    if path not in files:
        files[path] = git_sha(path)
current_files = {}
changes = {}
for path, expected in files.items():
    current_files[path] = git_sha(path, PROFILE_COMMIT)
    assert sha((root / path).read_bytes()) == current_files[path], ("working source differs", path)
    if current_files[path] != expected:
        changes[path] = current_files[path]
assert set(changes) == {"src/ibme/ibs/certified/registration.py", "tests/test_c_registration.py"}

installed_profile = json.loads((evidence / "profile-installed.json").read_bytes())
assert installed_profile["status"] == "passed"
assert installed_profile["source_commit"] == PROFILE_COMMIT
assert installed_profile["original_instances_restored"] == 5
assert installed_profile["entropy_bytes"] == installed_profile["new_roots_or_keys_or_signatures"] == 0
for value in provider_records(installed_profile):
    actual = value["path"].replace("\\", "/")
    assert actual.startswith(installed_profile["site"] + "/"), actual
    if "/experiments/" in actual:
        path = "experiments/" + actual.split("/experiments/", 1)[1]
    else:
        path = "src/ibme/" + actual[len(installed_profile["site"] + "/ibme/"):]
    assert value["sha256"] == git_sha(path, PROFILE_COMMIT), path

matrix = json.loads((evidence / "combinations.json").read_bytes())
assert matrix["counts"]["pass"] == matrix["executed_cases"] == 10
assert matrix["executed_checks"] == 338 and matrix["security_proof_count"] == 0
allow = [*("cli-" + profile + ".json" for profile in profiles),
         "combinations.json", "combinations.txt", "framework.json", "framework.xml",
         "installed-check.py", "installed.json", "sage.txt", "sage.xml", "wheel.txt",
         "development-eager-import.txt", "development-invalid-hybrid.json",
         "development-preset.txt", "development-restore-guard.json", "check-source.py",
         "profile-install-check.py", "profile-installed.json", "profile-windows.txt", "profile-windows.xml",
         "profile-sage.txt", "profile-sage.xml", "profile-framework.json", "profile-framework.xml",
         "profile-combinations.json", "profile-combinations.txt", "profile-wheel.txt"]
wheel = root / "test-results/c-2026-10-15/wheel-c/ibme-0.1.0-py3-none-any.whl"
wheel_record = {"bytes": 1339957,
                "sha256": "46e7e151912929e7ce4475a8289aa6a79af7ff015d073ac2a818db41433a85fc"}
if wheel.exists():
    assert wheel.stat().st_size == wheel_record["bytes"]
    assert sha(wheel.read_bytes()) == wheel_record["sha256"]
result = dict(status="passed", source_commit=COMMIT, files=dict(sorted(files.items())),
              source_files=len(files), recorded_provider_occurrences=recorded,
              explicit_native_files=len(native), wheel=wheel_record,
              wheel_present_for_recheck=wheel.exists(),
              evidence={name: sha((evidence / name).read_bytes()) for name in allow},
              private_outputs_read_or_copied=False)
profile_wheel = root / "test-results/c-2026-10-15/wheel-c-profile-fix/ibme-0.1.0-py3-none-any.whl"
profile_wheel_record = dict(bytes=1340115, sha256="472ebdf3bcc862475e0652828c4d5da039dcd8771b4edde3588e8a44c4ce1adb")
if profile_wheel.exists():
    assert profile_wheel.stat().st_size == profile_wheel_record["bytes"]
    assert sha(profile_wheel.read_bytes()) == profile_wheel_record["sha256"]
profile_matrix = json.loads((evidence / "profile-combinations.json").read_bytes())
assert profile_matrix["executed_cases"] == profile_matrix["counts"]["pass"] == 10
assert profile_matrix["executed_checks"] == 338
result["profile_dependency_fix"] = dict(source_commit=PROFILE_COMMIT,
    changed_sources=changes, current_files=current_files, installed_providers=len(installed_profile["providers"]),
    original_instances_restored=5, entropy_bytes=0, wheel=profile_wheel_record)
(evidence / "source-check.json").write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(json.dumps({k: result[k] for k in (
    "status", "source_files", "recorded_provider_occurrences", "explicit_native_files", "wheel"
)}))
