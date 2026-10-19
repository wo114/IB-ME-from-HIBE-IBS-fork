"""Frozen local runtime rejects changed bytes and unrecorded providers."""

import zipfile

import pytest

from experiments.research.wsl_wheel_runtime import verify_runtime, wheel_manifest


def fixture_wheel(tmp_path):
    wheel = tmp_path / "ibme-0.1.0-py3-none-any.whl"
    files = {"ibme/__init__.py": b"# identical source\n",
             "ibme/native/vendor.c": b"/* vendor source */\n",
             "ibme-0.1.0.dist-info/RECORD": b"pip replaces this metadata\n"}
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    root = tmp_path / "runtime"
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return wheel, root


def test_runtime_detects_vendor_change_and_extra_provider(tmp_path):
    wheel, root = fixture_wheel(tmp_path)
    expected = wheel_manifest(wheel)
    verify_runtime(root, expected)
    vendor = root / "ibme/native/vendor.c"
    original = vendor.read_bytes()
    vendor.write_bytes(b"/* changed source */\n")
    with pytest.raises(ValueError, match="vendor.c"):
        verify_runtime(root, expected)
    vendor.write_bytes(original)
    (root / "ibme/stale.py").write_bytes(b"# unrecorded provider\n")
    with pytest.raises(ValueError, match="unexpected runtime file"):
        verify_runtime(root, expected)


@pytest.mark.parametrize("member", ["../outside.py", "/absolute.py", "ibme\\escape.py", "unrelated/__init__.py"])
def test_wheel_rejects_non_package_or_escaping_paths(tmp_path, member):
    wheel = tmp_path / "ibme-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ibme/__init__.py", b"")
        archive.writestr(member, b"")
    with pytest.raises(ValueError):
        wheel_manifest(wheel)


def test_changed_cache_cannot_hide_behind_unchanged_file_length(tmp_path):
    wheel, root = fixture_wheel(tmp_path)
    expected = wheel_manifest(wheel)
    module = root / "ibme/__init__.py"
    original = module.read_bytes()
    module.write_bytes(original.replace(b"identical", b"different"))
    assert module.stat().st_size == len(original)
    with pytest.raises(ValueError, match="__init__.py"):
        verify_runtime(root, expected)
