#!/usr/bin/env python3
"""从 C3 Yamux 已验证的同输入探针复制工作流惰性分配 A/B。"""

import argparse
import hashlib
import shutil
import tempfile
from pathlib import Path


COMPONENT = Path("firmware/components/esp_frp")
RUNTIME_FILES = (Path("src/work.c"), Path("src/work_internal.h"))
BASELINE_HASHES = {
    Path("firmware/sdkconfig"): "a66858cf817841457a8557a46ec18e5757e4889a5e31dffc0978adf8a277fb52",
    Path("firmware/apps/esp_base/main/frps_session_qemu_probe.c"):
        "601f69047acdca637bbab49dd76f5a29168577705a9b5e8352281b8a334e2ddd",
    COMPONENT / "include/esp_frp_yamux.h":
        "f1c2fb9b6e2b77975bd4fcb6e5f2a9de16c9ffc25e92dd69506cf894b571f5e6",
    COMPONENT / "src/yamux.c":
        "9da9f54d8659b2053b60afcd1cbb0dd0acbfcf8df872c812f551f4a9e0dac2f3",
    COMPONENT / "src/session.c":
        "48810478d39819bbffe61cd7a533675aa75696fe7f32d998c11827e615319a68",
    COMPONENT / "src/work.c":
        "c55ba93bb4e5b2fa9238a5aecc655ba2cc230c43fe7fbfc64f9fb2938e64b52d",
    COMPONENT / "src/work_internal.h":
        "7554b793a3cb4d20461a4cf87d3d39a8b686f5867ade015d0d30c56b61e6d2ee",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def file_hashes(root: Path) -> dict[Path, str]:
    return {path.relative_to(root): digest(path) for path in root.rglob("*") if path.is_file()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline_probe", type=Path)
    parser.add_argument("candidate_frp_source", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    baseline = args.baseline_probe.resolve(strict=True)
    source = args.candidate_frp_source.resolve(strict=True)
    output = args.output_root.resolve()
    if output.exists():
        parser.error(f"输出目录已存在：{output}")
    for relative, expected in BASELINE_HASHES.items():
        actual = digest(baseline / relative)
        if actual != expected:
            parser.error(f"冻结输入不符：{relative} {actual} != {expected}")
    for relative in RUNTIME_FILES:
        if not (source / relative).is_file():
            parser.error(f"候选源码缺少：{relative}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="c3-lazy-work-ab-", dir=output.parent) as staging:
        root = Path(staging)
        old = root / "old" / "probe"
        new = root / "new" / "probe"
        for target in (old, new):
            shutil.copytree(baseline, target, ignore=shutil.ignore_patterns("build"))
        for relative in RUNTIME_FILES:
            shutil.copy2(source / relative, new / COMPONENT / relative)
        old_files = file_hashes(old)
        new_files = file_hashes(new)
        if old_files.keys() != new_files.keys():
            raise ValueError("旧/新工程文件集合不同")
        changed = {path for path in old_files if old_files[path] != new_files[path]}
        expected = {COMPONENT / path for path in RUNTIME_FILES}
        if changed != expected:
            raise ValueError(f"旧/新工程非目标差异：{sorted(map(str, changed ^ expected))}")
        root.rename(output)

    print(f"C3_LAZY_WORK_AB_READY old={output / 'old/probe'} new={output / 'new/probe'}")
    for relative in RUNTIME_FILES:
        print(f"NEW_{relative.name}_SHA256={digest(source / relative)}")


if __name__ == "__main__":
    main()
