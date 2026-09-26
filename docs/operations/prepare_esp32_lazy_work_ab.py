#!/usr/bin/env python3
"""从 ESP32 字宽 AEAD/FRPS 冻结输入派生工作流与 Yamux 合并 A/B。"""

import argparse
import hashlib
import shutil
import tempfile
from pathlib import Path


COMPONENT = Path("firmware/components/esp_frp")
RUNTIME_FILES = (
    Path("src/work.c"), Path("src/work_internal.h"),
    Path("include/esp_frp_yamux.h"), Path("src/yamux.c"), Path("src/session.c"),
)
COMPONENTS = ("esp_container", "esp_frp", "esp_ota", "mqtt")
LOCK = Path("firmware/dependencies.lock.esp32")
PROBE = Path("firmware/apps/esp_base/main/frps_session_qemu_probe.c")
FRPS_CONFIG = Path("firmware/apps/esp_base/main/qemu_frps_config.h")
BASELINE_HASHES = {
    Path("firmware/sdkconfig"): "ea99dc8fe0ca63a2e6009c4df3e9194c8ae98365a1bbc1de6da86c0775ae801b",
    COMPONENT / "src/aead.c": "b20cde4a481b6cd7264fa1f84234e11fe55b7754cb006ed266825679cb4723d5",
    COMPONENT / "src/word_storage.h": "6b51d18873126d9550b8bee4952798499ae9ed0c8d0f3ffcd78ced31b26ff1bd",
    COMPONENT / "src/work.c": "c55ba93bb4e5b2fa9238a5aecc655ba2cc230c43fe7fbfc64f9fb2938e64b52d",
    COMPONENT / "src/work_internal.h": "7554b793a3cb4d20461a4cf87d3d39a8b686f5867ade015d0d30c56b61e6d2ee",
    COMPONENT / "src/session.c": "51dc11977f0e6a6d8fae5a3b089f2ab35c70c29bdd1fe9e10de4adbaed5500ac",
    COMPONENT / "src/yamux.c": "7c684a019d07a3e639de7e5836a739940b180bf9abc52cf296777cd4ff99ab79",
    COMPONENT / "include/esp_frp_yamux.h": "0d00dea162a8791179e4e51d303505ae84f6c8c2c3918dc8552d9e38226b1391",
    PROBE: "5b005bf9a3eb2b91883ee09b6c6da90811da70b607da2cde68484952fafd2e9b",
    FRPS_CONFIG: "27e5f8bfdf676b43b0b28dd9c712334f1745398d7a2019c04a5058723cc148a3",
}
CORRECTED_PROBE_SHA256 = "5b005bf9a3eb2b91883ee09b6c6da90811da70b607da2cde68484952fafd2e9b"
OLD_LOCK_PREFIX = "../../../../private/private/tmp/esp32-frps-session-qemu-20260927/probe-sntp/firmware/components/"


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
    parser.add_argument("corrected_time_probe", type=Path)
    parser.add_argument("output_root", type=Path)
    args = parser.parse_args()
    baseline = args.baseline_probe.resolve(strict=True)
    source = args.candidate_frp_source.resolve(strict=True)
    corrected = args.corrected_time_probe.resolve(strict=True)
    output = args.output_root.resolve()
    if output.exists():
        parser.error(f"输出目录已存在：{output}")
    for relative, expected in BASELINE_HASHES.items():
        actual = digest(baseline / relative)
        if actual != expected:
            parser.error(f"冻结输入不符：{relative} {actual} != {expected}")
    if digest(corrected) != CORRECTED_PROBE_SHA256:
        parser.error("Base SNTP 协调探针与已验证源码不符")
    for relative in RUNTIME_FILES:
        if not (source / relative).is_file():
            parser.error(f"候选源码缺少：{relative}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="esp32-lazy-work-ab-", dir=output.parent) as staging:
        root = Path(staging)
        old = root / "old" / "probe"
        new = root / "new" / "probe"
        for side, target in (("old", old), ("new", new)):
            shutil.copytree(baseline, target, ignore=shutil.ignore_patterns("build", "*.log"))
            shutil.copy2(corrected, target / PROBE)
            lock_file = target / LOCK
            content = lock_file.read_text()
            final_components = output / side / "probe/firmware/components"
            for component in COMPONENTS:
                before = OLD_LOCK_PREFIX + component
                if content.count(before) != 1:
                    raise ValueError(f"组件锁缺少精确路径：{component}")
                content = content.replace(before, str(final_components / component), 1)
            lock_file.write_text(content)
        for relative in RUNTIME_FILES:
            shutil.copy2(source / relative, new / COMPONENT / relative)
        old_files = file_hashes(old)
        new_files = file_hashes(new)
        if old_files.keys() != new_files.keys():
            raise ValueError("旧/新工程文件集合不同")
        changed = {path for path in old_files if old_files[path] != new_files[path]}
        expected = {COMPONENT / path for path in RUNTIME_FILES} | {LOCK}
        if changed != expected:
            raise ValueError(f"旧/新工程非目标差异：{sorted(map(str, changed ^ expected))}")
        old_lock = (old / LOCK).read_text().replace(str(output / "old/probe/firmware/components"), "<components>")
        new_lock = (new / LOCK).read_text().replace(str(output / "new/probe/firmware/components"), "<components>")
        if old_lock != new_lock:
            raise ValueError("组件锁路径归一化后仍有差异")
        root.rename(output)

    print(f"ESP32_LAZY_WORK_AB_READY old={output / 'old/probe'} new={output / 'new/probe'}")
    print(f"CLOCK_PROBE_SHA256={CORRECTED_PROBE_SHA256}")
    for relative in RUNTIME_FILES:
        print(f"NEW_{relative.name}_SHA256={digest(source / relative)}")


if __name__ == "__main__":
    main()
