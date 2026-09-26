#!/usr/bin/env python3
"""从已冻结的 C3 FRPS QEMU probe 派生同时间输入的旧/新 FRP 对照。"""

import argparse
import hashlib
import shutil
import tempfile
from pathlib import Path


RUNTIME_FILES = (
    ("include/esp_frp_yamux.h", "include/esp_frp_yamux.h"),
    ("src/yamux.c", "src/yamux.c"),
    ("src/session.c", "src/session.c"),
)
PROBE_FILE = Path("firmware/apps/esp_base/main/frps_session_qemu_probe.c")
COMPONENT_DIR = Path("firmware/components/esp_frp")
INCLUDE_OLD = '#include "esp_frp.h"\n'
INCLUDE_NEW = '#include "esp_frp.h"\n#include "esp_base_time.h"\n'
CLOCK_OLD = "    const struct timeval simulated = {.tv_sec = QEMU_FRPS_EPOCH, .tv_usec = 0};\n"
CLOCK_NEW = (
    "    for (unsigned waited_ms = 0; waited_ms < 10000 && !esp_base_time_ready(); waited_ms += 20) {\n"
    "        vTaskDelay(pdMS_TO_TICKS(20));\n"
    "    }\n"
    '    ESP_LOGI(TAG, "frps phase=base_sntp_ready ready=%u", esp_base_time_ready() ? 1u : 0u);\n'
    "    if (!esp_base_time_ready()) {\n"
    '        report_status("base_time_unavailable", EFRP_TIME_UNTRUSTED, NULL);\n'
    "        return false;\n"
    "    }\n"
    + CLOCK_OLD
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replace_once(value: str, before: str, after: str) -> str:
    if value.count(before) != 1:
        raise ValueError(f"冻结探针锚点应恰好出现一次：{before.strip()}")
    return value.replace(before, after)


def changed_files(old: Path, new: Path) -> set[Path]:
    left = {path.relative_to(old) for path in old.rglob("*") if path.is_file()}
    right = {path.relative_to(new) for path in new.rglob("*") if path.is_file()}
    if left != right:
        raise ValueError("旧/新工程文件集合不同")
    return {path for path in left if sha256(old / path) != sha256(new / path)}


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
    for relative, _ in RUNTIME_FILES:
        if not (source / relative).is_file():
            parser.error(f"候选 FRP 缺少文件：{relative}")
    if not (baseline / PROBE_FILE).is_file():
        parser.error("输入不是已准备的 C3 FRPS QEMU probe")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="c3-yamux-clock-ab-", dir=output.parent) as staging:
        root = Path(staging)
        old = root / "old" / "probe"
        new = root / "new" / "probe"
        for target in (old, new):
            shutil.copytree(baseline, target, ignore=shutil.ignore_patterns("build"))
            probe = target / PROBE_FILE
            text = probe.read_text(encoding="utf-8")
            text = replace_once(text, INCLUDE_OLD, INCLUDE_NEW)
            text = replace_once(text, CLOCK_OLD, CLOCK_NEW)
            probe.write_text(text, encoding="utf-8")
        for relative, target_relative in RUNTIME_FILES:
            shutil.copy2(source / relative, new / COMPONENT_DIR / target_relative)
        expected = {COMPONENT_DIR / target for _, target in RUNTIME_FILES}
        actual = changed_files(old, new)
        if actual != expected:
            raise ValueError(f"旧/新工程意外差异：{sorted(map(str, actual ^ expected))}")
        probe_hash = sha256(old / PROBE_FILE)
        if probe_hash != sha256(new / PROBE_FILE):
            raise ValueError("旧/新时间探针不同")
        root.rename(output)

    print(f"C3_YAMUX_CLOCK_AB_READY old={output / 'old/probe'} new={output / 'new/probe'}")
    print(f"CLOCK_PROBE_SHA256={probe_hash}")
    for _, target in RUNTIME_FILES:
        print(f"CANDIDATE_{Path(target).name}_SHA256={sha256(output / 'new/probe' / COMPONENT_DIR / target)}")


if __name__ == "__main__":
    main()
