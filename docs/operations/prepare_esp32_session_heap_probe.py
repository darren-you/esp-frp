#!/usr/bin/env python3
"""复制冻结 ESP32 五仓探针，仅在仓外记录 malloc 失败当刻的 8BIT 堆。"""

import argparse
import hashlib
import shutil
from pathlib import Path


SDKCONFIG = Path("firmware/sdkconfig")
OPENETH = Path("firmware/apps/esp_base/main/openeth_qemu_probe.c")
FRPS_CONFIG = Path("firmware/apps/esp_base/main/qemu_frps_config.h")
SESSION = Path("firmware/components/esp_frp/src/session.c")
LOCK = Path("firmware/dependencies.lock.esp32")
EXPECTED = {
    SDKCONFIG: "ea99dc8fe0ca63a2e6009c4df3e9194c8ae98365a1bbc1de6da86c0775ae801b",
    OPENETH: "869161a86b1a4d84faf397134f8829039204428ce73332a6088a55a07ff4f489",
    FRPS_CONFIG: "27e5f8bfdf676b43b0b28dd9c712334f1745398d7a2019c04a5058723cc148a3",
    SESSION: "06d1513c088bacf571e0a7a49da57e035dbd837f1dd94d3399a03ca96e91892a",
}
OLD_COMPONENTS = "../../../../../private/private/tmp/esp32-lazy-work-sntp-ab-20260927/new/probe/firmware/components/"
COMPONENTS = ("esp_container", "esp_frp", "esp_ota", "mqtt")
REPLACEMENTS = (
    (
        "openeth phase=%s error=%d got_ip=%d free=%u largest=%u min=%u alloc_fail=%u last_size=%u last_caps=%u",
        "openeth phase=%s error=%d free=%u largest=%u min=%u fail_free=%u last_size=%u fail_largest=%u",
    ),
    ("phase, (int)error, atomic_load(&s_got_ip),", "phase, (int)error,"),
    (
        "atomic_fetch_add(&s_failed_count, 1);",
        "atomic_store(&s_failed_count, (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT));",
    ),
    (
        "atomic_store(&s_failed_caps, caps);",
        "(void)caps;\n    atomic_store(&s_failed_caps, (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));",
    ),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline_probe", type=Path)
    parser.add_argument("output_probe", type=Path)
    args = parser.parse_args()
    baseline = args.baseline_probe.resolve(strict=True)
    output = args.output_probe.resolve()
    if output.exists():
        parser.error(f"输出已存在：{output}")
    for relative, expected in EXPECTED.items():
        actual = digest(baseline / relative)
        if actual != expected:
            parser.error(f"冻结输入不符：{relative} {actual} != {expected}")

    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(baseline, output, ignore=shutil.ignore_patterns("build", "*.log"))
    source = (output / OPENETH).read_text()
    for before, after in REPLACEMENTS:
        if source.count(before) != 1:
            parser.error(f"OpenETH 定点仪表化匹配数不为 1：{before}")
        source = source.replace(before, after, 1)
    (output / OPENETH).write_text(source)
    port = (output / FRPS_CONFIG).read_text()
    if port.count("29175U") != 1:
        parser.error("FRPS 端口输入不符")
    (output / FRPS_CONFIG).write_text(port.replace("29175U", "29185U", 1))

    lock = (output / LOCK).read_text()
    for component in COMPONENTS:
        before = OLD_COMPONENTS + component
        if lock.count(before) != 1:
            parser.error(f"组件锁不符：{component}")
        lock = lock.replace(before, str(output / "firmware/components" / component), 1)
    (output / LOCK).write_text(lock)
    print(f"ESP32_SESSION_HEAP_PROBE={output}")
    print(f"OPENETH_SHA256={digest(output / OPENETH)}")


if __name__ == "__main__":
    main()
