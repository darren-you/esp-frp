#!/usr/bin/env python3
"""仓外复制 heap 探针，仅启用固定 SDK 的 TLS 动态收发缓冲。"""

import argparse
import hashlib
import shutil
from pathlib import Path


SDKCONFIG = Path("firmware/sdkconfig")
LOCK = Path("firmware/dependencies.lock.esp32")
FRPS_CONFIG = Path("firmware/apps/esp_base/main/qemu_frps_config.h")
OLD_COMPONENTS = "../../../../private/private/tmp/esp32-session-capacity-20260927/heap-probe/firmware/components/"
COMPONENTS = ("esp_container", "esp_frp", "esp_ota", "mqtt")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("heap_probe", type=Path)
    parser.add_argument("output_probe", type=Path)
    args = parser.parse_args()
    baseline = args.heap_probe.resolve(strict=True)
    output = args.output_probe.resolve()
    if output.exists():
        parser.error(f"输出已存在：{output}")
    source_config = (baseline / SDKCONFIG).read_text()
    if source_config.count("# CONFIG_MBEDTLS_DYNAMIC_BUFFER is not set") != 1:
        parser.error("冻结 SDK TLS buffer 输入不符")
    if (baseline / FRPS_CONFIG).read_text().count("29185U") != 1:
        parser.error("仓外 FRPS 端口输入不符")

    shutil.copytree(baseline, output, ignore=shutil.ignore_patterns("build", "*.log"))
    (output / SDKCONFIG).write_text(source_config.replace(
        "# CONFIG_MBEDTLS_DYNAMIC_BUFFER is not set", "CONFIG_MBEDTLS_DYNAMIC_BUFFER=y", 1))
    lock = (output / LOCK).read_text()
    for component in COMPONENTS:
        before = OLD_COMPONENTS + component
        if lock.count(before) != 1:
            parser.error(f"组件锁不符：{component}")
        lock = lock.replace(before, str(output / "firmware/components" / component), 1)
    (output / LOCK).write_text(lock)
    print(f"ESP32_DYNAMIC_TLS_PROBE={output}")
    print(f"SDKCONFIG_SHA256={digest(output / SDKCONFIG)}")


if __name__ == "__main__":
    main()
