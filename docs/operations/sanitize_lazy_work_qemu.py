#!/usr/bin/env python3
"""保存容量 QEMU 的顺序事件并清除设备身份与重复 OpenETH 报错。"""

import argparse
import hashlib
import re
from pathlib import Path


ANSI = re.compile(r"\x1b\[[0-9;]*m")
IDENTITY = re.compile(r"\b(boot_id|device_id)=[^\s]+")
NO_MEMORY = "opencores.emac: no mem for receive buffer"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = args.input.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    selected = [f"# raw_sha256={digest}", "# boot_id/device_id 已脱敏；重复 OpenETH RX 失败只保留首条。"]
    failures = 0
    for line in data.decode(errors="replace").splitlines():
        line = ANSI.sub("", line)
        if NO_MEMORY in line:
            failures += 1
            if failures > 1:
                continue
        elif not any(marker in line for marker in
                     ("ESP_BASE_READY", "ESP_BASE_REPORTED", "five-capacity-", "Guru Meditation", "panic")):
            continue
        selected.append(IDENTITY.sub(lambda match: f"{match.group(1)}=<redacted>", line))
    selected.append(f"# openeth_rx_no_memory_lines={failures}")
    args.output.write_text("\n".join(selected) + "\n")


if __name__ == "__main__":
    main()
