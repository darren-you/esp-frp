#!/usr/bin/env python3
"""Run the C3 Flash probe twice against one QEMU MTD image, never a device."""

import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


PARTITION_OFFSET = 0x110000
PARTITION_BYTES = 0x10000
PHASE_MARKERS = (
    b"EFRP_C3_FLASH PHASE1_PASS",
    b"EFRP_C3_FLASH PHASE2_PASS",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_phase(command: list[str], log_path: Path, marker: bytes) -> None:
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                data = log_path.read_bytes()
                if marker in data:
                    return
                if b"EFRP_C3_FLASH fail" in data or b"Guru Meditation Error" in data:
                    raise RuntimeError(f"probe failed; inspect {log_path}")
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU exited {process.returncode}; inspect {log_path}")
                time.sleep(0.2)
            raise TimeoutError(f"QEMU timed out; inspect {log_path}")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: run_qemu.py BUILD_DIRECTORY NEW_OUTPUT_DIRECTORY")
    build = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    image = output / "qemu-flash.bin"
    fixture = (build / "full-record.bin").read_bytes()
    if len(fixture) != 65568:
        raise RuntimeError("full AEAD fixture missing")
    merge = [sys.executable, "-m", "esptool", "--chip", "esp32c3", "merge-bin",
             "--output", str(image), "--pad-to-size", "4MB", "--flash-mode", "dio",
             "--flash-freq", "80m", "--flash-size", "4MB",
             "0x0", str(build / "bootloader" / "bootloader.bin"),
             "0x8000", str(build / "partition_table" / "partition-table.bin"),
             "0x10000", str(build / "esp_frp_c3_flash_scratch.bin")]
    with (output / "merge.log").open("wb") as log:
        subprocess.run(merge, stdout=log, stderr=subprocess.STDOUT, check=True)
    command = [shutil.which("qemu-system-riscv32") or "qemu-system-riscv32",
               "-M", "esp32c3", "-drive", f"file={image},if=mtd,format=raw",
               "-nographic", "-serial", "mon:stdio", "-no-reboot"]
    (output / "commands.txt").write_text(" ".join(merge) + "\n" +
                                          " ".join(command) + "\n", encoding="utf-8")
    receipts = [f"fixture_sha256={hashlib.sha256(fixture).hexdigest()}",
                f"initial_flash_sha256={digest(image)}"]
    for index, marker in enumerate(PHASE_MARKERS, start=1):
        run_phase(command, output / f"phase-{index}.log", marker)
        image_bytes = image.read_bytes()
        expected = bytes([0xFF]) * PARTITION_BYTES if index == 2 else fixture[16:65552]
        if image_bytes[PARTITION_OFFSET:PARTITION_OFFSET + PARTITION_BYTES] != expected:
            raise RuntimeError(f"phase {index} host-side Flash bytes mismatch; inspect {image}")
        if index == 1:
            (output / "phase-1-flash.bin").write_bytes(image_bytes)
        receipts.append(f"phase_{index}_flash_sha256={hashlib.sha256(image_bytes).hexdigest()}")
        receipts.append(f"phase_{index}_scratch_sha256=" + hashlib.sha256(expected).hexdigest())
    (output / "receipt.txt").write_text("\n".join(receipts) + "\n", encoding="ascii")
    print(f"EFRP_C3_FLASH QEMU_PASS output={output}")
    print("\n".join(receipts))


if __name__ == "__main__":
    main()
