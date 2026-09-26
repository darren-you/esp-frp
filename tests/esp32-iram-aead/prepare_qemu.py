#!/usr/bin/env python3
"""从冻结的五仓 ESP32 QEMU 输入准备独立字宽 AEAD 接收对照工程。"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil


BASELINE = {
    "firmware/sdkconfig": "b1f4e090370e5ac7b20a05cf84faf941f39c847df7b18eccc1e777e90586d6ff",
    "firmware/build/esp_base.bin": "d57ca7be871f59b6366b8614e1349dffb3cba9506c5438571956e1bfae6c4e32",
    "firmware/apps/esp_base/main/capacity_runtime_probe.c": "b1526168e0f0db1a21869a485bd7dc165cdfcbe37e0637ea9d9e0534bf80ea1f",
    "firmware/apps/esp_base/main/aead_4096.bin": "2855df4bd4199f7ce21526c33bcc0b21776adf4d6e5b9f631e43491ea9d30e20",
    "firmware/apps/esp_base/main/aead_65536.bin": "35979812621d6b6778c4086f937991353cfa7f73a4c1aa60dfcfc5507b2542aa",
}
COMPONENTS = ("esp_container", "esp_frp", "esp_ota", "mqtt")
FRP_RUNTIME = {
    "CMakeLists.txt": "a5616d5c04ced70c2df104a703ca8c55b69f8c49310c5384487c6f6e5b377f23",
    "include/esp_frp_aead.h": "2e710ea5fc8fd398dae1714c0311e5a6d810c5f080a2ca90b81e5f6c3519c366",
    "src/aead.c": "b20cde4a481b6cd7264fa1f84234e11fe55b7754cb006ed266825679cb4723d5",
    "src/crypto_backend.h": "1b7753f0b44f72c9683adb0b6778ed311b2848a25cd0b5984928320149cdea6b",
    "src/crypto_psa.c": "6cd9943cc804c07fe65a7ab03fb50f819c71b274ffdcaffb4412f9f771f49842",
    "src/session.c": "51dc11977f0e6a6d8fae5a3b089f2ab35c70c29bdd1fe9e10de4adbaed5500ac",
    "src/word_storage.h": "6b51d18873126d9550b8bee4952798499ae9ed0c8d0f3ffcd78ced31b26ff1bd",
}


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def replace_once(path: Path, old: str, new: str) -> None:
    data = path.read_text()
    if data.count(old) != 1:
        raise SystemExit(f"预期恰好一处接点：{path} {old!r}")
    path.write_text(data.replace(old, new, 1))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path, help="冻结的 Wi-Fi IRAM-off 五仓工程")
    parser.add_argument("frp", type=Path, help="本分支源码的独立副本")
    parser.add_argument("destination", type=Path, help="尚不存在的仓外输出目录")
    args = parser.parse_args()
    baseline, frp, destination = (p.resolve() for p in (args.baseline, args.frp, args.destination))
    if destination.exists() or destination.is_relative_to(baseline) or destination.is_relative_to(frp):
        parser.error("输出已存在或位于输入内部")
    for relative, expected in BASELINE.items():
        path = baseline / relative
        if not path.is_file() or digest(path) != expected:
            parser.error(f"冻结输入摘要不符：{relative}")
    for relative, expected in FRP_RUNTIME.items():
        path = frp / relative
        if not path.is_file() or digest(path) != expected:
            parser.error(f"FRP 运行源码摘要不符：{relative}")
    fixture = Path(__file__).with_name("word_capacity_probe.c")
    shutil.copytree(baseline, destination, ignore=shutil.ignore_patterns("build", "*.log"))
    firmware = destination / "firmware"
    target_component = firmware / "components/esp_frp"
    shutil.rmtree(target_component)
    shutil.copytree(frp, target_component, ignore=shutil.ignore_patterns(".git", "build*", "*.log"))
    lock = firmware / "dependencies.lock.esp32"
    old_prefix = "../../../../private/private/tmp/esp32-auth-wifi-iram-off-exact-20260927/probe/firmware/components/"
    content = lock.read_text()
    for component in COMPONENTS:
        previous = old_prefix + component
        if content.count(previous) != 1:
            parser.error(f"target 锁不匹配：{component}")
        content = content.replace(previous, str(firmware / "components" / component), 1)
    lock.write_text(content)
    main_dir = firmware / "apps/esp_base/main"
    shutil.copy2(fixture, main_dir / "word_capacity_probe.c")
    replace_once(main_dir / "CMakeLists.txt", '"capacity_runtime_probe.c" EMBED_FILES',
                 '"capacity_runtime_probe.c" "word_capacity_probe.c" EMBED_FILES')
    replace_once(main_dir / "CMakeLists.txt", 'REQUIRES esp_frp', 'REQUIRES esp_hw_support esp_frp')
    probe = main_dir / "capacity_runtime_probe.c"
    replace_once(probe, 'static const char *const TAG = "five-capacity-auth";',
                 'static const char *const TAG = "five-capacity-auth";\n'
                 'void capacity_word_probe(const uint8_t *, size_t, const uint8_t *, size_t);')
    replace_once(probe,
                 'probe_record("ready_max", aead_65536_bin_start,\n'
                 '                             (size_t)(aead_65536_bin_end - aead_65536_bin_start), 65536, false);',
                 'probe_record("ready_max", aead_65536_bin_start,\n'
                 '                             (size_t)(aead_65536_bin_end - aead_65536_bin_start), 65536, false);\n'
                 '                capacity_word_probe(aead_4096_bin_start,\n'
                 '                    (size_t)(aead_4096_bin_end - aead_4096_bin_start),\n'
                 '                    aead_65536_bin_start,\n'
                 '                    (size_t)(aead_65536_bin_end - aead_65536_bin_start));')
    print(f"baseline_config_sha256={BASELINE['firmware/sdkconfig']}")
    print(f"baseline_signed_app_sha256={BASELINE['firmware/build/esp_base.bin']}")
    print(f"candidate_config_sha256={digest(firmware / 'sdkconfig')}")
    print(f"candidate_frp_aead_sha256={digest(target_component / 'src/aead.c')}")
    print(f"candidate_frp_words_sha256={digest(target_component / 'src/word_storage.h')}")
    print(f"candidate_fixture_sha256={digest(main_dir / 'word_capacity_probe.c')}")
    print(f"candidate_lock_sha256={digest(lock)}")
    print(f"destination={destination}")


if __name__ == "__main__":
    main()
