#!/usr/bin/env python3
"""在仓外复制已注册的五仓 C3 QEMU 输入，只加入注册后 AEAD 记录探针。"""

import argparse
import hashlib
import shutil
from pathlib import Path


MAIN = Path("firmware/apps/esp_base/main")
EXPECTED = {
    MAIN / "capacity_runtime_probe.c": "a99ba972cdbaf9f37ecf768f136113dca15903e7bf3fd3787c0de4c128e08654",
    MAIN / "frps_session_qemu_probe.c": "601f69047acdca637bbab49dd76f5a29168577705a9b5e8352281b8a334e2ddd",
    MAIN / "qemu_frps_config.h": "632a954f06e5d28630058964f23b4f7c88f612b17646904b140f6d8e0df68831",
    Path("firmware/sdkconfig"): "a66858cf817841457a8557a46ec18e5757e4889a5e31dffc0978adf8a277fb52",
}
FRP = Path("firmware/components/esp_frp")
BASELINE_FRP = {
    Path("src/aead.c"): "7b480078377b51caa617b2892718e03bc207b1ac5c633087970fc59f0967965f",
    Path("src/session.c"): "48810478d39819bbffe61cd7a533675aa75696fe7f32d998c11827e615319a68",
    Path("src/work.c"): "f0da8a9852e339012c82180e8ac73451a3bc4347b881ff17a1141be40f445f7b",
    Path("src/work_internal.h"): "3b5db34f163aad4771d89ee7cc9b23a5cb778831220f1f4f8e45e56961da7b28",
    Path("src/yamux.c"): "9da9f54d8659b2053b60afcd1cbb0dd0acbfcf8df872c812f551f4a9e0dac2f3",
    Path("include/esp_frp_aead.h"): "ced8e2134e9d106deff062808c0bd12738143eeee78408758e314d34392a7d70",
    Path("include/esp_frp_yamux.h"): "f1c2fb9b6e2b77975bd4fcb6e5f2a9de16c9ffc25e92dd69506cf894b571f5e6",
}
CANDIDATE_FRP = {
    Path("src/aead.c"): "b20cde4a481b6cd7264fa1f84234e11fe55b7754cb006ed266825679cb4723d5",
    Path("src/crypto_backend.h"): "1b7753f0b44f72c9683adb0b6778ed311b2848a25cd0b5984928320149cdea6b",
    Path("src/crypto_openssl.c"): "9798c7e01642c94ca4bbc19f87276142eca2b05acc29b3240674c7553ee89177",
    Path("src/crypto_psa.c"): "6cd9943cc804c07fe65a7ab03fb50f819c71b274ffdcaffb4412f9f771f49842",
    Path("src/session.c"): "06d1513c088bacf571e0a7a49da57e035dbd837f1dd94d3399a03ca96e91892a",
    Path("src/word_storage.h"): "6b51d18873126d9550b8bee4952798499ae9ed0c8d0f3ffcd78ced31b26ff1bd",
    Path("include/esp_frp_aead.h"): "2e710ea5fc8fd398dae1714c0311e5a6d810c5f080a2ca90b81e5f6c3519c366",
    Path("src/work.c"): BASELINE_FRP[Path("src/work.c")],
    Path("src/work_internal.h"): BASELINE_FRP[Path("src/work_internal.h")],
    Path("src/yamux.c"): BASELINE_FRP[Path("src/yamux.c")],
    Path("include/esp_frp_yamux.h"): BASELINE_FRP[Path("include/esp_frp_yamux.h")],
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text()
    if source.count(old) != 1:
        raise ValueError(f"替换锚点不存在或不唯一：{path}: {old[:80]}")
    path.write_text(source.replace(old, new))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate_frp", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--port", type=int, default=29183)
    args = parser.parse_args()
    baseline = args.baseline.resolve(strict=True)
    candidate_frp = args.candidate_frp.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or not 1024 <= args.port <= 65535:
        parser.error("输出目录必须不存在，端口须在 1024..65535")
    for name, expected in EXPECTED.items():
        actual = digest(baseline / name)
        if actual != expected:
            parser.error(f"冻结输入漂移：{name} {actual} != {expected}")
    for name, expected in BASELINE_FRP.items():
        actual = digest(baseline / FRP / name)
        if actual != expected:
            parser.error(f"FRP 基线漂移：{name} {actual} != {expected}")
    for name, expected in CANDIDATE_FRP.items():
        actual = digest(candidate_frp / name)
        if actual != expected:
            parser.error(f"FRP 候选漂移：{name} {actual} != {expected}")

    shutil.copytree(baseline, output, ignore=shutil.ignore_patterns("build"))
    for name in CANDIDATE_FRP:
        shutil.copy2(candidate_frp / name, output / FRP / name)
    runtime = output / MAIN / "capacity_runtime_probe.c"
    session = output / MAIN / "frps_session_qemu_probe.c"
    config = output / MAIN / "qemu_frps_config.h"
    replace_once(config, "#define QEMU_FRPS_PORT 29173U", f"#define QEMU_FRPS_PORT {args.port}U")
    replace_once(runtime, "static void *run_guest(void *argument)",
        "bool capacity_registered_record_probe(void)\n"
        "{\n"
        "    const unsigned failures_before = s_failures;\n"
        "    probe_record(\"registered_4k\", aead_4096_bin_start,\n"
        "                 (size_t)(aead_4096_bin_end - aead_4096_bin_start), 4096, false);\n"
        "    probe_record(\"registered_max\", aead_65536_bin_start,\n"
        "                 (size_t)(aead_65536_bin_end - aead_65536_bin_start), 65536, false);\n"
        "    return failures_before == s_failures;\n"
        "}\n"
        "static void *run_guest(void *argument)")
    replace_once(session, "void capacity_openeth_report_heap(const char *phase, int error);",
        "void capacity_openeth_report_heap(const char *phase, int error);\n"
        "bool capacity_registered_record_probe(void);")
    replace_once(session, '    report_status("result", result, &status);\n'
        '    const efrp_result_t destroyed = efrp_destroy(&client, 5000);',
        '    report_status("result", result, &status);\n'
        '    const bool record_checked = ready && capacity_registered_record_probe();\n'
        '    const efrp_result_t destroyed = efrp_destroy(&client, 5000);')
    replace_once(session, "    return ready && destroyed == EFRP_OK && client == NULL;",
        "    return ready && record_checked && destroyed == EFRP_OK && client == NULL;")

    print(f"REGISTERED_RECORD_QEMU_READY output={output} port={args.port}")
    for name in (MAIN / "capacity_runtime_probe.c", MAIN / "frps_session_qemu_probe.c", MAIN / "qemu_frps_config.h"):
        print(f"{name} sha256={digest(output / name)}")


if __name__ == "__main__":
    main()
