#!/usr/bin/env python3
"""编译真实父级 C++ 消费者，核对公共头与 trace 宏的 ABI 传播。"""
from __future__ import annotations

import argparse
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CMAKE_SOURCE = """cmake_minimum_required(VERSION 3.16)
project(esp_frp_public_consumer LANGUAGES C CXX)
add_subdirectory("${EFRP_SOURCE_DIR}" esp_frp)
add_executable(consumer consumer.cpp)
target_compile_features(consumer PRIVATE cxx_std_11)
target_compile_options(consumer PRIVATE -Wall -Wextra -Werror -Wpedantic)
target_compile_definitions(consumer PRIVATE EXPECT_TRACE=${EXPECT_TRACE})
target_link_libraries(consumer PRIVATE esp_frp)
"""
CPP_SOURCE = """#include "esp_frp.h"
#include "esp_frp_quic_peer.h"
#include "esp_frp_udp.h"
#include "esp_frp_yamux.h"
#include <type_traits>
#if EXPECT_TRACE
#ifndef EFRP_LAB_TIMEOUT_TRACE
#error EFRP_LAB_TIMEOUT_TRACE_NOT_PROPAGATED_TO_PARENT_CONSUMER
#endif
#define CHECK_MEMBER(owner, member, type) \\
    static_assert(std::is_same<decltype(owner::member), type>::value, #owner "." #member)
CHECK_MEMBER(efrp_status_t, mux_timeout_source, unsigned);
CHECK_MEMBER(efrp_status_t, control_timeout_source, unsigned);
CHECK_MEMBER(efrp_status_t, mux_timeout_stream_id, uint64_t);
CHECK_MEMBER(efrp_status_t, mux_timeout_age_ms, uint32_t);
CHECK_MEMBER(efrp_status_t, mux_timeout_pending_bytes, uint32_t);
CHECK_MEMBER(efrp_session_status_t, mux_timeout_source, unsigned);
CHECK_MEMBER(efrp_session_status_t, control_timeout_source, unsigned);
CHECK_MEMBER(efrp_session_status_t, mux_timeout_stream_id, uint64_t);
CHECK_MEMBER(efrp_session_status_t, mux_timeout_age_ms, uint32_t);
CHECK_MEMBER(efrp_session_status_t, mux_timeout_pending_bytes, uint32_t);
CHECK_MEMBER(efrp_work_status_t, timeout_source, efrp_work_timeout_source_t);
CHECK_MEMBER(efrp_work_status_t, timeout_stream_id, uint64_t);
CHECK_MEMBER(efrp_work_status_t, timeout_age_ms, uint32_t);
CHECK_MEMBER(efrp_work_status_t, timeout_incoming_bytes, uint16_t);
CHECK_MEMBER(efrp_work_status_t, timeout_outgoing_bytes, uint16_t);
CHECK_MEMBER(efrp_transport_status_t, timeout_source, unsigned);
CHECK_MEMBER(efrp_transport_status_t, timeout_stream_id, uint64_t);
CHECK_MEMBER(efrp_transport_status_t, timeout_age_ms, uint32_t);
CHECK_MEMBER(efrp_transport_status_t, timeout_pending_bytes, uint32_t);
CHECK_MEMBER(efrp_yamux_t, timeout_source, efrp_yamux_timeout_source_t);
CHECK_MEMBER(efrp_yamux_t, timeout_stream_id, uint32_t);
CHECK_MEMBER(efrp_yamux_t, timeout_age_ms, uint32_t);
CHECK_MEMBER(efrp_yamux_t, timeout_pending_bytes, uint32_t);
#undef CHECK_MEMBER
#else
#ifdef EFRP_LAB_TIMEOUT_TRACE
#error EFRP_LAB_TIMEOUT_TRACE_PRESENT_WHEN_OFF
#endif
#endif
// 引用真实 C 导出供 C++ 链接器核对；此程序只编译，不运行。
auto public_binding = &efrp_xtcp_binding_validate;
int main() { return public_binding == nullptr; }
"""


def run(command: list[str], mode: str, stage: str) -> None:
    result = subprocess.run(command, text=True, capture_output=True, timeout=120)
    if result.returncode:
        output = (result.stdout + result.stderr).strip()
        raise RuntimeError(f"TRACE {mode} {stage}失败（退出码 {result.returncode}）\n"
                           f"  命令  {shlex.join(command)}\n{output}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmake", default="cmake", help="CMake 可执行文件，默认从 PATH 读取")
    parser.add_argument("--cmake-prefix-path", help="传给 CMake 的本机依赖前缀，可用分号分隔")
    args = parser.parse_args()
    print("ESP FRP 公共消费者\n  范围  当前源码、父级 C++、OpenSSL、TRACE OFF/ON", flush=True)
    try:
        cmake = shutil.which(args.cmake)
        if not cmake:
            raise RuntimeError("找不到 CMake；使用 --cmake 指定本机可执行文件")
        with tempfile.TemporaryDirectory(prefix="esp-frp-public-consumer-") as directory:
            workspace = Path(directory)
            source = workspace / "consumer"
            source.mkdir()
            (source / "CMakeLists.txt").write_text(CMAKE_SOURCE, encoding="utf-8")
            (source / "consumer.cpp").write_text(CPP_SOURCE, encoding="utf-8")
            for mode, expected in (("OFF", "0"), ("ON", "1")):
                build = workspace / mode.lower()
                configure = [cmake, "-S", str(source), "-B", str(build),
                             f"-DEFRP_SOURCE_DIR={ROOT}", "-DBUILD_TESTING=OFF",
                             f"-DEFRP_LAB_TIMEOUT_TRACE={mode}", f"-DEXPECT_TRACE={expected}",
                             "-DEFRP_MBEDTLS_SOURCE_DIR=", "-DEFRP_PSA_SOURCE_DIR="]
                if args.cmake_prefix_path:
                    configure.append(f"-DCMAKE_PREFIX_PATH={args.cmake_prefix_path}")
                run(configure, mode, "配置")
                run([cmake, "--build", str(build), "--target", "consumer", "--parallel", "2"],
                    mode, "编译与链接")
                print(f"  TRACE {mode:<3}  配置、编译与真实 C 导出链接通过", flush=True)
        print("  结果  通过；程序未运行，临时工程已清理")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"  结果  失败\n  原因  {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
