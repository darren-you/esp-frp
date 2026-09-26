#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "用法：$0 <prepare_esp32_lazy_work_ab.py 输出目录> <FRP QEMU runner>" >&2
    exit 2
fi
ab_root=$1
runner=$2
export IDF_PATH=/Users/darrenyou/.cache/darren-space/esp-idf-578cf89
source "$IDF_PATH/export.sh" >/dev/null
test_key=/private/tmp/esp32-auth-capacity-20260927/test-key.pem

for side in old new; do
    probe="$ab_root/$side/probe"
    log_root="$ab_root/$side"
    idf.py -C "$probe/firmware" -DIDF_TARGET=esp32 \
        -DESP_BASE_CONTAINER_BINDING_PROBE=ON -DEFRP_LAB_ESP32_IRAM_AEAD_RX=ON \
        build >"$log_root/build.log" 2>&1
    python -m espsecure verify-signature --version 1 \
        --keyfile "$test_key" "$probe/firmware/build/esp_base.bin" \
        >"$log_root/signature.log" 2>&1
    shasum -a 256 "$probe/firmware/sdkconfig" "$probe/firmware/build/esp_base.bin" \
        "$probe/firmware/build/esp_base.elf" >"$log_root/sha256.txt"

    "$probe/fixture/frps-server" -port 29175 \
        -cert "$probe/fixture/frps_server.pem" \
        -key "$probe/fixture/frps_server_key.pem" >"$log_root/frps.log" 2>&1 &
    frps_test_pid=$!
    trap 'kill -TERM "$frps_test_pid" 2>/dev/null || true' EXIT
    ready=0
    for attempt in 1 2 3 4 5; do
        if rg -q QEMU_FRPS_READY "$log_root/frps.log"; then ready=1; break; fi
        sleep 1
    done
    [[ $ready == 1 ]]
    python3 "$runner" "$probe/firmware" "$log_root/qemu.log" 60
    kill -TERM "$frps_test_pid"
    wait "$frps_test_pid" || true
    trap - EXIT
    echo "$side: $(rg -c 'QEMU_FRPS_READY|QEMU_FRPS_STOPPED' "$log_root/frps.log" | tr '\n' ' ')"
    rg 'frps phase=|probe_summary|no mem for receive buffer' "$log_root/qemu.log" | tail -n 35 || true
done
