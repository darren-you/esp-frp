#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
    echo "用法：$0 <heap-probe 目录> <FRP QEMU runner>" >&2
    exit 2
fi
probe=$1
runner=$2
output_root=$(dirname "$probe")
label=$(basename "$probe")
export IDF_PATH=/Users/darrenyou/.cache/darren-space/esp-idf-578cf89
source "$IDF_PATH/export.sh" >/dev/null
test_key=/private/tmp/esp32-auth-capacity-20260927/test-key.pem

if lsof -nP -iTCP:29185 -sTCP:LISTEN >/dev/null 2>&1; then
    echo "29185 已有监听，停止本轮仿真" >&2
    exit 1
fi
python -m espsecure verify-signature --version 1 \
    --keyfile "$test_key" "$probe/firmware/build/esp_base.bin" \
    >"$output_root/$label-signature.log" 2>&1
shasum -a 256 "$probe/firmware/sdkconfig" "$probe/firmware/build/esp_base.bin" \
    "$probe/firmware/build/esp_base.elf" >"$output_root/$label-sha256.txt"

"$probe/fixture/frps-server" -port 29185 \
    -cert "$probe/fixture/frps_server.pem" \
    -key "$probe/fixture/frps_server_key.pem" >"$output_root/$label-frps.log" 2>&1 &
frps_test_pid=$!
trap 'kill -TERM "$frps_test_pid" 2>/dev/null || true' EXIT
ready=0
for attempt in 1 2 3 4 5; do
    if rg -q QEMU_FRPS_READY "$output_root/$label-frps.log"; then ready=1; break; fi
    sleep 1
done
[[ $ready == 1 ]]
python3 "$runner" "$probe/firmware" "$output_root/$label-qemu.log" 60
kill -TERM "$frps_test_pid"
wait "$frps_test_pid" || true
trap - EXIT
rg 'frps phase=|openeth phase=|probe_summary' "$output_root/$label-qemu.log" | tail -n 45
