#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 3 ]]; then
    echo "用法：$0 <探针工程> <独立日志目录> <QEMU runner>" >&2
    exit 2
fi
probe=$1
logs=$2
runner=$3
[[ -d $probe/firmware && -x $probe/fixture/frps-server && -f $runner ]]
if [[ -e $logs ]]; then
    echo "日志目录已存在：$logs" >&2
    exit 2
fi
mkdir -m 700 -p "$logs"

port=$(sed -n 's/^#define QEMU_FRPS_PORT \([0-9]*\)U$/\1/p' \
    "$probe/firmware/apps/esp_base/main/qemu_frps_config.h")
[[ -n $port ]]
if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "测试端口已被占用：$port" >&2
    exit 2
fi
export IDF_PATH=/Users/darrenyou/.cache/darren-space/esp-idf-578cf89
source "$IDF_PATH/export.sh" >/dev/null
idf.py -C "$probe/firmware" -D ESP_BASE_CONTAINER_BINDING_PROBE=ON \
    build >"$logs/build.log" 2>&1
python -m espsecure verify-signature --version 2 \
    --keyfile "$probe/test-key.pem" "$probe/firmware/build/esp_base.bin" \
    >"$logs/signature.log" 2>&1
shasum -a 256 "$probe/firmware/sdkconfig" "$probe/firmware/build/esp_base.bin" \
    "$probe/firmware/build/esp_base.elf" >"$logs/sha256.txt"

frps_pid=''
cleanup() {
    if [[ -n $frps_pid ]]; then
        kill -TERM "$frps_pid" 2>/dev/null || true
        wait "$frps_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
"$probe/fixture/frps-server" -port "$port" \
    -cert "$probe/fixture/frps_server.pem" \
    -key "$probe/fixture/frps_server_key.pem" >"$logs/frps.log" 2>&1 &
frps_pid=$!
ready=0
for _ in 1 2 3 4 5; do
    if rg -q QEMU_FRPS_READY "$logs/frps.log"; then ready=1; break; fi
    sleep 1
done
[[ $ready == 1 ]]
python3 "$runner" "$probe/firmware" "$logs/qemu.log" 20
cleanup
frps_pid=''
rg 'ESP_BASE_READY|heap phase=guest_event_done|registered_4k|registered_max|frps phase=|openeth phase=after_cleanup|probe_summary' "$logs/qemu.log" \
    >"$logs/selected.log"
rg 'QEMU_FRPS_READY|QEMU_FRPS_STOPPED' "$logs/frps.log"
cat "$logs/selected.log"
