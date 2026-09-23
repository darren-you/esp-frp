# P4-04：ESP32-C3 QEMU 客户端回收切片（2026-09-24）

本轮在官方 Espressif QEMU 的 ESP32-C3 机器上运行[独立生命周期探针](../../tests/c3-lifecycle/README.md)，执行真实 `esp-frp` 客户端源码和 ESP-IDF FreeRTOS port。公开基线为 `esp-frp` `3a40a2c06580232bbe23cb981eeb21c4d14d33c1`；只新增测试应用与文档，没有修改协议或客户端实现。

| 对象 | 本轮固定事实 |
| --- | --- |
| ESP-IDF | 公开修复 fork `578cf89c343e388db43ba1f4ddcd602fedcb763c`，`tools/sdk.py check` 通过 |
| ESP lwIP | `2758df4cd3666b3b2a5b53830148379326425c0d` |
| QEMU | 官方 `qemu-riscv32` `esp_develop_9.2.2_20260417`，`qemu-system-riscv32` SHA-256 `3e38982c1ea3e750edfc8c910a0fd44727fe07d9c666b84d18d2b7985ac58246` |
| C3 应用 | `esp_frp_c3_lifecycle.bin` 459056 字节，SHA-256 `3539787de249e93102e72edb1361fd2ba647d0d498e883c1d0949889accdd1d2` |

使用仓外构建目录和 sdkconfig 执行：

```bash
source /absolute/path/to/locked-esp-idf/export.sh
python3 tools/sdk.py check --path "$IDF_PATH"
idf.py -C tests/c3-lifecycle -B /absolute/path/frp-c3-lifecycle-build \
  -D SDKCONFIG=/absolute/path/frp-c3-lifecycle-sdkconfig build
idf.py -C tests/c3-lifecycle -B /absolute/path/frp-c3-lifecycle-build \
  qemu --qemu-extra-args=-no-reboot
```

最终镜像在 QEMU 的串口输出 `EFRP_C3_LIFECYCLE PASS cycles=100 warmup=10 baseline=335572 lowest=335572 final=335572 largest=196608`；没有 fail、heap loss、panic。每轮均确认不可信时间使客户端在网络前进入 `EFRP_PHASE_FAILED`，错误为 `EFRP_TIME_UNTRUSTED`，一次尝试、零重试/就绪会话，然后 stop 完成、worker 归位、destroy 清空句柄。预热后的 100 次空闲 heap 没有下降，最大连续块最终为 196608 字节。QEMU 运行日志留在仓外 `/private/tmp/esp-frp-c3-qemu-run-final.log`，SHA-256 `2a071b8b70b8bbd923af31392d24e278877399dbbd0dd607124b6682c2b8a16a`。

本结果证明同一固定 SDK 上客户端失败和 FreeRTOS 资源回收路径可在 C3 仿真运行。QEMU 没有运行 Wi-Fi/FRPS、TLS、DNS 或 TCP 工作流；它不代替[同源码官方 FRPS 主机矩阵](p4-host-workflow-matrix.md)，也不代替 P4-04 所需的真实 C3 双流、背压、异常协议、百次连接及资源验收。没有设备写入。
