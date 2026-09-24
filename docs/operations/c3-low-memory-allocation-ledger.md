# ESP32-C3 小内存 FRP 分配账本

本记录以 `esp-frp@c5fbe40920ae35bceeaf3d086ad9cd9740ebbb65`、公开固定 ESP-IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c` 为 FRP 源码基线。它用于裁决现有 ESP32-C3／4 MiB 上 FRP 与 64 KiB Wasm guest 的并发容量；没有改变协议、分配器、固件分区或设备运行面。

## FRP 当前分配

用固定 C3 RISC-V 编译器 `riscv32-esp-elf-gcc 15.2.0` 对当前头文件和源码中的类型求 `sizeof`，所得 32 位对象尺寸如下。`efrp_session_t` 包含 `efrp_work_set_t`，表中子项不能重复相加。

| 对象或申请 | 字节 | 来源与存活期 |
| --- | ---: | --- |
| `efrp_session_t` | 17,688 | `src/session.c`；认证、注册、已注册和工作流期间 |
| 其中 `efrp_work_set_t` | 6,672 | `src/work_internal.h`；已包含在会话对象中 |
| 其中每条 `efrp_work_stream_t` | 2,192 | 三条共 6,576 字节；已包含在工作集内 |
| `efrp_yamux_t` | 5,552 | `src/session.c` 单独 `calloc`；与会话同寿命 |
| AEAD 接收区 | **65,552** | `src/session.c` 单独 `calloc`；与会话同寿命，容纳完整 64 KiB 明文及 16 字节 GCM tag |
| `efrp_client_t` | 3,088 | `src/client.c`；从 `create` 至 `destroy`，不含 CA 拷贝 |
| FreeRTOS worker 栈 | 6,144 | `src/client_port.h` 与 `src/client_port_idf.c`；从 `create` 至 `destroy` |
| `efrp_tls_t` | 2,472 | 固定 SDK C3 对象的 DWARF `DW_AT_byte_size`；不含 Mbed TLS／PSA 动态分配 |

仅会话、Yamux 和 AEAD 接收区就常驻 **88,792 字节**。加上 client、worker 栈和 TLS 对象为 **100,496 字节**，仍未计 CA 拷贝、Mbed TLS／PSA、lwIP、FreeRTOS 控制结构、socket、cJSON、工作握手临时 4 KiB 区及 Wi-Fi。此数值是这些显式对象的字节求和，不是 FRP 会话的完整堆峰值。

会话创建次序先申请会话对象，再申请 65,552 字节 AEAD 接收区，最后申请 Yamux；严格 TLS 已完成后才进入此路径。完整合法控制记录的 GCM tag 验证成功前，`src/aead.c` 不将明文交给 wire parser。当前合同接受 64 KiB AEAD 明文，不能因常见控制 JSON 较小而把接收区改为小包上限。减小搬运块、Yamux ring 或 worker 栈只影响上表其余部分，无法消除这一完整记录的存储需求；更改申请次序也不改变同时存活的总量。

## 最新五组件 QEMU 对照

[Container 五组件 QEMU 容量复测](https://github.com/darren-you/esp-container/blob/77155349795f3b6564e6f6fbbacb61e884e583ad/docs/operations/five-component-qemu-capacity-probe.md) 使用 Base `31f5ebc`、FRP `c5fbe40`、MQTT `5bff093`、OTA `3c3f72b`、Container `00c788e` 与同一固定 SDK。64 KiB guest 在 `ESP_BASE_READY` 后存活且完成事件调用时，8-bit free heap 为 **11,328 字节**，最大连续块为 **7,680 字节**。此时 FRP／MQTT／OTA 入口只被链接，尚未建立网络会话。

单次 AEAD 申请比该时点空闲总量多 **54,224 字节**，比最大连续块多 **57,872 字节**；即使其余 FRP 对象和 TLS 均不占内存，也无法在此 QEMU 状态创建当前 FRP 会话。`ESP_BASE_READY` 空闲 101,716 字节；同一 WAMR 版本已观测到的 69,632 字节线性内存申请与 AEAD 接收区之和为 135,184 字节，单这两块就比 READY 空闲多 **33,468 字节**，还未计 guest 的其他分配和 FRP 网络资源。

同一 QEMU 镜像在 **没有 guest、没有网络连接**的 `ESP_BASE_READY` 时点，free heap 为 **101,716 字节**，最大连续块为 **90,112 字节**。上表 FRP 显式并存对象合计 **100,496 字节**，与这个时点的 free heap 相差仅 **1,220 字节**；这还是未计 CA、Mbed TLS／PSA 动态内存、lwIP、连接与工作流临时申请的静态下界。此处只把预计同时存活的 FRP 对象与**同一无 guest 时点**的 free heap 比较，没有把 guest 存活后的 11,328 字节再与 READY 数值相加；单次 65,552 字节申请虽然小于 READY 时的最大连续块，也不能证明后续 TLS 握手和会话能分配成功。因此，即使改为 FRP 与 guest 互斥，也必须先在完整五组件镜像中完成真实 FRPS 连接及资源测量，不能把互斥作为已经可行的 C3 设计。

因此，本分支不以削减合法记录容量、跳过 GCM 认证、削弱 TLS／CA／SNI 或未经实测缩减栈来制造并发通过。需先裁决 FRP 会话与 guest 是否必须同时保持活跃，再在真实目标板及实际 Wi-Fi、FRPS、MQTT、OTA 负载下测量可用总堆、最大连续块与失败路径。上述 QEMU 数据只证明本次软件切片的并发容量冲突，并提示无 guest 时 FRP 仍未验收；它不是实板最终预算，也不授权设备写入或改变 4 MiB 分区。

## 核对方法

- `riscv32-esp-elf-gcc -std=c11 -Os -S` 编译仅包含当前 `src/session.c`／`src/client.c` 的仓外尺寸探针；汇编常量分别给出会话 17,688、工作集 6,672、单条工作流 2,192、Yamux 5,552、client 3,088 字节。探针没有改仓内源码。
- 固定 SDK C3 构建的 `tls_mbedtls.c.obj` 调试信息给出 `efrp_tls` 的 `DW_AT_byte_size: 2472`；`src/client_port.h` 固定 worker 栈为 6,144 字节。
- `include/esp_frp_aead.h` 将接收区定义为 `65536 + 16`；`src/session.c` 的 `calloc` 与 `src/aead.c` 的认证后交付路径确认上述对象同时存活和认证顺序。

本记录没有 FRP 源码改动，因此没有新的性能或互操作通过结论。此前独立实板双流与官方 FRPS 互操作记录继续各按原覆盖范围成立；本次五组件并发、真实射频和长稳仍待验收。
