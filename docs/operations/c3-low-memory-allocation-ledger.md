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

## 当前五组件 QEMU 对照

[Base 第二轮 C3 内存复测](https://github.com/esp-space/esp-base/blob/fa4d622f7824924184039a9f365be5548241e3aa/docs/operations/c3-low-memory-base-probe.md)使用 Base `fa4d622`、FRP `c56a0f3`、MQTT `ccf81df`、OTA `3c3f72b`、Container `60b65d2` 与固定 WAMR／ESP-IDF。测试键签名的五组件 QEMU 镜像在**未建立 Wi-Fi、FRPS、Broker 或 OTA 下载会话**时，`ESP_BASE_READY` 的 8-bit free heap／最大连续块为 **152,124／114,688 字节**；64 KiB guest 存活并完成事件调用时为 **61,736／40,960 字节**。FRP、MQTT、OTA 仅被链接，QEMU 专用 ADC2 校准空实现使镜像不能刷写实板。该探针尚未使用下文 Container `bbc186e` 的按节装载实现。

在 guest 存活的这个时点，单次 **65,552 字节** AEAD 接收区申请已分别超过空闲总量 **3,816 字节**、最大连续块 **24,592 字节**；因此现有调用顺序无法再创建 FRP 会话。上表 FRP 显式并存对象总计 **100,496 字节**，比该时点的剩余空闲堆多 **38,760 字节**，尚未计 CA、Mbed TLS／PSA、lwIP、Wi-Fi 或其他动态申请。不能把这些缺口解释为调整分配次序即可消除，也不能据此声称真实板上的最终并发容量。

同一镜像在**没有 guest、没有网络连接**的 READY 时点，即使先扣除 FRP 已知显式对象，也只剩 **51,628 字节**；真实 TLS 握手、CA、网络栈、MQTT 与工作流尚未支付。此时最大连续块 114,688 字节虽大于单次 AEAD 申请，仍不能证明 FRP 会话能完成创建、认证并持续运行。FRP 与 guest 互斥目前也只是待验证的容量假设，不是已经可行的 C3 设计。

## Container 按节装载与代码容量边界

[Container `bbc186e` 的 C3 检查点](https://github.com/esp-space/esp-container/blob/bbc186ed97fc6c6e8ea4f2b71189560679100caf/docs/operations/c3-low-memory-profile.md)已用 WAMR Classic/Normal 按节装载替代完整 Wasm 常驻可写副本，只在模块卸载前持有代码节和数据节的可写副本。它的**另一组**五组件无网络 QEMU 使用 Base `c51c60b`，READY free／最大连续块为 **136,936／114,688 字节**：在 437 字节 counter 中增加 39 KiB 未调用的真实代码节，得到 **40,383 字节**模块，guest 存活时只余 **5,520／1,920 字节**；增加 40 KiB 后的 **41,407 字节**模块在 READY 后 `open` 失败。这个边界只适用于该代码形状和该内存组合，不能写成所有业务 Wasm 的通用上限，也不能把 Base `fa4d622` 的空闲值直接套算成 `bbc186e` 的新运行峰值。

Container 的宿主只读 `mmap→open→munmap→run` 验证了新装载器的输入持有期；现有设备包槽 provider 仍只提供 `esp_partition_read`，没有从已验签 `product.pkg` 包槽到运行期的 `esp_partition_mmap`、槽保护与解除映射接线。此前推导的 **373 KiB Wasm** 只是候选三包槽的 Flash 几何上界，填充自定义节可加载不代表同长度真实代码可运行，也不代表包槽安装或实板已验收。

## 历史组合（不作为当前容量对照）

[旧五组件 QEMU 容量复测](https://github.com/esp-space/esp-container/blob/77155349795f3b6564e6f6fbbacb61e884e583ad/docs/operations/five-component-qemu-capacity-probe.md)使用 Base `31f5ebc`、FRP `c5fbe40`、MQTT `5bff093`、OTA `3c3f72b`、Container `00c788e`。其无网络 READY free／最大连续块为 **101,716／90,112 字节**，64 KiB guest 存活时为 **11,328／7,680 字节**；当时还对完整 Wasm 做可写副本，并观测到 69,632 字节的单页线性内存申请。当前按节装载已改变 Wasm 字节的持有方式，旧组合的空闲量只保留为优化前历史基线，不能再作为最新组合的唯一容量论据。

本分支不以削减合法记录容量、跳过 GCM 认证、削弱 TLS／CA／SNI 或未经实测缩减栈来制造并发通过。FRP 会话与 guest 是否必须同时活跃仍需维护者裁决；真实 C3 上的 Wi-Fi、FRPS、MQTT、OTA、包槽映射和失败路径尚未联合测量。上述 QEMU 数据既不证明互斥可行，也不授权设备写入或改变 4 MiB 分区。

## 核对方法

- `riscv32-esp-elf-gcc -std=c11 -Os -S` 编译仅包含当前 `src/session.c`／`src/client.c` 的仓外尺寸探针；汇编常量分别给出会话 17,688、工作集 6,672、单条工作流 2,192、Yamux 5,552、client 3,088 字节。探针没有改仓内源码。
- 固定 SDK C3 构建的 `tls_mbedtls.c.obj` 调试信息给出 `efrp_tls` 的 `DW_AT_byte_size: 2472`；`src/client_port.h` 固定 worker 栈为 6,144 字节。
- `include/esp_frp_aead.h` 将接收区定义为 `65536 + 16`；`src/session.c` 的 `calloc` 与 `src/aead.c` 的认证后交付路径确认上述对象同时存活和认证顺序。

本记录没有 FRP 源码改动，因此没有新的性能或互操作通过结论。此前独立实板双流与官方 FRPS 互操作记录继续各按原覆盖范围成立；本次五组件并发、真实射频和长稳仍待验收。
