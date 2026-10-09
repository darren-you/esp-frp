# P6-03：FRP 会话握手与 Flash 窗口阶段复用检查点

2026-09-27。基线为 `9a0839a603ed1f6bbce0d1b3c65a6bb43e501cf3`。本轮只改变 `src/session.c` 内 4096 字节 Flash reader 窗口的存放位置：从会话常驻字段移入握手／已认证控制联合区。FRP wire、认证、最大记录、Flash provider、分区和运行目标均未改变。

## 生命周期核对

| 路径 | 联合区与资源边界 |
| --- | --- |
| 创建和握手失败 | 联合区只承载握手；未初始化的 reader 执行 `close` 不触碰窗口，`clear` 销毁握手并清零联合区。 |
| LoginResp 完成 | `take_result` 复制方向密钥与 run ID，解除对握手缓存的借用；`handshake_destroy` 清零旧联合区，之后才在控制成员内初始化 Flash reader。 |
| 已认证控制 | Flash reader 窗口与 wire parser `json_rx` 位于控制成员内不同地址，可以同时持有当前窗口明文与部分 wire 帧。握手对象不再访问联合区。 |
| 错误、取消和 stop | `clear` 先关闭 reader，再清零联合区。若 Flash `clear` 失败，reader 保留隔离 lease 和指向仍存活窗口的指针；会话句柄保留，`destroy` 重试 `reader_close` 成功后才释放。 |

AppleClang arm64 的结构布局检查在相同头文件与编译器下对基线 `git show` 源码和本轮源码分别执行：`efrp_session` 从 **15640 B** 降至 **14768 B**，减少 **872 B**。当前联合区 9248 B，其中握手成员 6024 B，控制成员 9248 B；Flash 窗口仍为 4096 B。该数字是单个会话对象尺寸，不能直接推断 TLS、Yamux、Flash owner、工作流与应用同时存活时的堆峰值。

## Host 回归

使用现有完整 Mbed TLS 4.1.0 host 构建，AppleClang `-fsanitize=address,undefined -fno-omit-frame-pointer -g`，并开启 `MBEDTLS_PLATFORM_MEMORY`、`MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS`、官方 FRP v0.71.0 协议 fixture。重建 `session_peer` 与 `session_idf_flash_peer` 后：

- `session_upstream` **1/1 通过**。覆盖正常注册和心跳、握手与加密尾数据、64 KiB 正确／错误 tag、取消，以及 Flash clear 失败后保留 session handle 和隔离 lease 再次 `destroy` 成功；对象释放前清零由分配 fixture 检查。
- `session_idf_flash_upstream` **1/1 通过**。正式 session、reader 和 IDF provider 经测试分区 shim 同路执行，覆盖满长正确／错误 tag、owner／lease 收敛与小记录不访问 scratch。
- `handshake`、`aead_flash`、`idf_flash_store` 的 ASan/UBSan 定向回归均通过，分别检查握手移交、reader `close` 失败重试和 provider lease 隔离。

以上仅证明 host 软件路径。没有修改或刷写实体设备、Base 锁、产品分区、凭据或根计划；没有重新测量固定 SDK 双目标镜像、QEMU 或 Base/MQTT/OTA 与原生业务并发峰值。P6-03 产品容量与实板验收仍以各自独立证据为准。
