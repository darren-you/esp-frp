# ESP32 会话对象的 IRAM 8BIT 放置检查点

2026-09-28。当前 `efrp_session_t` 在 ESP32 为 14,576 字节。创建会话时，仅在 ESP-IDF 的 ESP32 target 同时启用 `CONFIG_ESP32_IRAM_AS_8BIT_ACCESSIBLE_MEMORY` 时，使用 `MALLOC_CAP_INTERNAL | MALLOC_CAP_IRAM_8BIT` 分配这个字节可寻址对象；其他配置仍使用普通 `calloc`。IDF 要求该配置先启用单核模式。能力已启用而申请失败时返回 `EFRP_NO_MEMORY`，不转用普通堆。会话清零、失败清理和销毁仍使用原有路径；公开 API、记录上限与协议未变。

固定 SDK `578cf89c`／lwIP `2758df4` 的 ESP32 签名 Base 仓外副本，仅将受管 FRP `src/session.c` 换成此候选，在额外的 OpenETH、固定测试时钟与官方 FRPS 探针下完成严格 CA/IP SAN TLS、Login、代理注册与 Pong，TLS 验签状态为 0。ECDSA v1 签名 app 为 `0x10fff4` 字节，SHA-256 `ebbbd9cd7be6cf146bffc999862b6b276f5d0254274e29baee4f04755ae1b184`，官方签名和分区容量检查通过。QEMU 普通 8BIT 堆历史最低 **50,248 字节**，比 48 KiB 门高 **1,096 字节**；会话存活时可用 IRAM 8BIT 从 83,160 降到 68,308 字节。仓外输入、日志和 Flash 留在 `mac-work-1:/private/tmp/esp-base-p603-frp-iram-policy-20260928/`。对照的当前正式 FRP 普通分配路径在同类探针下最低为 35,008／35,396 字节，见 Base 的[内存归因](https://github.com/esp-space/esp-base/blob/e9627fe14ca37c24d6598973bf3a1a67eb62f704/docs/operations/p6-03-current-frp-session-placement-checkpoint.md)。这些时序样本不能相减为精确节省量。

同一源码的 AppleClang ASan/UBSan 默认 host 测试 **10/10**，完整 Mbed TLS 4.1.0／PSA、官方 FRPS 会话与 Flash reader 测试 **19/19**；后者走普通 host 分配路径。ESP32-C3 签名 Base 仓外副本完成固定 SDK 构建、RSA v2 官方验签及候选双槽容量检查：app `0x111000` 字节，SHA-256 `94aca38b45501b470d2d266c0d0fc44c386aa4198c2c0c7a3b06ad49fe06b203`，每槽剩余 61,440 字节；C3 不走 IRAM 分支。C3 输入在 `mac-work-1:/private/tmp/esp-base-c3-frp-iram-policy-20260928/`。

这是会话内存策略和独立网络探针的验证，不是 Base 正式 FRP owner 的联网运行。Base 的 Wi-Fi IP、SNTP 时间门、loopback HMAC listener、MQTT／OTA 并发及两块实体板尚未覆盖；单核调度和 IRAM 8BIT 非对齐访问代价也尚未量测。当前 Base 正式 ESP32 配置未开启该能力，故此检查点不宣称 P6-03 的 48 KiB 产品资源门已通过，且未刷写设备。
