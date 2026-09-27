# ESP32 FRP 工作流对象的 IRAM 8BIT 放置检查点

2026-09-28。沿用[会话 IRAM 策略](p6-esp32-session-iram-placement.md)，ESP32 单核且启用 `CONFIG_ESP32_IRAM_AS_8BIT_ACCESSIBLE_MEMORY` 时，FRP 把 client（3,120 B）、TLS 句柄（2,456 B）、会话（14,576 B）、工作流对象（每条 2,192 B）和工作流握手 JSON 缓冲（4,096 B）从普通内部堆放入 `MALLOC_CAP_INTERNAL | MALLOC_CAP_IRAM_8BIT`。C3 和 host 保持普通 `calloc`。能力已启用而分配失败时返回原有内存错误，不退回普通堆；释放、敏感数据清零和协议限额不变。对象尺寸来自固定 SDK 的 ESP32 ELF 类型信息。

针对 Base 签名产品的仓外 QEMU 探针，在已配置 OpenETH、测试时钟和官方 FRPS 严格 CA／IP SAN TLS 的条件下，完成 Login、注册、Pong 和 **一条真实工作流**。本地回环端点对 300,001 B 逐字节回显，FRPS 入站与出站各 300,001 B 均匹配；设备报告 `completed=1 failed=0`，本地收发各 300,001 B，TLS 验签标志为 0，未记录分配失败。普通内部 8BIT 堆历史最低 **53,424 B**，高于 48 KiB（49,152 B）门 **4,272 B**；工作流进行时的 IRAM 8BIT 可用量为 57,924 B。旧版本仅把会话放入 IRAM，同类工作流探针最低 **42,424 B**。两个运行时样本的差值用于判定这一候选跨过目标门，不作为逐对象精确节省量。

候选从精确锁定 FRP `1dcb6d63d471ccc4cefb369637f853af7d98d77d` 的 Base 仓外副本覆盖本次五份源码，并非已更新 Component Manager 锁的产品镜像。固定 ESP-IDF `578cf89c`／lwIP `2758df4` 构建，ECDSA v1 签名 app `0x10fff4` B，SHA-256 `24ec316be97a44ac313530600a62619df972819e09c9e412da67d7e3b35405f6`；官方签名、分区解码和双槽尺寸检查通过，每槽余 65,548 B。QEMU 输入、Flash、FRPS 与串口日志在 `mac-work-1:/private/tmp/esp-base-p603-frp-work-iram-20260928/`，结果文件 `network-run-result.json` 报告回显校验成功。

此探针直接创建 FRP client，绕过 Base 正式 Wi-Fi IP、SNTP 和 HMAC listener owner；它没有 MQTT、OTA 下载或 Container guest 同时在线，也未测两条活跃流及一条预备流的峰值。48 KiB 产品门、P6-03 和实体板验收均未因此完成。本次没有刷写设备。

同一源码的默认 AppleClang ASan/UBSan host 回归 **10/10**，完整 Mbed TLS 4.1.0／PSA、官方 FRPS 会话与工作流、Flash reader 的 ASan/UBSan 回归 **23/23**。host 使用普通分配路径；这些结果验证协议与清理回归，不代替设备侧容量测量。

C3 仓外产品副本也覆盖相同源码并完成固定 SDK 构建；RSA v2 签名 app `0x111000` B，SHA-256 `097362ac01e3d1b65a20322545f2e16ef213681f06be11ae0546607b7824715b`，官方验签、分区解码和双槽容量检查通过，每槽余 61,440 B。输入留在 `mac-work-1:/private/tmp/esp-base-frp-work-iram-pin-c3-20260928/`。此项只证明 C3 的编译与容量，未重跑 C3 网络或实板工作流。
