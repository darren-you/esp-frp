# P6-03：ESP32 纯 IRAM 字宽接收 AEAD 实验

2026-09-27。在独立 `esp-frp` 分支上增加**默认关闭**的 `EFRP_LAB_ESP32_IRAM_AEAD_RX`。固定 ESP32 五仓 QEMU 中，Base READY 且 64 KiB ABI 2 guest 存活时，原 8BIT 分块 reader 无法接收完整合法 64 KiB 明文记录；同一候选镜像、同一 guest 与密文输入下，字宽 reader 成功完成 65,536 字节的 GCM 认证与逐字节交付核对。满长坏 tag 被拒绝且所有 16 块在释放前经 32 位读取确认为零。本实验没有打开产品默认开关，没有写物理设备。

## 实现与安全边界

固定 ESP-IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c` 的 `esp_heap_caps.h` 把 `MALLOC_CAP_32BIT` 定义为允许对齐 32 位数据访问；`memory_layout.c` 把纯 IRAM 优先列为 `EXEC | 32BIT`，共享 D/IRAM 也列入该能力池，所以两池读数不能相加。实验模式的会话分配器只接受 `esp_ptr_in_iram` 且非 `esp_ptr_in_diram_iram` 的完整块；共享 D/IRAM 命中时直接拒绝，不占用 8BIT 池继续读记录。

`src/word_storage.h` 对 I 总线块只用 `volatile uint32_t` 对齐访问，逻辑字节按 4 字节 word 打包／解包；末块按 4 字节取整，申请后先以 32 位写全零。`aead.c` 仍在每块首字节到达时才申请、仍允许最大 65,536 字节明文与 16 字节 tag；失败、取消和已消费片段都经 32 位清零。字宽 reader 的 `efrp_aead_plaintext` 拒绝暴露裸块指针，只有完整 tag 认证后 `efrp_aead_copy_plaintext` 才从块中取字节。

固定 TF-PSA-Crypto 的 `psa/crypto.h` 规定 `psa_aead_update` 消费 `const uint8_t *input` 并输出 `uint8_t *output`，输出可延迟至 `psa_aead_verify`；`crypto_sizes.h` 提供 `PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE`。本适配器沿用 512 字节独立输入和该宏限定的独立输出栈缓冲，在 PSA 调用前从 word 块读取，调用后按 `produced` 偏移写回 word 块；PSA 从不收到 I 总线指针。认证前块属于 reader 私有；坏 tag 时 PSA 返回签名错误，reader 清零并释放所有块。OpenSSL host 后端的字宽路径同样使用独立输入／输出缓冲，不向 EVP 传 I 总线指针。

实验会话另持有 1024 字节 byte-accessible 明文暂存。`control_input` 只在认证完成后复制一段明文给 wire parser，随即清零暂存，再按解析器实际消费量清理 reader；TLS、Yamux、控制密文与工作流仍各有原来的暂存所有权。关闭实验开关时仍由原 `calloc/free` 分块 reader 负责正式会话。若纯 IRAM 碎片或其它使用使任一块申请失败，reader 返回粘性 `EFRP_NO_MEMORY` 并清理已收密文，没有降低协议上限或改用共享 D/IRAM。

## 固定输入与同阶段 A/B

从[上一轮 Wi-Fi IRAM-off 精确五仓工程](https://github.com/esp-space/esp-container/blob/73acc255b1d071cb6883c1890aded50eb6ad6254/docs/operations/esp32-wifi-iram-qemu-ab.md)的仓外副本准备。Base `1f43b6ff867dfcc262fc6a348b6d50285395c6e0`、MQTT `9d6d95e779f4f5ff387a6d9b54015bf4e43565f2`、OTA `207273188b984161362824c3344614e812016836`、Container 嵌入组件 `8eb805f3f12cb3cd836e9833acb4aca878ae80e7`、SDK `578cf89c343e388db43ba1f4ddcd602fedcb763c`、实际 lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`、WAMR `26c235e53e29acd8b43abe7f3b524577bd4d1ae5` 不变；FRP 由 `1f0c8f37db3765a74b3b95871bb266d0c73d1248` 派生为本分支字宽实验。`sdkconfig` SHA-256 仍为 `b1f4e090370e5ac7b20a05cf84faf941f39c847df7b18eccc1e777e90586d6ff`，两项 Wi-Fi IRAM 开关均为 `n`。4 KiB 与 64 KiB AEAD wire 二进制摘要不变；准备脚本逐项核对。

同一第二轮 Base READY + guest 事件成功后的候选镜像，先运行原 reader，再运行字宽 reader。该候选的 8BIT 起点为 **61,236／43,008 B**，比上一轮未加入新探针的镜像少 168 B；表内 A/B 均从此同一运行态起算。

| 接收路径 | 65,536 B 合法记录 | 4,096 B 与坏 tag | 释放／能力池 |
| --- | --- | --- | --- |
| 原 8BIT 分块 | 第 14 块 `EFRP_NO_MEMORY=-20`；已消费 wire 53,264 B，未认证或交付；13 块全释放 | 两次 4 KiB 完整认证；4 KiB 坏 tag `-11`，零交付 | 每次回到 8BIT 61,236／43,008 B |
| 字宽纯 IRAM | wire **65,568 B** 全部消费；`records=1`，**65,536 B** 逐字节相等；16 块全在纯 IRAM `0x4008ddac` 至 `0x4009dde7`，均非 byte-accessible | 4 KiB 完整认证；4 KiB 与 64 KiB 坏 tag 均 `-11`、`records=0`、零交付 | 16 块释放前 word 清零错误 0；8BIT 一直 61,236／43,008 B；EXEC／32BIT free **132,316 → 66,716 → 132,316 B** |

16 次申请都为 4,096 字节、4 字节对齐；逐块记录的起点、纯 IRAM 判定、8BIT 与 EXEC／32BIT 读数见[脱敏 QEMU 日志](esp32-iram-aead-qemu-trace.txt)。满长坏 tag 也申请、清零并释放了 16 块，拒绝数、清零错误和区域错误均为 0。Base 的两轮 guest `open/init/event/stop/close` 均成功、事件返回 3，`probe_summary runs=2 failures=0`。QEMU 限时运行 45 秒后宿主 SIGTERM 停止，无 panic；Wi-Fi／FRP／MQTT 仍是 `unconfigured`。

## Host 回归与签名镜像

官方 Mbed TLS 4.1.0 内含 TF-PSA-Crypto 1.1.0 的 AppleClang ASan／UBSan 实验构建完整 `ctest` **19/19 通过，317.77 秒**，含官方 FRPS 的会话、双业务流、背压、取消、工作流故障和客户端生命周期。`aead` 的字宽模式覆盖 1、3、4、4095、4096、4097、65535、65536 字节、单字节拆包、认证前无明文、满长坏 tag、部分记录销毁与十六个分配失败点。随后将 `aead_upstream` 对端也切到字宽路径并重建，`aead`／官方 `aead_upstream` **2/2 通过**。OpenSSL ASan／UBSan 的 `aead`／官方 `aead_upstream` 另为 **2/2 通过**。host 的普通内存不能证明 I 总线访问；QEMU 是该访问与容量的独立证据。

最终 ECDSA v1 测试签名 app **1,114,100 B**（`0x10fff4`），SHA-256 `e54493c022c2e5b7e8ee3ef7906708d3dfe39e6dfe0d9f7975dabddfdb89700e`；固定 `espsecure v5.4.0 verify-signature --version 1` 报告 `Verifying 1114032 bytes of data... Signature is valid.`。最小 `0x120000` app 分区还余 `0x1000c` B。测试签名键只在仓外；本镜像含合成 guest 和密文 fixture，不能作为产品发布镜像。

[准备与重跑入口](../../tests/esp32-iram-aead/README.md)及[SHA-256 收据](p6-frp-esp32-iram-aead-sha256.txt)保留固定输入、实验源码、签名镜像、原始 QEMU 日志摘要和脱敏 trace。该 QEMU 程序直接调用 reader，没有建立真实 FRP session／TLS、Wi-Fi 连接、MQTT Broker、OTA 或真实工作流；host 的官方双流不代替这些模块在设备上与 guest 同时存活的峰值。实板资源、网络与签名启动仍未验收，**P6-03 尚不能作为完整五仓产品验收通过**。
