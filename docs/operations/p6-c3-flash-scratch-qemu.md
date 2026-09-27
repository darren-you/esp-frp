# P6-03 / P4-04：C3 QEMU 真实 Flash scratch 与满长 AEAD 探针

2026-09-27。公开 `esp-frp` 基线 `98bab0c0fbac684a6f89772c50c8bcf37aafe4fc`，在[独立 C3 探针](../../tests/c3-flash-scratch/README.md)中执行正式 IDF 分区 provider 和正式 Flash AEAD reader。C3 QEMU 的真实 MTD 文件经历完整 64 KiB 擦除、写入、回读、跨两次独立启动保留，以及 boot recovery 擦除；65,568 字节合成 wire 经完整 GCM 认证后交付 65,536 字节明文，随后 16 个 4 KiB 窗口逐一复验和核对。满长错误 tag 被拒绝，明文零交付。**此处未执行 FRPS session、TLS 或产品固件，也未刷写实体设备。**

## 固定输入与边界

| 对象 | 本轮事实 |
| --- | --- |
| 源码 | `esp-frp` `98bab0c0fbac684a6f89772c50c8bcf37aafe4fc` 派生的独立探针；FRP 生产源码未改 |
| SDK | `esp-idf` `578cf89c343e388db43ba1f4ddcd602fedcb763c`；实际 lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`；`tools/sdk.py check` 通过 |
| QEMU | mac-work-1 Homebrew `qemu 11.0.0` 的 `qemu-system-riscv32 -M esp32c3`，可执行文件 SHA-256 `4f7c97e65cade8ed485fd5d0a6966f60db337b7772a6c21ed3e32ac961bbc5d9`；不同于旧 P4 生命周期收据的 Espressif QEMU 9.2.2 |
| IDF 配置 | target `esp32c3`、4 MiB MTD、UART console、自定义实验分区表；生成 `sdkconfig` SHA-256 `25737f6e2d8e54bce825cd8783b96bd9255ff7248fd538abc3b999407482f67c`；`dependencies.lock` SHA-256 `ee2e5f95d26b694a7472abe07e48c3daa1aafd84a6d4a32da1e75a62019b15de` |
| 实验分区 | `frp_scratch` data/undefined、`0x110000/0x10000`、擦除粒度 4096、可写、未加密；分区二进制 SHA-256 `5f900b9e9930afe0f5ad7742849f0835a1d7ccd02c392fe34ab2130c7ff249d6` |
| 应用镜像 | `esp_frp_c3_flash_scratch.bin` `0x48b20` 字节，SHA-256 `d2a6009aea18a2d39e94002e75c42426e27155249536b3404a9c219280027bf8` |
| 合成记录 | `make_fixture.py` 用公开公式生成 key、nonce、明文；完整 wire SHA-256 `c5a73e30ed6b7b9cafb84e9051e348865d723006f88d59b768b4e1014d709399`；无真实 Token、地址或设备身份 |

`src/session.c` 的当前唯一控制接收路径依次调用 `efrp_aead_flash_reader_init`、`efrp_aead_flash_feed`、`efrp_aead_flash_plaintext`、`efrp_aead_flash_consume_plaintext` 和 `efrp_aead_flash_reader_close`。本探针直接调用**同一个** `src/aead_flash.c` reader 与 `src/idf_flash_store.c` provider，ELF 中核对到 `efrp_aead_flash_feed`、`efrp_idf_flash_store_bind` 和 `efrp_crypto_gcm_decrypt_store` 符号。探针没有调用 `efrp_session_step`；此关系仅说明测试到的 reader 是正式 session 所用实现，不代表完整 session 已在 QEMU 运行。

实验 `frp_scratch@0x110000` 沿用独立样例专用布局，**不是 Base 候选 `frp_scratch@0x3e6000`**；本轮没有改 Base 正式分区、签名制品、Flash owner 或生产代码。`with_owner` 是探针单 owner 原子回调，没有模拟 Base 的 OTA/Container 并发。

## 真实执行与测量

第一次启动从全 `0xff` 的独占 scratch 开始。provider bind 逐项核对分区，`recover` 后读回 64 KiB 全 `0xff`。reader 分块接收合成记录，在最终 tag 到达前 `plaintext` 返回 `WOULD_BLOCK`；认证后，QEMU 分区 65,536 个密文字节与 fixture 逐字节相等。reader 对初次认证及 16 个窗口累计进行 **17 次**全记录 GCM/SHA-256 复验，计入 reader 的 Flash 读取为 **1,114,112 字节**（`17 × 65,536`）；每个窗口 4,096 字节明文都与固定公式逐字节相等。窗口消费后 lease 撤销，密文仍留在 MTD 中等待下次 begin 或 boot recover。接着发送仅翻转最后一位 tag 的另一条完整 65,568 字节记录，结果为 `EFRP_AUTHENTICATION_FAILED`、`records=0`、零明文、窗口全零，lease 撤销。

| QEMU 应用内测量 | 第一次启动 | 第二次启动 |
| --- | ---: | ---: |
| recover 经过时间 | 35,371 µs | 35,962 µs |
| 满长 feed 加首次认证 | 658,435 µs，其中 owner 内 Flash operation 644,105 µs | — |
| 16 个明文窗口复验与消费 | 283,537 µs，其中 owner 内 Flash operation 132,994 µs | — |
| 单个窗口复验最长 | 17,833 µs | — |
| 满长坏 tag 拒绝 | 248,984 µs，其中 owner 内 Flash operation 238,329 µs | — |
| owner 内 Flash operation 累计 / 最长单次 | 1,050,671 / 77,769 µs；调用 2,437 次 | 35,836 / 35,836 µs；调用 1 次 |
| `MALLOC_CAP_8BIT` 空闲基线 / 最低 / 最终 | 328,948 / **327,740** / 327,740 B | — / **328,948** / 328,948 B |
| `MALLOC_CAP_8BIT` 最大连续块最低 | **188,416 B** | **188,416 B** |

这些时间来自 QEMU 的 `esp_timer_get_time`，`flash_operation_us` 在探针 `with_owner` 内围住正式 provider 发起的擦写、分块写回读和读取；feed/窗口总时间还包括 PSA 运算和逐字节比对。`MALLOC_CAP_8BIT` 只在探针运行的若干采样点读取，不是全生命周期追踪；输入密文静态嵌入 app Flash，4 KiB 窗口静态分配。第一次最终空闲值比 recover 后基线少 1,208 字节，本轮不据此判断泄漏原因或产品容量。它们都不是物理 SPI Flash 延迟，也不包含 TLS、lwIP、Wi-Fi、FRPS session、Base/MQTT/OTA/Container 的内存峰值。

runner 在第一次 QEMU 退出后直接按主机文件字节检查 MTD 的 scratch 恰为 fixture 密文，并保存完整 `phase-1-flash.bin`。第二次启动复用该镜像，新的静态 provider 首先读到跨启动保留的 **65,536** 个密文字节，再调用正式 boot `recover`，最后完整读回 **65,536** 个 `0xff`。主机侧也核对最终镜像 scratch 全 `0xff`。第一次镜像 SHA-256 `80e2e3647451d7528b2b1b13cb90e6ab63bd9b96a52d1460df9619730b17d2d6`；最终镜像与初始镜像同为 `c6dfcf7e80be5ee9e7f2d31d938f3cdcc6a0ac6961491046f71a5c0af7f607d0`。第一次 scratch SHA-256 `f608a64bc134caaadcee9c6344cd365a21bc63be9be5ff3b1822506aaa6a893b`，最终全擦为 `71189f7fb6aed638640078fba3a35fda6c39c8962e74dcc75935aac948da9063`。

## 日志与未覆盖事项

完整原始 QEMU 日志、两份 4 MiB 镜像、merge 命令与摘要同时保存在 mac-work-1 `/private/tmp/esp-frp-c3-flash-scratch-run-20260927-b/` 和 mac-ci-1 `/private/tmp/esp-frp-c3-flash-scratch-evidence-final-20260927/`。`phase-1.log`、`phase-2.log` 的 SHA-256 分别是 `c1702554ec1b24d7e3d0e1b0b163b3372a669d52988847e5da201dae92df916b` 与 `5e21e838009e7bcf3384aa9a6adf2acd43968ba54d3a80d719d87db78685c12b`；[摘录](p6-c3-flash-scratch-qemu-trace.txt)可在仓内直接审阅。首次构建在仓外重命名源码目录时因测试 CMake 固定 `REQUIRES esp-frp` 找不到组件而失败；原始 `first-build-failed.log` 和当时的输入行保存在同一 mac-ci-1 证据目录。随后测试入口改用源码根 basename 注册，产品实现未变；最终构建及两次 QEMU 运行成功。失败日志没有被成功记录覆盖。

本实验未验证真实 FRPS/TLS/Yamux 会话、Wi-Fi 和 lwIP、Base 的正式 `0x3e6000` 布局、Base storage owner 与 OTA 竞争、ESP32-D0WD-V3、掉电中断点、磨损、实板性能及完整 P4-04/P6-03 产品矩阵。尤其不能用这里的实验 app 大小、空闲堆或仿真时延推导签名 Base 候选可用。下一步必须在真实产品布局、完整链接集合和设备上按各自门禁验收；本轮不更改这些合同。
