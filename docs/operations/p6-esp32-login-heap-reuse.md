# ESP32 Login 握手接收区复用检查点

2026-09-27。本轮只改 `esp-frp` 的会话内存生命周期，并在固定 SDK 的 host 与 ESP32 QEMU 上验证。没有改 FRP wire、Token 算法、严格 TLS、工作流上限、65,536 字节合法 AEAD 明文上限，也没有写实体设备。P6-03 仍未验收：正式五仓配置在本轮 QEMU 启动阶段存在前置故障，且没有完成正式会话内满长记录及实体板矩阵。

## 分配来源与可复用区

先前独立收据 `codex/p6-esp32-session-capacity-20260927@8d2f90bb9c142839103cf849a1ef25c9fc755538`的动态 TLS 侧在首次 Login 写出时记录到 4,437 字节分配失败，失败当刻 8BIT free/largest 为 6,472/4,096 字节。固定 SDK 的 `components/mbedtls/port/dynamic/esp_mbedtls_dynamic_impl.c` 在 TLS TX buffer 路径按 `SSL_BUF_HEAD_OFFSET_SIZE + MBEDTLS_SSL_OUT_BUFFER_LEN` 申请；本配置中 4,096 字节内容、TLS header/IV/MAC/padding 和缓冲头合计对应 4,437 字节。这笔 TLS 缓冲本身不能从 FRP 协议层移除。

同一时段，旧 `session.c` 在已分配的会话对象之外，另持有 `handshake_rx` 的 4,096 字节。会话内 `efrp_handshake_t.output[4096]` 已属于握手/控制联合区：输出期间响应输入由 `EFRP_HANDSHAKE_SEND` 拒绝；Yamux 先复制输出字节，`consume_output` 再逐段清零；全部消费后才能进入 Hello/Login 接收。`efrp_wire_init` 只登记接收指针，不提前写入该区域。因此会话现在将完整 `output` 借给握手 reader，删除独立的 4 KiB 堆申请。成功移交时先清零再重用联合区；拒绝、超时、取消和销毁仍清零敏感字节。其他部分重叠不受支持。

## 固定 SDK 验证

- `mac-work-1` 的 SDK 为 `578cf89c343e388db43ba1f4ddcd602fedcb763c`，使用仓库锁定的 lwIP；没有改 SDK。Mbed TLS 4.1.0 / TF-PSA-Crypto 1.1.0 host ASan/UBSan 构建后，完整 CTest **20/20 通过**，包含 C3/ESP32 握手、官方 FRP Login/会话、双工作流、失败注入和清理。日志 SHA-256：`d49a66d03394fba4d9ead04babf2136a9a0ae20c7f0abe8e1730d489f23318be`。
- 相同固定 SDK 的公开空输入 C3 sample 完成编译链接；构建日志 SHA-256 `0195d17f1c9f3c2ebb4517eb817d7ada243105347b7b165f03ee794ab0f11b8a`。这是 target 软件构建，不是 C3 设备验收。
- 握手单元测试新增同一 `output` 区内接收的分段输出、响应拒绝、LoginResp 后尾数据、错误和清零检查。Session 分配失败测试现在只注入会话与 Yamux 两笔创建申请；完整官方 FRPS 会话和 64 KiB AEAD host 用例仍在上述 20 项中通过。
- ESP32 五仓 QEMU 探针由前轮动态 TLS 输入复制，旧、新两边的 `sdkconfig` 均为 SHA-256 `e84296e5593124441a1a0deb24d69388832e10a8171d30a0daf66ebeaba8002b`。除仓外锁路径外，固件源码只在 `esp_frp/src/session.c` 与注释头文件 `esp_frp/include/esp_frp_handshake.h` 不同；旧、新 `session.c` SHA-256 分别为 `06d1513c088bacf571e0a7a49da57e035dbd837f1dd94d3399a03ca96e91892a` 和 `f0014738764fc999f70fba30e5432358a9a7c6c3f4973ff1c133d4eb6603e55b`。
- 本轮原产品 `CONFIG_ESP_TASK_WDT_INIT=y` 的旧、新镜像重跑都曾在 `app_main` 前的 `esp_task_wdt_init`/`task_wdt_isr` 空指针处崩溃。为了让 FRP 阶段可观察，**仅仓外 QEMU 对照**把两侧都设为 `# CONFIG_ESP_TASK_WDT_INIT is not set`，并都传 `-icount shift=auto`；动态 TLS、64 KiB guest、OpenETH、真实 SNTP、严格证书校验和官方回环 FRPS 保持。此变体不是产品配置，更不能推断实体板有同一看门狗故障。旧版前两次 SNTP 未通过而未进入 FRP；下面取两边都收到真实 SNTP 同步的完整一轮。

| QEMU 观测点，8BIT 字节 | 旧版 | 新版 |
| --- | ---: | ---: |
| `AUTHENTICATING` 阶段 free/largest | 12,860 / 11,776 | 16,972 / 15,872 |
| 差额 | — | +4,112 / +4,096 |
| 官方 FRPS 注册、首次 Pong | `ready=1, pongs=1` | `ready=1, pongs=1` |
| 会话销毁后 free/largest | 46,716 / 43,008 | 46,720 / 43,008 |

两侧测试 ECDSA v1 签名均由 `espsecure verify-signature` 验证有效；镜像都是 1,179,636 字节，距 0x120000 应用槽仅余 12 字节。旧、新镜像 SHA-256 分别为 `c39cc568e3952ac6bb0c3a9725ddb4b45e30056c765686978ca0c22bf886cf20` 和 `63131994cafb5489f1c0328f8de5e09717174e0bac64e692d153e1aaeb4d7ffc`。脱敏前 QEMU 日志留在 `mac-work-1:/private/tmp/esp32-login-heap-probe-20260927/`，旧轮 `wdt-off-old-attempt-1.log` SHA-256 `9c19f37194bc5906e019c647c96c7cb0a42e0f2f3295622574d371f7dacbf19e`，新轮 `wdt-off-new-qemu.log` SHA-256 `4beae61bbcf290f349442c987a63545ee1d79563c9f9bdf9bf3e48fb9751242b`。

## 结论边界

前轮“旧版 Login 的 4,437 字节申请失败”只适用于当轮正式 `sdkconfig` 下记录到的 4,096 字节最大连续块；旧版在本轮关停看门狗自动初始化的仿真配置中**也完成了注册与 Pong**，不能再把该失败说成旧源码必然不能登录。本次修改的实际收益是握手期间 8BIT 最大连续块增加 4,096 字节，且 host/官方 FRPS 实测无 wire 或清理退化。它没有证明原正式配置的启动问题已解决，也没有证明正式会话可接收完整 64 KiB AEAD 记录；后者仍受真实同存预算约束。
