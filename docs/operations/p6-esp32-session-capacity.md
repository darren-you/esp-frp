# ESP32 正式 FRP 会话容量停止点

2026-09-27。本轮在独立 `esp-frp` 分支只保存内存审计和仓外仿真收据；正式 FRP 源码、产品 `sdkconfig`、其他四仓、设备均未修改。结论限定于下列固定 ESP32 QEMU 输入：严格 TLS 已完成，但静态 TLS 缓冲输入下 `efrp_session_create` 的首笔 `calloc(12304)` 失败；仅打开固定 SDK 的 TLS 动态收发缓冲后，会话进入 `AUTHENTICATING`，首次 Login 写入又因内存不足而失败。两侧均未注册、未收到 Pong，更未在正式会话内完成 64 KiB AEAD 记录。

## 固定输入与对象账本

基线从[上一轮五仓收据](p6-frp-lazy-work-stream-capacity.md)的 `/private/tmp/esp32-lazy-work-sntp-ab-20260927/new/probe` 复制：Base `1f43b6f`、FRP `e5a6b0b5a8f6c908cddd948a3e652045022f5fb6`、MQTT `9d6d95e`、OTA `2072731`、Container `d501287`；IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c`、lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`、WAMR `26c235e53e29acd8b43abe7f3b524577bd4d1ae5`。两个本轮输入均使用相同 FRP `session.c` SHA-256 `06d1513c088bacf571e0a7a49da57e035dbd837f1dd94d3399a03ca96e91892a`、同一个仅用于仓外测量的 OpenETH 失败回调 SHA-256 `e27dacb8cf5a6bfdb8c9f08ddf9feb47f14bae15d9da512e3cd8c6da294baee0`、同一回环官方 FRPS 端口 29185、测试 TLS 证书与签名键、相同 60 秒 QEMU 截止。Wi-Fi 两个 IRAM 优化开关仍关闭。

基线探针只把 OpenETH 失败回调原有统计槽用于记录**失败当刻** `MALLOC_CAP_8BIT` 的 free/largest 和失败申请大小，并更换仓外回环端口。动态探针与其逐文件比较，除 `dependencies.lock.esp32` 的绝对组件路径外，仅 `sdkconfig` 不同：`CONFIG_MBEDTLS_DYNAMIC_BUFFER=y`；`CONFIG_MBEDTLS_DYNAMIC_FREE_CONFIG_DATA` 保持关闭，TLS 入站/出站上限仍为 16,384/4,096 B。前者让固定 SDK 按需持有并释放 TLS 记录缓冲，不改变 FRP 消息或证书校验合同；这只是一项仓外配置对照，不是产品默认值。固定 SDK 的选项语义以其 `components/mbedtls/Kconfig` 与 `port/dynamic/dynamic_buffer_architecture.md` 为准。

固定 SDK ELF 的 DWARF 表明 `sizeof(efrp_session_t)=12,304` B，其中 `storage` 联合区为 5,968 B：握手 `token` 1,024 B、`client_hello` 512 B、`output` 4,096 B；控制阶段的 `aead_tx` 1,056 B 与 `json_rx` 4,096 B 共享该联合区。会话另有四个 1,024 B 传输/控制/明文暂存区、1,024 B token、480 B 状态、264 B AEAD reader、88 B writer、52 B 帧 reader、104 B 工作槽集合及指针/标量/对齐。可用[DWARF 读取脚本](inspect_session_dwarf.py)对冻结 ELF 重算；对象大小不等于堆峰值。

## 同输入 A/B 结果

两侧均出现 Base `ESP_BASE_READY`、64 KiB ABI2 guest 存活、OpenETH DHCP、Base SNTP ready，随后调用真实 `efrp_start` 连接回环官方 FRPS。测试键 ECDSA v1 对 1,179,568 B 镜像数据验签有效；签名镜像均为 1,179,636 B，距 `0x120000` app slot 余 12 B。脱敏顺序日志为[静态缓冲侧](p6-esp32-session-heap-qemu.txt)、[动态缓冲侧](p6-esp32-session-dynamic-qemu.txt)；签名校验原样输出见[静态侧](p6-esp32-session-heap-signature.txt)和[动态侧](p6-esp32-session-dynamic-signature.txt)，完整摘要见[收据](p6-esp32-session-capacity-sha256.txt)。

| 观察点 | 静态 TLS 缓冲 | 动态 TLS 缓冲 |
| --- | ---: | ---: |
| `sdkconfig` SHA-256 | `ea99dc8f…5ae801b` | `97a0f8ca…51e182` |
| 进入 TLS 握手阶段时 8BIT free/largest | `7,892/6,912` B | `29,908/28,672` B |
| TLS 后最远阶段 | phase 2，首笔 session 失败 | phase 3 `AUTHENTICATING`，首次 Login 写入失败 |
| 失败当刻 8BIT free/largest | `10,204/9,216` B | `6,472/4,096` B |
| 失败申请大小 | `calloc(12304)` | TLS/PSA 底层 `4,437` B |
| 结果 | `error=-20`, `tls_error=0`, `verify=0` | `error=-20`, `tls_error=-141`, `verify=0` |
| 注册/Pong | `ready=0, pongs=0` | `ready=0, pongs=0` |
| FRP 销毁后 free/largest | `46,584/43,008` B | `46,564/43,008` B |
| OpenETH 清理后 free/largest | `60,516/43,008` B | `60,496/43,008` B |

基线失败当刻的总空闲也低于 12,304 B，因此不能归因于连续块碎片化，单纯拆小会话申请没有容量保证。动态侧 session 分配已越过先前停止点，严格 TLS 验证仍为零错误；但 `4,437` B 申请时最大连续块为 `4,096` B，Login 尚未送达 FRPS。两侧随后增加的 free 数是错误清理后读数，不能当作分配当刻预算。两侧测试夹具均将正式 FRP 容量失败计入 `probe_summary runs=2 failures=1`；这是预期观察结果，不能称为五仓业务通过。

## 源码候选与取舍

只读生命周期审查找到一笔真实可消除的 4,096 B 堆申请：`session.c` 在 `calloc(session)` 后为 `handshake_rx` 再申请 4 KiB，而 `efrp_handshake_t.output[4096]` 已在 session 联合区内。`efrp_handshake_feed` 在 output 发完前返回 `WOULD_BLOCK`，`efrp_handshake_consume_output` 将已确认发送的前缀清零；之后才接收 Hello/Login 回复。因此握手回复可以在同一 4 KiB 区域按阶段复用，保持回复上限和清零语义。此候选只减少 **session 创建成功后的** 4 KiB 峰值，不能解决静态侧首笔 12,304 B 分配失败。它也未与动态 TLS 配置一起完成 MCU 同输入 QEMU，对首次 Login、注册、Pong、会话内 64 KiB 的收益不能推断；本轮没有合入产品源码。

保持 65,536 B 最大合法 AEAD、tag 全认证后才交付明文、三条工作流、严格 TLS 与签名合同的条件下，当前固定 ESP32/64 KiB guest 同存组合尚无可验收的完整会话。此前同条件的独立 AEAD reader 已在第 14 个 4 KiB 块失败并零交付；即使越过 Login，不能把这项独立测试或 4 KiB 正常认证推为会话内满长成功。要达到原合同，仍需有经测量足够的实际内存预算及正式会话全路径验收；本轮不以降低记录上限、认证要求或工作流上限换取表面成功。

## 复现

在 `mac-work-1` 固定 SDK 环境保留上一轮冻结 probe、测试夹具和 QEMU runner 后，用本分支脚本依次复制，目标目录必须不存在。`prepare_esp32_session_heap_probe.py` 校验关键冻结 SHA；第二步逐目录复制，其结果相对于第一步只有 TLS 配置和绝对路径锁变化。`run_esp32_session_heap_probe.sh` 先验签，再运行回环 FRPS 与 QEMU，末尾关闭 FRPS；它不烧录设备。

```bash
python3 docs/operations/prepare_esp32_session_heap_probe.py \
  /private/tmp/esp32-lazy-work-sntp-ab-20260927/new/probe \
  /private/tmp/esp32-session-capacity-20260927/heap-probe
python3 docs/operations/prepare_esp32_dynamic_tls_probe.py \
  /private/tmp/esp32-session-capacity-20260927/heap-probe \
  /private/tmp/esp32-session-capacity-20260927/dynamic-probe

export IDF_PATH=/Users/darrenyou/.cache/darren-space/esp-idf-578cf89
source "$IDF_PATH/export.sh"
for side in heap dynamic; do
  idf.py -C "/private/tmp/esp32-session-capacity-20260927/$side-probe/firmware" \
    -DIDF_TARGET=esp32 -DESP_BASE_CONTAINER_BINDING_PROBE=ON \
    -DEFRP_LAB_ESP32_IRAM_AEAD_RX=ON build
  bash docs/operations/run_esp32_session_heap_probe.sh \
    "/private/tmp/esp32-session-capacity-20260927/$side-probe" \
    /private/tmp/esp32-frps-session-qemu-20260927/frp_chunked_qemu.py
done
```

运行前须确保回环 29185 未占用；两轮串行。`sdkconfig` 在 IDF 构建后规范化，收据记录的是构建后的 SHA。原始 guest 日志与签名产物留在 `mac-work-1` 的 `/private/tmp/esp32-session-capacity-20260927/`；仓内日志筛选关键阶段、脱敏身份和压缩重复 OpenETH 报错，首行记录原始 SHA-256。`mac-work-1` 当前 QEMU/FRPS 已退出，29185 无监听。
