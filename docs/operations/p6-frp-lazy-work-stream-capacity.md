# P6 工作槽惰性分配与五仓 QEMU 容量复测

2026-09-27。在独立 `esp-frp` 分支验证三个工作流对象按实际请求分配；所有 QEMU 运行均为仓外副本、回环官方 FRPS、测试证书和测试签名键。未修改产品默认值，未连接或写入实体设备。签名镜像和原始日志摘要见[收据](p6-frp-lazy-work-sha256.txt)，按时间顺序脱敏的设备日志分别为 [C3 旧侧](p6-frp-lazy-work-c3-old-qemu.txt)、[C3 新侧](p6-frp-lazy-work-c3-new-qemu.txt)、[ESP32 旧侧](p6-frp-lazy-work-esp32-old-qemu.txt)、[ESP32 新侧](p6-frp-lazy-work-esp32-new-qemu.txt)。

## 改动与生命周期

`work.streams[3]` 从三个常驻完整对象改为三个指针。收到 `ReqWorkConn` 且有空槽时，先 `calloc` 一个工作对象，再调用 `efrp_yamux_open`；分配失败返回 `EFRP_NO_MEMORY`，请求计数不提前扣减，会话按原错误路径结束。Yamux 返回 `WOULD_BLOCK` 或错误时，临时对象清零释放。成功打开后才扣减待办请求。正常完成、失败、取消及销毁时，等 Yamux 与本地连接释放后清零释放该对象；本地异步 `destroy` 返回 `WOULD_BLOCK` 时继续持有对象直到重试完成。仍只有三个工作槽、一条 SENDING/WAITING 流、原有窗口和期限。共享 4 KiB 工作握手区保持原有按首段输入申请的行为。

固定 SDK 的 ELF/DWARF 尺寸如下；这些是对象尺寸，不等于运行峰值。

| 目标与对象 | 旧侧 | 新侧 | 差值 |
| --- | ---: | ---: | ---: |
| C3 `efrp_work_set_t` | 6,672 B | 104 B | -6,568 B |
| C3 `efrp_session` | 17,848 B | 11,280 B | -6,568 B |
| ESP32 `efrp_session` | 18,872 B | 12,304 B | -6,568 B |
| 单条 `efrp_work_stream_t` | 2,192 B | 2,192 B | 0 |
| C3 `efrp_yamux_t` | 1,488 B | 1,488 B | 0 |
| ESP32 `efrp_yamux_t` | 5,552 B | 1,488 B | -4,064 B |

C3 对照固定 Base `058e965671fa0e4d417114897541710699571c52`、原 FRP `1f0c8f37db3765a74b3b95871bb266d0c73d1248` 加 Yamux ring `34f2a32ddbc974db04ca37f40cf3fefaf27d7d0b`、MQTT `9d6d95e`、OTA `2072731`、Container `8eb805f`，旧新仅 `src/work.c` 和 `src/work_internal.h` 不同。ESP32 对照固定 Base `1f43b6f`、旧 FRP `fbf5ec07cca6ac36cf06a780444e75928e9dddfd`、MQTT `9d6d95e`、OTA `2072731`、Container `d501287` 的仓外输入；新侧合并 C3 Yamux 与本工作槽改动，因此与旧侧有五个 FRP 源文件差异，**不能**把 ESP32 结果单独归因于工作槽。两组均使用 IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c`、lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`、WAMR `26c235e53e29acd8b43abe7f3b524577bd4d1ae5`（组件摘要 `a799be27248cadffdee6f6fae988dbdf3f5d423baab0b1008d74b8581b5ed507`）；其他组件取自各自冻结探针，准备脚本逐文件核对两侧输入。ESP32 两侧 `sdkconfig` SHA-256 同为 `ea99dc8f…5ae801b`，`ESP_WIFI_IRAM_OPT` 和 `ESP_WIFI_RX_IRAM_OPT` 均关闭；字宽 AEAD 实验开关只用于仓外构建。

## 软件与构建验证

用官方 Mbed TLS 4.1.0 完整发布包（`mbedtls-4.1.0.tar.bz2` SHA-256 `377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10`）及内含 PSA，在 `-fsanitize=address,undefined`、`MBEDTLS_PLATFORM_MEMORY` 和 `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` 下，打开官方 FRPS/Go 密码及 Yamux 互操作，最终合并源码的默认模式 [CTest 20/20 通过](p6-frp-lazy-work-host-ctest.txt)，耗时 169.50 秒；再加 `-DEFRP_LAB_ESP32_IRAM_AEAD_RX=ON` 的字宽模式 [CTest 20/20 通过](p6-frp-lazy-work-word-host-ctest.txt)，耗时 179.71 秒。`work_allocation` 注入首次分配失败，检查待办请求保留、三个槽取消后清零释放和重复取消；`work_upstream`/`work_faults_upstream` 验证实际 FRPS 双流、取消与背压。固定 IDF 五仓工程的 C3、ESP32 候选都完成构建与测试键镜像验签。host 字宽模式分配器仍为字节可访问，测试没有证明 MCU 真实工作流压力、I 总线访问或物理射频行为。

## C3 同输入 QEMU

两侧 `sdkconfig` SHA-256 均为 `a66858cf…277fb52`，镜像均为 1,249,280 B，`espsecure v5.4.0` RSA v2 第 0 签名块验签成功。每侧启动回环官方 FRPS 29173；等待 Base `READY`、64 KiB ABI2 guest 运行、OpenETH DHCP 和 Base SNTP ready，再走真实 `efrp_start` 与严格 TLS。完整先后事件见两份脱敏日志。

| 观察点 | 旧侧：Yamux ring，常驻工作槽 | 新侧：Yamux ring，惰性工作槽 |
| --- | --- | --- |
| 直接 AEAD reader | READY + guest 下 4 KiB、坏 tag、64 KiB 成功或按预期拒绝；`ready_max_with_client` 在 65,536 B 峰值后清零释放 | 相同 |
| 官方 FRPS 最远状态 | `AUTHENTICATING`，8BIT free/largest/min = `9,336/3,584/4,608` B；随后固定 OpenETH RX `malloc(1522)` 失败 | `REGISTERED`，`ready=1 pongs=1 error=0`；注册阶段 free/largest/min = `20,104/9,216/4,620` B |
| 清理 | 20 秒截止前未进入正常 FRP 销毁；RX 失败日志累计 84,839 行 | `efrp_destroy=0` 后 free/largest = `70,756/45,056` B；OpenETH 清理后 `84,400/45,056` B；guest 关闭，`probe_summary runs=2 failures=0` |

旧侧的 RX 失败不能等同于 `efrp_start` 失败；新侧的注册和 Pong 也没有触发工作流，更没有在会话内接收满长 AEAD。直接 reader 的满长成功发生在 FRP 正式会话建立前，不能用作会话内满长验收。

## ESP32 同输入 QEMU

旧新均是 Base READY + 64 KiB ABI2 guest 存活、OpenETH DHCP、Base SNTP `time_ready=1` 后启动真实 FRP；官方 FRPS 回环监听 29175，严格 TLS 的 `tls_error=0 verify=0`。两侧测试键 ECDSA v1 验签 `1,179,568` B 数据有效，签名镜像都是 `1,179,636` B，距 `0x120000` app slot 尚有 12 B。`sdkconfig` SHA-256 同为 `ea99dc8f…5ae801b`。

| 观察点 | 旧侧 | 新侧 |
| --- | ---: | ---: |
| `efrp_session` ELF 尺寸 | 18,872 B | 12,304 B |
| `TLS_HANDSHAKING` 采样 8BIT free/largest | 7,916/6,912 B | 7,888/6,912 B |
| TLS 成功后第一次 session 分配失败 | `calloc(18872)`，caps 6144 | `calloc(12304)`，caps 6144 |
| FRP 最终状态 | `client_phase=8 failure_phase=2 error=-20 ready=0 pongs=0` | 同左 |
| FRP 销毁后 free/largest/min | 46,552/43,008/1,468 B | 46,584/43,008/936 B |
| OpenETH 清理后 free/largest | 60,520/43,008 B | 60,516/43,008 B |

停止点在 `client.c` 的 `TLS_HANDSHAKING` 后调用 `efrp_session_create`，`session.c` 首笔完整会话 `calloc` 返回空；未发 Login，因此未注册、未 Pong，也不能进行会话内 64 KiB 记录验证。两侧在 Base READY + guest 阶段的**独立** 64 KiB reader 均于第 14 个 4 KiB 块申请失败（已分配的 13 块均释放、零明文交付）；4 KiB 合法记录通过，坏 tag 按预期零交付。Base READY 前的独立满长 reader 通过，但其内存条件不同。该探针把预期容量失败计入 `probe_summary runs=2 failures=1`，不能误写为整轮成功。先前使用未协调 Base SNTP 的试轮停在 `clock_invalid`，不用于本表；本表仅使用已验证的 SNTP 协调输入。

## 复现边界

仓外输入和产物位于 `mac-work-1` 的 `/private/tmp/esp-c3-lazy-work-ab-20260927`、`/private/tmp/esp32-lazy-work-sntp-ab-20260927`。对应准备脚本 [C3](prepare_c3_lazy_work_ab.py)、[ESP32](prepare_esp32_lazy_work_ab.py) 在复制前检查冻结 SHA，并检查新旧文件差异；运行脚本 [C3](run_c3_lazy_work_ab.sh)、[ESP32](run_esp32_lazy_work_ab.sh) 固定目标、签名核验、官方 FRPS 与 QEMU 截止时长。C3 使用 `/private/tmp/esp-c3-yamux-clock-ab-20260927/new/probe` 为基线；ESP32 使用 `/private/tmp/esp32-frps-session-qemu-20260927/probe-sntp` 及其 `frps_session_qemu_probe.c`。两个 runner 都可传同 SHA-256 `6980ae49…2083b71431be` 的 `/private/tmp/esp-c3-yamux-frps-qemu-20260927/frp_chunked_qemu.py` 或 `/private/tmp/esp32-frps-session-qemu-20260927/frp_chunked_qemu.py`。构建环境要求对应冻结 SDK、IDF Python 环境、`espsecure` 与已有测试键/证书夹具；脚本不会烧录实体设备。

在 `mac-work-1` 取得本分支完整 `esp-frp` 源码后，从仓根运行；以下 `/absolute/path/to/esp-frp` 替换为该 checkout 路径。输出目录需事先不存在：

```bash
python3 docs/operations/prepare_c3_lazy_work_ab.py \
  /private/tmp/esp-c3-yamux-clock-ab-20260927/new/probe \
  /absolute/path/to/esp-frp /private/tmp/esp-c3-lazy-work-ab-20260927
bash docs/operations/run_c3_lazy_work_ab.sh \
  /private/tmp/esp-c3-lazy-work-ab-20260927 \
  /private/tmp/esp-c3-yamux-frps-qemu-20260927/frp_chunked_qemu.py

python3 docs/operations/prepare_esp32_lazy_work_ab.py \
  /private/tmp/esp32-frps-session-qemu-20260927/probe-sntp \
  /absolute/path/to/esp-frp \
  /private/tmp/esp32-frps-session-qemu-20260927/probe-sntp/firmware/apps/esp_base/main/frps_session_qemu_probe.c \
  /private/tmp/esp32-lazy-work-sntp-ab-20260927
bash docs/operations/run_esp32_lazy_work_ab.sh \
  /private/tmp/esp32-lazy-work-sntp-ab-20260927 \
  /private/tmp/esp32-frps-session-qemu-20260927/frp_chunked_qemu.py
```

当前可确认：C3 合并候选越过先前 RX 停止点并完成正式注册与 Pong；ESP32 虽削减 6,568 B 常驻会话尺寸，仍缺一笔 12,304 B 可用连续内存，正式会话及会话内满长记录未验收。两目标的工作流 MCU 容量、实体板和五仓完整业务验收仍需分别验证。
