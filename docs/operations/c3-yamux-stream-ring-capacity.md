# C3 官方 FRPS 会话的 Yamux 接收 ring 容量复测

2026-09-27 在独立 `esp-frp` 工作树从 `1f0c8f37db3765a74b3b95871bb266d0c73d1248` 派生本次改动。前一轮固定五仓 ESP32-C3 QEMU 软件切片在严格 TLS 已 OPEN 后，`efrp_session_create` 的整笔 `sizeof(efrp_yamux_t)=5552` 字节分配失败，返回 `EFRP_NO_MEMORY=-20`，因此没有进入 Login。本轮只改变 Yamux 接收 ring 的持有方式。最终 A/B 以相同 guest、OpenETH、官方 FRPS fixture、测试 CA/Token、仿真时钟和记录输入构建两个镜像；两个镜像仅有三个 FRP 组件源码文件不同。不修改四流上限、每流 1024 字节 ring、262144 字节初始信用、最大合法 64 KiB AEAD 记录或产品默认配置。

## 变更与所有权

旧结构将四个 ring 全部内嵌在 mux，控制流刚创建就要一次申请 5552 字节。新结构的 C3 编译尺寸为 `sizeof(efrp_yamux_t)=1488`、`sizeof(efrp_yamux_stream_t)=56`；`efrp_yamux_open` 只为真实打开的一条流申请 1024 字节 ring，成功排入 SYN 后才占用流槽与 ID。控制流阶段对象加单条 ring 合计 2512 字节，较旧对象少 3040 字节，未计分配器元数据。工作流的 ring 只在收到工作请求并打开对应流时申请；四流同时存活时，ring 总量仍为 4096 字节。

控制队列满时 `open` 先返回 `EFRP_WOULD_BLOCK`，不申请 ring；ring 申请失败返回 `EFRP_NO_MEMORY`，不消耗 ID 或控制队列。排队未成功时释放刚申请的 ring。RST 保留当前 ring 直到允许 `release`，以维持迟到 DATA 的排空与流槽语义；`release` 和最终 `destroy` 使用项目的不可优化清零函数释放 ring。会话失败、取消和最终销毁均通过 `clear` 调用 `efrp_yamux_destroy`；`destroy` 后才允许重用同一 mux 存储。公开客户端 API 未变；低层 Yamux API 增加显式 `destroy`。现有背压、FIN/RST、信用回补、非法帧和错误回收逻辑未削减。

## 主机验证

在 `mac-work-1` 使用官方 Mbed TLS 4.1.0 完整发布包（SHA-256 `377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10`）、其中的 TF-PSA-Crypto、官方 FRP v0.71.0 回环 fixture，以及 AppleClang ASan/UBSan。最终源码在默认 OpenSSL 构建的 CTest **8/8 通过**；完整 Mbed TLS 构建 **19/19 通过，312.99 秒**，包含 `yamux_upstream`、`session_upstream`、`work_upstream`、`work_faults_upstream` 和 `client_upstream`。ASan 没有报告 ring 泄漏或释放后访问，官方会话/工作流测试仍覆盖真实 FRPS 的注册、心跳、双流、背压、FIN/RST、取消与重启。主机结果不代表 MCU 容量通过。

主机构建参数：

```bash
cmake -S . -B /private/tmp/esp-frp-c3-yamux-full-build-20260927 \
  -DBUILD_TESTING=ON \
  -DEFRP_MBEDTLS_SOURCE_DIR=/private/tmp/esp-frp-c3-yamux-mbedtls-source-20260927/mbedtls-4.1.0 \
  -DGEN_FILES=OFF -DEFRP_TEST_UPSTREAM_CRYPTO=ON -DEFRP_TEST_UPSTREAM_YAMUX=ON \
  -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/cjson \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g -DMBEDTLS_PLATFORM_MEMORY -DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS'
cmake --build /private/tmp/esp-frp-c3-yamux-full-build-20260927 -j 8
ctest --test-dir /private/tmp/esp-frp-c3-yamux-full-build-20260927 --output-on-failure
```

## 同输入 C3 QEMU 结果

冻结输入为 ESP Base `058e965671fa0e4d417114897541710699571c52`、FRP 基线 `1f0c8f37db3765a74b3b95871bb266d0c73d1248`、MQTT `9d6d95e779f4f5ff387a6d9b54015bf4e43565f2`、OTA `207273188b984161362824c3344614e812016836`、Container `8eb805f3f12cb3cd836e9833acb4aca878ae80e7`。固定 ESP-IDF 为 `578cf89c343e388db43ba1f4ddcd602fedcb763c`；两个签名 guest 的 `sdkconfig` SHA-256 均为 `a66858cf817841457a8557a46ec18e5757e4889a5e31dffc0978adf8a277fb52`。从上一轮 Container worktree 提交 `01d441da49afde8380b38cefd23e12da9baf1301` 的 `docs/operations/c3-frps-qemu-session-capacity-probe.md` 所述仓外工程复制。旧版保持 FRP 原件；新版仅替换 FRP 组件的 `include/esp_frp_yamux.h`、`src/yamux.c`、`src/session.c`。

原始探针在 DHCP 后立即把系统时间设为 `2026-09-27 12:00 UTC`，同时 Base SNTP 仍可能完成第一次同步并改写系统时间；其 `trusted_time` 又要求时间不早于该固定秒。复测中，未协调时钟的同一新版镜像既出现过进入 `AUTHENTICATING` 后 OpenETH 失败，也出现过 TLS 阶段 `EFRP_TIME_UNTRUSTED=-18` 并成功清理。为隔离这一测试夹具竞态，最终 A/B **共同**在仓外探针等待 `esp_base_time_ready()` 最多 10 秒，记录 `base_sntp_ready=1` 后再设置原先同一固定测试秒；信任回调、证书有效期、Token 和产品时钟代码均不变。协调版探针在旧/新工程的 SHA-256 同为 `601f69047acdca637bbab49dd76f5a29168577705a9b5e8352281b8a334e2ddd`。这是一项测试时序修正，不能把未协调运行和最终 A/B 的绝对 heap 数值直接相减。

`free / largest / min` 为 `MALLOC_CAP_8BIT` 字节；`min` 是每次启动的低水位，不随释放回升。旧/新分别使用相同 fixture 的独立 QEMU 运行；两次均有 Base READY 且 ABI 2 标准 64 KiB guest 持续存活。早期 reader 是**同镜像内的独立手工探针**，不是 FRP session 内记录。

| 阶段 | 旧版 free / largest / min | 新版 free / largest / min | 观测 |
| --- | ---: | ---: | --- |
| Base READY，guest 已打开 | 84,844 / 45,056 / 55,364 | 84,844 / 45,056 / 55,364 | 同输入、无 client |
| 无 client 手工 64 KiB reader | 84,844 / 45,056 / 55,364 | 84,844 / 45,056 / 55,364 | 两边均 16 块申请/释放、完整 tag 认证、65,536 字节比较；持有时 19,244 / 8,704 |
| 空闲 client + 手工 64 KiB reader | 74,920 / 45,056 / 18,464 | 74,920 / 45,056 / 18,464 | 仍无 session；两边持有时 9,320 / 3,584，清理后 74,920 / 45,056；随后 `efrp_destroy` 回到 84,844 / 45,056 |
| OpenETH DHCP | 71,072 / 45,056 / 6,164 | 71,156 / 45,056 / 6,164 | 两边 `got_ip=1`，后续使用 `10.0.2.2` 宿主映射 |
| Base SNTP 首次就绪、重设固定测试时钟 | 70,960 / 45,056 / 6,164 | 70,944 / 45,056 / 6,164 | 两边 `base_sntp_ready=1`，即 `efrp_create` 前 |
| `efrp_create` 与 `efrp_start` | 60,512 / 45,056 / 6,164 | 60,496 / 45,056 / 6,164 | API 均返回 0；worker 起初 STOPPED |
| TLS_HANDSHAKING | 31,928 / 18,432 / 6,164 | 31,928 / 18,432 / 6,164 | `attempts=1` |
| **旧版 Yamux 分配失败** | 60,216 / 45,056 / **4,636** | — | `EFRP_NO_MEMORY=-20`、失败申请 5,552 字节、caps 6144；`tls_error=0`、`verify=0`、`ready=0` |
| **新版 AUTHENTICATING** | — | **9,336 / 3,584 / 4,596** | `efrp_session_create` 已成功，控制流 ring 已分配；`ready=0`、`pongs=0` |
| 旧版 `efrp_destroy` 和 OpenETH 清理后 | 84,432 / 45,056 / 4,636 | — | guest 收尾 `probe_summary runs=2 failures=1`，失败是预期容量停止点 |
| 新版 OpenETH 接收循环 | — | 无后续 app 采样 | 20 ms 后反复记录 `no mem for receive buffer`；未观察到 LoginResp、注册、Pong、`efrp_destroy` 或清理后 heap |

新版状态推进证明旧 5552 字节 Yamux 申请失败已经越过：`client.c` 只有在 TLS step 成功、`efrp_session_create` 成功后才发布 `AUTHENTICATING=3`；会话创建内必须先分配 1488 字节 mux、4096 字节登录区及控制流 1024 字节 ring。新版没有出现旧的 `EFRP_NO_MEMORY=-20` client 失败状态。它**不证明** ClientHello/Login 已到达服务端，更不证明注册或 Pong。

新版下一确定停止点位于固定 SDK `components/esp_eth/src/openeth/esp_eth_mac_openeth.c` 的 `emac_opencores_rx_task`：每次接收通知后取 `ETH_MAX_PACKET_SIZE=1522` 并执行 `malloc(length)`；申请失败打印 `no mem for receive buffer`，在该内层循环没有失败分支的 `break`。首次错误在 guest 5516 ms；8-bit 最大块 3584 是 5496 ms 的先前采样，既非同时刻、也不能代表该 `malloc` 的确切可用池。日志没有分配回调记录 OpenETH 所请求的能力掩码，因此 1522 字节是固定 SDK 源码的申请尺寸，不应把先前 `MALLOC_CAP_8BIT` 快照解释为分配应该成功。日志被驱动连续输出占据，宿主按有界 QEMU 期限终止；新版未出现最终 `probe_summary runs=2`。guest 内 client/网卡清理读数缺失，不能推断泄漏或回收成功。两轮测试 FRPS 均按各自唯一测试 PID 停止，29173 端口无遗留监听。

**本轮容量结论仅到这里。** Base READY + 标准 64 KiB guest + 严格 TLS + 真实 FRP client 已进入会话认证阶段，但尚未完成 Login、代理注册、Pong，更未在真实 FRP session 内收取和认证完整 64 KiB 记录。手工 reader 的成功不能替代会话内证据。原 Wi-Fi IRAM 两项维持关闭；没有缩减 guest、记录、TLS 或官方协议，没有物理设备写入。

## 复现与收据

先按 Container 报告的 `prepare_c3_frps_session_qemu.py` 从冻结输入生成原始 `probe`，并按该报告构建其官方 `fixture/frps-server`。把本工作树源码与 Container 的 QEMU runner 同步到 mac-work-1 仓外路径；[对照准备脚本](prepare_c3_yamux_clock_ab.py)复制两份输入、共同加入 Base SNTP 首次就绪等待，再只给新版替换三个 FRP 源文件。脚本校验两份工程除这三份文件外逐字节一致，且两个时间探针摘要一致；本轮脚本重放与手工构建输入逐文件相同。

```bash
rsync -az --exclude=.git /private/tmp/esp-frp-c3-yamux-20260927/ \
  mac-work-1:/private/tmp/esp-frp-c3-yamux-test-20260927/
scp /private/tmp/esp-container-c3-client-qemu-20260927/docs/operations/frp_chunked_qemu.py \
  mac-work-1:/private/tmp/esp-c3-frps-runner-20260927.py
```

以下命令在 mac-work-1 执行；输出根目录必须先不存在。两个 IDF 构建串行，避免 Espressif Component Manager 的同一 git cache `index.lock` 竞争；每个镜像分别验测试签名：

```bash
baseline=/private/tmp/esp-c3-frps-session-qemu-20260927/probe
frp_source=/private/tmp/esp-frp-c3-yamux-test-20260927
ab_root=/private/tmp/esp-c3-yamux-clock-ab-20260927
python3 "$frp_source/docs/operations/prepare_c3_yamux_clock_ab.py" \
  "$baseline" "$frp_source" "$ab_root"
source /Users/darrenyou/.cache/darren-space/esp-idf-578cf89/export.sh
for side in old new; do
  probe="$ab_root/$side/probe"
  idf.py -C "$probe/firmware" -D ESP_BASE_CONTAINER_BINDING_PROBE=ON build
  python -m espsecure verify-signature --version 2 \
    --keyfile "$probe/test-key.pem" "$probe/firmware/build/esp_base.bin"
done
```

每侧各自启动一次仅监听宿主回环 `127.0.0.1:29173` 的官方 FRPS fixture，再用 Container runner 运行 QEMU。该 runner 执行 `qemu-system-riscv32 -M esp32c3 ... -nic user,model=open_eth -no-reboot`；20 秒是宿主有界终止期限，guest 到达停止点更早。每侧运行后只终止该次 fixture PID：

```bash
for side in old new; do
  probe="$ab_root/$side/probe"
  log_root="$ab_root/$side"
  "$probe/fixture/frps-server" -port 29173 \
    -cert "$probe/fixture/frps_server.pem" \
    -key "$probe/fixture/frps_server_key.pem" > "$log_root/frps.log" 2>&1 &
  frps_test_pid=$!
  trap 'kill -TERM "$frps_test_pid" 2>/dev/null || true' EXIT
  for attempt in 1 2 3 4 5; do
    rg -q QEMU_FRPS_READY "$log_root/frps.log" && break
    sleep 1
  done
  rg -q QEMU_FRPS_READY "$log_root/frps.log" || exit 1
  python3 /private/tmp/esp-c3-frps-runner-20260927.py \
    "$probe/firmware" "$log_root/qemu.log" 20
  kill -TERM "$frps_test_pid"
  wait "$frps_test_pid" || true
  trap - EXIT
done
```

镜像使用公开测试签名键、UART0 QEMU 控制台与 ADC2 校准空桩，**不可刷物理设备**。测试 CA、Token 和私钥仅在仓外临时目录生成，不在本提交中。旧/新 app 均为 `0x131000` 字节，小于 `0x1e0000` 字节最小应用槽，RSA v2 signature block 0 校验有效。以下 SHA-256 只标识本轮本地证据；证书随机生成和构建时间使重新派生的 app 字节可不同。

| 制品 | SHA-256 |
| --- | --- |
| 旧/新相同 `sdkconfig` | `a66858cf817841457a8557a46ec18e5757e4889a5e31dffc0978adf8a277fb52` |
| 旧/新相同时间协调探针 | `601f69047acdca637bbab49dd76f5a29168577705a9b5e8352281b8a334e2ddd` |
| `esp_frp` Yamux 头文件、`yamux.c`、`session.c` | `f1c2fb9b6e2b77975bd4fcb6e5f2a9de16c9ffc25e92dd69506cf894b571f5e6`、`9da9f54d8659b2053b60afcd1cbb0dd0acbfcf8df872c812f551f4a9e0dac2f3`、`48810478d39819bbffe61cd7a533675aa75696fe7f32d998c11827e615319a68` |
| 旧版签名 app / ELF / QEMU 日志 | `5fd623959ef0681510292a9177bdb0c6eff2c478bfa585feebc70f40806bfe48` / `0dfc0186559ffc1929f023dc10624c20621bc62c1c0682d102a951974f06b3b3` / `9b149d4d01bf2bd15045444907272b1123f888f041ccbd3191014706aca3993d` |
| 新版签名 app / ELF / QEMU 日志 | `cc883c361963012eecc792a8d9523e691372a83575c6ccf3d3ec33c4f10d8929` / `b576f4a857d4dc87ada9c34508a78269f3ad5be254e1a95b993d2551dbb37a35` / `80bc5e0b99e8f16291f73fd11c610d96968771c57a788a3b5aefc0df331523bf` |
| 两轮测试 FRPS 日志各自 | `650e345436ea149e58a5ba7bcfd579c5ff2aaf5d8f4e5be26a5d79be37df8e75` |
| 最终完整主机 CTest 日志 | `0eaa76dc4b068f77a9b80f54a44ecc7dc219d46436f675c2321eb74acfbcfbf4` |

若需要继续推进，必须先在**相同完整输入**下处理 OpenETH RX 申请失败与调度阻塞，并拿到可清理的状态，再观察真实 Login、注册/Pong 和会话内满长认证。当前代码不能标记为完整 C3 五仓验收。
