# 开发检查点

2026-09-22 执行约束：按维护者最新要求，后续需人工断电的测试全部暂缓，直到维护者明确通知具备条件；不重复请求拔插，未执行项不计通过。其余开发、自动化和无需人工断电的实板验证继续。

2026-09-23 P4 SDK 与资源检查点：维护者批准的最小 lwIP 零窗口 ACK 根因修正已纳管到公开 `esp-lwip`，保留上游历史/许可。IDF 固定 `fff9895c82d744c7237be8847347bdd1b07c6643`，最终 lwIP 锁为 `2758df4cd3666b3b2a5b53830148379326425c0d`（根因提交 3dc581c，后续只补测试许可证）。独立 SDK 已从公开源重新准备，CMake 严格守卫、SDK 八项 Git fixture 与真实 lwIP 两项回归通过，原系统 SDK 未修改。

工作握手缓冲共享与登录/控制存储复用，使 C3 会话对象从 41264 降至 24848 字节，保留 64 KiB AEAD 接收能力和 4 KiB JSON。完整 host 15 项及最终存储实现五项受影响 ASan/UBSan、两项 TSan 通过；新增部分握手/旧流 RST 场景能够检出故意错误清空的变体。该存储实现的实板完成百次重建、三次同实例与 station 周期、首次和追加五次 FRPS 重启，以及双流大载荷。随后将 worker/main 栈调到 8/4 KiB，再做四档双流、两种方式各五轮 300001 字节、三次重建/同实例重启/station 周期和 FRPS 重启恢复，全部通过。

最终最低 heap 27572 字节，worker/main 最低栈余量 5088/2204 字节，分配失败零；仍未达到 48 KiB 目标。较早正式 SDK 复测曾在追加 FRPS 重启第 4 次出现 work TIMEOUT，后两轮未复现，不宣称其唯一根因已经闭合。各轮已恢复完整原应用槽、双份全量回读、UUID/revision 5/Wi-Fi/原 Bridge 并停止隔离服务。证据和边界见 [C3 回环与内存问题](../issues/c3-loopback-memory-pressure.md)。下一步继续资源峰值、FRP DNS/异常协议实板矩阵与 Base/MQTT 组合；P4 未完成，人工断电继续暂缓。

以下为较早的独立样例检查点，保留当时的故障事实：

2026-09-23 P4 独立 C3 样例检查点：已实现仓外输入、RAM Wi-Fi、真实 SNTP、固定回环双连接、串口实验命令及 heap/栈/socket/esp_timer/分配失败采样。`previous_run_id` 允许调用方显式移交已验证身份，新实例仍完整重新鉴权；客户端现有 20 种模式和 16 个配置负例。仓外 ASan/UBSan 15 项完整 CTest 全通过（244.52 秒），客户端 TSan 两项通过（30.91 秒），仓外 C3 完整样例构建通过。

实板已通过 SNTP、严格 TLS、Token 登录、代理与首次 Pong，以及双连接各 1/1024 字节往返。原会话大于最大连续堆块，现拆为 41264/20912/65552 字节三块，协议容量不变，三处分配失败与清零释放有回归。双流各 65536 字节仍失败：默认队列时最低 heap 864 字节及 CRYPTO_ERROR；缩小样例网络队列后转发超时、tcpip 任务持续运行并触发 IDLE 看门狗。具体根因尚未证明，当前配置仍属实验，百次生命周期与完整 P4 未通过。详见 [C3 回环与内存问题](../issues/c3-loopback-memory-pressure.md)。

四轮均已恢复原应用、同 UUID、revision 5、Wi-Fi 和原 Mac Bridge，实验期间非应用分区未变。第四轮恢复原基座后正常更新了 PHY 校准，新的双份稳定 Flash 除 phy/cal_data 外均与旧基线相同；新基线在私有 p4-sample4-20260923/restored-c.bin 与 restored-d.bin，不能宣称所有回读等于旧 P2 字节。隔离 FRPS 已停止。接下来先定位 MCU 双流停滞，再补完整资源与网络故障矩阵；人工断电继续暂缓。

以下为较早的软件检查点：

2026-09-22 P4 单 worker 检查点：应用入口 `esp_frp.h` 已组合 create/start/stop/destroy、配置复制、四项有界队列、唯一 I/O owner、阶段事件和状态副本。stop 等待本地工作连接、FRPS socket、迟到 DNS 与回调全部收敛；超时保留句柄和停止请求。destroy 同步结束 worker 后清零配置。网络中断使用一个带抖动的退避截止时刻，证书、认证和协议错误进入 failed。详见 [客户端生命周期](../design/client-lifecycle.md)。

- 实际官方 FRPS 百次创建/注册/停止/销毁通过；同实例另做十次 stop/start，非空 client_id 下保持原 run_id。新 worker 上三轮双流各方向核对 300001 字节，随后取消两条活动本地连接。真实 FRPS 停服并在原端口重建后自动恢复；不是模拟 socket 错误代替服务重启。
- 19 种生命周期/业务模式覆盖 DNS 迟到、停止超时、并发调用有界拒绝、STOPPED 回调未结束、四阶段取消、可信时间丢失、错误 Token/证书身份和分配失败。退避阶梯用测试时钟推进，真实服务恢复用真实时间；14 个配置负例、三个 host 创建分配点拒绝与凭据清零通过。host TSan 的客户端两项测试通过，pthread 与测试 DNS 不替代实际 FreeRTOS/DNS 验证。
- 仓外完整 Mbed TLS 初轮 15 项中 14 项通过，工作流故障测试因独立进程共用 client_id 被拒绝。受控复现取得官方“already online”原因后，将各场景身份与其唯一代理绑定；控制会话、百轮双流和工作流故障三项复测全通过。加强非空身份与 run_id 检查后，客户端两项 ASan/UBSan 与两项 TSan 再次通过。默认 OpenSSL 六项也通过；最终源码的 15 项覆盖由初轮和受影响复测共同证明，不伪称初轮全绿。
- C3 编译链接通过：客户端对象 3088 字节，调度对象 528 字节，worker 栈预算 12288 字节，另有复制 CA、会话 127728 字节和 TLS/SDK 资源。尚未测 MCU heap/连续块/栈余量。仅编译探针 497104 字节，SHA-256 `a39a21288e30420dbaa8421403eb417d34bb6e8ff6e874fd4a6b34a739f2e2d6`；默认分区不是本板可刷制品，本轮未写入设备。
- 63 份精确源码、初次编译/测试失败与最终日志、身份冲突复现、host/TSan/IDF 制品共 156 个文件，归档到 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-client-20260922/`；摘要和 0700/0600 权限通过。工程检查仅覆盖结构。

下一步建立独立 sample，验证 C3 的真实 SDK DNS/TCP/TLS/FRPS 和资源峰值，再进入 Base/MQTT 组合；人工断电项按维护者最新要求暂缓。P4 仍未完成。

以下为同日较早的工作流检查点：

2026-09-22 P4 工作流检查点：已实现 magic/NewWorkConn/StartWorkConn、固定 IPv4/port 目标、两条活跃业务流加一条预备流，以及有界双向转发和独立半关闭。ReqWorkConn 超限只计数拒绝；本地拒绝、RST、错误工作消息和慢流优先结束该流，保留其他流与控制会话。详见 [工作流](../design/work-streams.md)。

- 仓外精确源码的完整 Mbed TLS 13 项、默认 OpenSSL 6 项 ASan/UBSan CTest 全通过。实际官方 FRPS 百轮双业务流，200 条本地 TCP，每流两方向各核对 300001 字节，结束后 fd 恢复基线；四项真实 FRPS 故障覆盖本地拒绝、第三业务流容量、本地 RST 和活动中取消。
- 12 个官方 API 场景验证 StartWorkConn 与业务粘连、两个方向分别 FIN 后再反向传输、预备流长期等待后再使用、错误名称/error/超长/截断/越界端口/重复键、两类期限及慢流超时后另一流继续完成。长等待和期限使用测试单调时钟推进，慢读背压为真实 I/O。官方 FRPS/golib Join 在任一 EOF 后全关闭；端到端半关闭不能由这些结果推定，组件能力与上游边界分开报告。
- 连接层新增直接 IPv4、close_write/finish，100 次正常关闭测试在对端读取前排队数据并关闭，再验证完整尾数据和 EOF；既有 100 次连接/取消回归保留。复现 macOS 两端关闭后修改 SO_LINGER 返回 EINVAL，修正 POSIX 设置时机；IDF 按固定 lwIP 的半关闭和 TF_CLOSEPEND 路径处理，内存压力时长仍待 MCU 验证。
- destroy 改为持有句柄直至所有本地 socket 清理完成，WOULD_BLOCK 期间继续推进，不把取消结果当作已经释放。C3 编译链接通过，会话对象 127728 字节、连接对象 56 字节，不含 TLS/lwIP 内部及临时分配。仅编译探针 492464 字节，SHA-256 `64ce02642d21022a911e8fd3f78e9a52512171c91d4e8e03076a1ffc9ed49ef8`；默认分区不是本板可刷制品，本轮无设备写入。
- 55 份精确源码、锁定依赖、失败/最终日志及 host/IDF 制品共 115 个文件归档至 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-work-20260922/`，摘要与 0700/0600 权限复核通过。结构门禁通过不等于 FRP 行为门禁。

下一步实现单 worker 的生命周期、停止收敛、退避重连与独立 sample，再验证真实 C3 DNS/TCP/TLS/FRPS、内存峰值及 Base/MQTT 组合。P4 尚未完成。

以下为同日较早的控制会话检查点：

2026-09-22 P4 控制会话检查点：已在严格 TLS 上组合 Yamux、Hello/Login、控制 AEAD、TCP proxy 注册与 Token 心跳。握手后同包数据及各层背压保持完整；Yamux 输出必须等 TLS 排空才消费，控制 FIN 分别保留完整结束与截断原因。合同见 [控制会话](../design/control-session.md)。

- 仓外精确源码的完整 Mbed TLS 11 项、默认 OpenSSL 6 项 ASan/UBSan CTest 全通过，包含既有密码/握手/百次 Yamux 回归及新控制会话。工程检查仍只覆盖结构，不能代替协议测试。
- 实际官方 FRPS v0.71.0 使用临时证书、公开 Token、严格 TLS、HeartBeats/NewWorkConns scopes 和回环 listener；107 条连接覆盖百次注册/销毁、真实请求触发 ReqWorkConn、连续两个心跳、37/41 字节与交替 WOULD_BLOCK、Token/端口拒绝及登录/注册取消。结束后确认客户端 fd 释放、服务端代理 listener 撤销。
- 另有 17 个官方 API fixture 覆盖握手后 AEAD 尾数据、4096 字节控制 payload 跨缓冲、名称/类型/重复键/未知消息、重复或失败 Pong、过量工作请求、两种 FIN、wire/AEAD 截断、tag 篡改及注册/心跳响应期限。该组可控异常对端与实际 FRPS 分开报告。
- ESP-IDF v6.1 / C3 编译链接通过，控制会话对象 108704 字节，不含 TLS/SDK 内部与 cJSON 临时分配。默认分区仅编译探针 487472 字节，SHA-256 `2ab655112f2cdf241e3db1d0d8d1bf4600165cbd4c7c455fe19e1315dda741d4`，不是当前板可刷制品；本轮未打开或写入设备。
- 精确源码 50 份、日志、锁定依赖与 host/IDF 制品共 107 个文件归档至 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-session-20260922/`，摘要及 0700/0600 权限已复核。保留 Go 下载 EOF、测试对 `:端口` 的错误假设及分片回调签名编译失败日志；修正后独立检查通过，没有持久化下载用临时环境覆盖。

`REGISTERED` 只表示注册成功。ReqWorkConn 当前仅有界计数，NewWorkConn/StartWorkConn、本地双向转发、单 worker、重连和 C3/完整 Base 组合资源仍待实现；P4 保持实施中。

以下为同日较早的 DNS/TCP 检查点：

2026-09-22 P4 DNS/TCP 检查点：新增一次 IPv4 连接尝试，SDK 异步 DNS 与非阻塞 socket 由单 owner 收敛。取消/期限后不再创建连接；SDK 无 DNS 撤销 API，destroy 必须等待迟到回调完成，不释放仍被 SDK 借用的请求。合同见 [连接生命周期](../design/connection-lifecycle.md)。

- 直接编译 `dns_lwip.c` 的 API fixture 回归覆盖提交失败、缓存/异步、取消先后、地址拒绝、输入复制和 1000 次完成/取消竞争；ASan/UBSan 与单独 TSan 通过。该 fixture 不发送真实 DNS 查询，不替代 C3 DNS 网络验收。
- `connect.c` 通过 100 次真实 TCP 二进制往返及 fd 释放、接收 FIN 后发送、实际发送背压、RST、拒绝连接、CONNECTING 取消/期限和 100 次迟到 DNS 清理。113 条既有 Go TLS 连接均改用该 TCP 层后通过。
- 真实拒绝连接暴露 macOS 在 connect 失败后设置 SO_LINGER 返回 EINVAL，旧清理持续等待；已把取消关闭策略固定到 connect 前，回归通过。取消使用零 linger，不承诺业务排空或优雅 FIN；未来 work stream 的半关闭必须独立实现。
- 仓外精确源码的 Mbed TLS 10 项、默认 OpenSSL 6 项 CTest 全通过，含既有官方 FRP 握手/AEAD 与百次 Yamux。源码、日志与制品共 101 个文件归档至 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-connect-20260922/`；包含原清理失败、首次 registry 不可达与预期配置拒绝日志，摘要和 0700/0600 权限已核对。
- C3 在未启用 SO_LINGER 时按预期编译失败，开启后构建通过。连接对象 48 字节、DNS 请求 272 字节，不含 SDK 内部资源。仅编译探针 478672 字节，SHA-256 `295afd72252ff7149b6c4f5ce984c6f1eaa0114c7a466da29ae76527df6e62a0`；仍为默认分区，不是本板可刷制品，本轮无设备写入。

下一步装配唯一 worker 的 TLS/Yamux/控制握手，完成代理及 work stream，再做实际 SDK DNS、取消停止、组合资源和完整 FRPS 实板验证。P4 继续实施。

以下为同日较早的 TLS 核心检查点：

2026-09-22 P4 严格 TLS 核心检查点：基于 SDK Mbed TLS 实现非阻塞 I/O、强制证书/身份/日期校验、自有发送队列、绝对期限与取消释放。引擎不创建 DNS、socket、任务或计时器；外层连接及完整 FRP 会话仍待装配。公开合同见 [TLS 传输](../design/tls-transport.md)。

- 仓外独立 ASan/UBSan 构建：官方 Mbed TLS 4.1.0 / PSA 后端 8 项 CTest 全通过，同时回归既有官方 FRP 握手/AEAD 与百次 Yamux；默认 OpenSSL 协议核心的 4 项 CTest 也通过。
- Go 标准 TLS 服务端共 113 条连接，包含 TLS 1.3 百次生命周期、TLS 1.2、强制 17/19 字节部分读写、四类证书拒绝和七种终止场景。每次成功连接接收 70001 字节，再发送并回显 200001 字节。正常 close_notify、裸 TCP EOF、取消与握手/写入/关闭期限分别验证。
- 配置边界、部分无效 CA bundle、未可信时间、单调时钟与回调违规通过。最终独立构建启用 PSA 独占输入模式，逐个注入 23 个 SDK create 分配失败；释放 TLS 并清理隔离测试进程的 PSA 后剩余分配为零。此前普通 host 配置为 24 个位置，两份日志各自保留，不扩大为实板或握手全过程泄漏结论。
- C3 在关闭证书日期校验时按预期拒绝编译，开启后成功编译链接；本探针启用 TLS 1.2，TLS 1.3 的运行结论来自 host。TLS 句柄为 5528 字节（含 4096 字节 TX 队列），不含 SDK 动态分配；默认 RX/TX record 缓冲分别为 16384/4096。仅编译探针 369216 字节，SHA-256 `cf4c6ab1cc87580b20a33bf781cb6ac3d70122e5849d83a11846d5e01bd55117`，默认分区不是当前实板可刷制品，本轮无设备写入。
- 78 项内容及 manifest 共 79 个文件归档至 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-tls-20260922/`，包含精确源码、独立日志、SDK 配置与制品、预期日期守卫失败及已修复的测试头文件编译错误。摘要与 0700/0600 权限复核通过；工程检查只覆盖结构。

下一步实现可取消 DNS/TCP 建连及单 worker 装配，再完成代理控制、heartbeat/work scopes、work stream/本地转发与 C3 组合资源、真实 FRPS 矩阵。严格 TLS 核心完成不代表 P4 完成。

以下为同日较早的 Hello/Login 检查点：

2026-09-22 P4 Hello/Login 检查点：已实现有界握手核心、官方 Token 计算、run ID 和方向密钥移交，明确保留 LoginResp 后同一读取中的控制 AEAD 尾数据。

- ClientHello 仅广告 AES-256-GCM / JSON，32 字节随机数；Login 保留产品身份、精确 int64 Unix 秒和 pool_count=0。ServerHello/LoginResp 按顺序、结构、算法/随机数、错误及 run ID 验证。握手 payload 上限 4096，10 秒绝对期限，固定 cJSON 依赖；公开合同见 [控制握手](../design/control-handshake.md)。
- 仓外独立 ASan/UBSan 构建：OpenSSL 7 项 CTest、PSA 6 项全部通过。两后端各由官方 FRP v0.71.0 API 解码并鉴权真实 C Login，通过 9 组 Login→AEAD 往返及 6 组拒绝；另外复测既有 AEAD 矩阵，OpenSSL 构建复测 Yamux 百次 TCP 会话。这里没有启动完整 FRPS/TLS listener。
- C 回归覆盖所有测试步长和 EOF 截断点、错序/重复消息、JSON/协商负例、期限与清零。逐个拒绝 cJSON 分配，输出构建及 ServerHello 解析中间对象计数最终为零。补上借用缓存移交：take_result 后 destroy 不再清零已归还下一层的缓存，回归检查接管字节保持不变。
- ESP-IDF v6.1 / C3 编译链接通过，握手对象 5968 字节，另需 4096 字节接收区及库内临时分配。默认分区编译探针为 282832 字节，SHA-256 `83870461dbfc8cf73805688c7b235628e9bc41f823dfc6cd8ead1e6eba334bbb`；不是本板可刷制品，本轮无设备写入。完整客户端峰值仍待实测。
- 精确源码、依赖锁、host/SDK 日志与制品共 59 个文件归档至 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-handshake-20260922/`，摘要及 0700/0600 权限复核通过。工程检查仅证明入口与元数据，不替代协议或硬件验收。

严格 TLS/时钟、控制代理注册、heartbeat/work auth scope 装配、work stream、本地 socket 与完整 worker、C3 资源和真实 FRPS 矩阵仍未完成；P4 继续实施。

以下为同日较早的 AEAD 检查点：

2026-09-22 P4 控制 AEAD 检查点：已实现 `aes-256-gcm` 的原始 Hello 摘要、HKDF-SHA256 方向密钥和有界增量记录层。完整 FRP 客户端继续实施中。

- 接收缓存 65552 字节，认证成功前不交付明文；支持部分输入/输出、64 KiB、多记录、空记录、篡改/重放/计数失败与清零。IDF PSA 适配通过不重叠的小块输入/输出处理同一份记录缓存；不依赖 SDK 未保证的原地解密。
- 仓外独立源码副本的 ASan/UBSan 验证通过：OpenSSL 3.6.4 后端 5 项 CTest（含先前 Yamux 的 100 次真实 TCP 会话），官方 TF-PSA-Crypto 1.1.0 host 后端 4 项 CTest。两后端分别直接调用 FRP v0.71.0 / golib v0.8.2 完成 12 组双向、10 组拒绝用例；逐字节比较载荷与 Hello 摘要。这里没有 FRPS 登录或真实 MCU 会话。
- 首次把 Espressif 的 TF 子树用于独立 host 构建，缺少 `jsonschema` 和 SDK port 头文件而失败；保留原日志。后续 host 使用经官方 SHA-256 校验的完整 TF-PSA-Crypto 发布包；SDK 芯片移植由单独 IDF 构建验证，不混称两者。
- ESP-IDF v6.1 / C3 编译链接通过。reader/writer 对象分别为 104/88 字节；本探针 RX/TX 为 65552/4128 字节。PSA 内部资源和 TLS 峰值尚未实测。编译探针 264736 字节，SHA-256 `16139633239fb824f545aa1c2289a24e3814dc66f7af6c457858f5831a2a2bd2`；默认分区仅供编译，不是本板可刷镜像，本轮无设备写入。
- 工程结构与元数据检查通过，检查器仍没有 FRP 专项行为门禁。全部精确测试源码、host/IDF 日志、SDK 配置、制品、原失败日志和摘要在 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-aead-20260922/`，目录 0700、文件 0600，归档摘要复核通过。

公开合同见 [AEAD 记录层](../design/aead-records.md) 与[测试入口](../../tests/README.md)。Hello/Login 语义验证、严格 TLS、控制/work stream、本地 socket 与 worker、C3 组合资源/分配失败和完整实板矩阵尚未完成；P4 保持实施中。

以下为同日较早的 Yamux 核心检查点：

2026-09-22 P4 Yamux 核心检查点：新增独立 C 实现的四流、小 ring、增量 DATA 与显式输出接口；完整 FRP 客户端仍未完成。

- 256 KiB 协议初始窗口保持不变，每流实际 ring 为 4096 字节；信用在完整 WindowUpdate 发送后回补。支持半关闭、DATA+FIN、ACK+FIN、RST、PING、GOAWAY、释放后迟到数据的有界排空与绝对期限；不实现服务端主动流业务，收到 SYN 明确 RST。
- ASan/UBSan 回归覆盖大帧拆分与粘连、部分输出、四流容量、队列满恢复、窗口溢出/超信用、迟到数据、超时、ID 耗尽和 1000 次流槽复用。
- 真实回环 TCP 对接 FRP v0.71.0 固定的 `fatedier/yamux` revision `d0154be01cd6bcb13bd89fe9c3614b2b9395bc72`，100 次连接重建；每轮两条流分别进行 300001 字节的双向精确比较、PING 与双向 FIN。上游配置使用 6 MiB 最大流窗口。此项没有 TLS、FRP 登录或 MCU。
- 在工作区外全新源码副本中，CMake 构建、两个 CTest 核心测试和上述上游互操作全部通过；测试只读取本仓源码及精确公开 Go 依赖，不读取相邻 checkout。Go 1.26.1、AppleClang 21.0.0、CMake 3.31.10。
- ESP-IDF v6.1 / ESP32-C3 编译通过，编译器 `esp-15.2.0_20251204`。会话对象在 C3 为 20912 字节，host 为 20968 字节。仅编译探针镜像为 148336 字节，SHA-256 `b37e0b2cb8f566e3b880cb2014c800fd6431a57ad9d71e360e8eee7d0875bcfd`；使用独立默认分区，不是当前实板可刷制品，本轮没有设备写入。
- `check_engineering_standards.sh --repo esp-frp` 通过组件入口与元数据检查；检查器尚无可用的 `--domain frp` 专项行为检查，不能用该结构通过代替协议测试。

源码摘要、独立构建与测试日志、SDK 配置、编译探针和 receipt 保存在 ESP Tool 私有忽略目录 `provisioning/receipts/private/p4-yamux-20260922/`。协议 API 与资源边界见 [Yamux 核心](../design/yamux-core.md)。TLS、64 KiB AEAD 工作区、Hello/Login、代理/work stream、本地 socket 与重连 worker 尚未接入；静态对象大小不等于完整 C3 客户端峰值，P4 不计完成。

以下为较早的 wire 帧基线：

2026-09-21 开发基线：wire v2 帧 reader 的 ASan/UBSan host 回归通过；包括逐字节、拆帧/粘帧、64 KiB、非法头、EOF 与回调拒绝。完整客户端及实板未完成，不可作为可用 FRPC 宣传。

开发基线已保存至 `master` 的 `965d3e16bb644b907dcc3b4439959dd28a16bf9a`。已从 GitHub 重新 clone 到工作区之外的全新目录进行独立验证，不复用原 checkout 的源码或构建产物。 CMake 构建和 ASan/UBSan CTest 通过，输入覆盖不依赖 Token 或私有基础设施。

正式发布与硬件验收仍未完成。构建与 host 测试不替代实板。
