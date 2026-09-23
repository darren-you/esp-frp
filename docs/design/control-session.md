# 控制会话

`esp_frp_session.h` 将严格 TLS、Yamux、Hello/Login 和控制 AEAD 组合为单 owner、一次会话的 C 核心。它注册一条 TCP proxy、维护 Token 心跳，并通过[工作流](work-streams.md)向固定本地目标转发。单 worker、自动重连和实板组合尚未完成；`REGISTERED` 只表示代理注册成功。

## 输入与所有权

create 接收已经 OPEN、无待发数据的 TLS 句柄和配置。Token、代理名称、Login 输入与固定本地目标复制到会话；TLS 始终借用。create 失败不取消调用方 TLS；成功后的取消、终止或销毁会取消 TLS、终止本地连接并清零内部密码、数据缓存和 Yamux，禁止继续使用失败实例。`efrp_session_destroy(&session)` 在 socket 清理未完成时返回 WOULD_BLOCK 并保留句柄，只有 OK 才释放并置空；随后才可销毁 TLS 和外层连接。终止状态的 step/cancel 仍继续清理。

`proxy_name` 是完整 wire 名称，要求非空、有效 UTF-8、最多 128 字节；调用方显式提供任何 user 前缀。`remote_port=0` 请求 FRPS 分配端口；配置不支持压缩和代理级额外加密。服务端返回的 remote address 是展示事实，官方 TCP proxy 通常只返回 `:端口`，不能直接作为未校验的本地目标使用。

核心不创建任务、DNS 请求或 timer；工作流拥有至多两条本地 socket。owner 定期调用 step，提供单调毫秒及可信 Unix 秒；反向时间、溢出风险和非正 Unix 秒拒绝。每次 step 最多执行八轮有界搬运，owner 不可重入或并发调用，也不能同时直接读写借用的 TLS。

## 协议、背压与期限

首条 Yamux 流承载 magic、ClientHello/Login。LoginResp 完成后释放握手借用区，在同一块内存初始化 AEAD；未消费的控制尾数据保持原顺序，认证成功后才交给 wire parser。控制 JSON payload（含两字节消息编号）最多 4096 字节；共享预检限制 UTF-8、深度、字段规模与重复解码键，不接受未知消息、字段或错误顺序。

NewProxyResp 必须匹配配置的名称，成功时 remote address 非空且最多 256 字节；错误返回 `EFRP_PROXY_REJECTED`。注册后立即发送 Ping，此后每 15 秒一次，始终使用官方 Token 公式签名。只有已有未完成 Ping 才接受 Pong，错误返回 `EFRP_AUTHENTICATION_FAILED`。注册响应和 Pong 各有 10 秒绝对期限，包含本地排队时间；TLS、Yamux 和握手更早到期时保留其错误。

ReqWorkConn 只能在 REGISTERING/REGISTERED 中接收，严格要求空对象；最多保留三条待处理请求，额外请求计数拒绝，不因此拆掉既有业务流。按工作槽和预备流上限逐步消费请求，完整计数与错误通过 status.work 提供。

TLS 已复制一段 Yamux 输出并不意味着该段已发完。会话记录暂存长度，直到 TLS 队列排空且仍 OPEN 才消费对应 Yamux 输出，因此不会提前发放接收信用。transport 和控制暂存区保留部分消费后的后缀；背压时停止读取该层新字节，不丢弃旧数据。

控制流 FIN 前先消费已认证明文，再检查握手、AEAD 和 wire 截断；TLS close_notify 还要检查剩余 Yamux framing。完整结束返回 `EFRP_SESSION_CLOSED`，截断、RST、认证、期限等保留不同原因。任一终止永久结束本会话，清理后状态仍保留结果、run ID、remote address 和已收到的 Pong 数；cancel 不覆盖既有失败。

## 验证范围

完整 Mbed TLS host 模式运行 `session_upstream`：实际官方 FRPS v0.71.0 在随机回环地址启动、启用严格 TLS 和 HeartBeats/NewWorkConns scopes。覆盖百次注册/销毁、真实外部连接触发 ReqWorkConn、连续两次心跳、37/41 字节与交替 WOULD_BLOCK 的 transport、错误 Token、占用端口及登录/注册取消。子进程检查 socket 已释放，测试确认 FRPS 已撤销代理监听。

另外 28 个场景复用相同官方 TLS/Yamux/wire/Token/AEAD API，并在 TLS 后注入固定非法 Yamux header。覆盖握手后同包 AEAD、4096 字节控制 payload 跨暂存边界、单条 64 KiB AEAD 明文、超长控制帧/AEAD 记录、名称/类型/重复键/未知消息拒绝、重复或失败 Pong、超量工作请求、FIN、TLS close_notify、帧/密文截断、tag 篡改、两类响应超时，以及 Yamux 版本/类型/旗标/信用/窗口/流 ID、RST 与截断。这些协议 fixture 不冒充完整 FRPS；两类对端共同验证组合行为。单设备入口和证据边界见 [crypto-interop](../../tests/crypto-interop/README.md#单设备协议-fixture)。

ESP-IDF v6.1 / C3 的会话分为 24848 字节对象、20912 字节 Yamux 和 65552 字节 AEAD 接收区，合计 111312 字节（不含 allocator 元数据），保持原有完整记录容量。会话保留 1056 字节 AEAD 发送区、四条 Yamux ring、阶段复用的握手/控制区和三个工作槽。实板首次测得 Wi-Fi 在线时最大连续块只有 114688 字节，因此禁止再要求一个 127728 字节的连续分配。首次两块分配在真实 TLS 后仍因堆区分布失败，因此采用三块分配，再移除互斥阶段的重复空间。任一分配失败都回滚；正常销毁和握手配置拒绝均清零三块内存。另需 TLS 对象、SDK 内部内存、cJSON 临时分配和每条连接 56 字节的对象。编译尺寸不是运行峰值或 MCU 泄漏结论；真实 SDK 网络、worker 和双业务流已部分通过，资源与故障缺口见 [C3 问题记录](../issues/c3-loopback-memory-pressure.md)，Base/MQTT 组合仍待验证。

登录握手和认证后的控制区在会话内复用同一存储：只有 `take_result` 复制密钥/run_id、销毁握手并释放借用后，才建立控制 writer 与 JSON parser。清理按实际初始化阶段执行，不能将控制字节解释为握手对象。控制明文输出最多 1024 字节，AEAD 发送区为 1056 字节；对端接收仍保留完整 65552 字节认证工作区及 4 KiB JSON 边界，不把本地发送大小当成对端 record 上限。
