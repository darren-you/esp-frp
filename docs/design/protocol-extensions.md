# FRP 协议扩展软件合同

本页描述 0.3.0 开发候选。维护者于 2026-10-02 允许扩展软件提前并行；两目标实板、Base/MQTT 组合和最终验收仍以[Base 原生业务与固件 OTA 首版](https://github.com/esp-space/esp-base/blob/master/docs/operations/ota-allocation-diagnostic-checkpoint.md)闭环为前置。完整 C QUIC TCP/UDP/STCP visitor、真实 FRPS 重启与取消，以及 XTCP 公共客户端双角色全链路软件互测均通过；这些结果不计作已验收的设备能力。冻结输入、测试及双目标构建见[软件检查点](../verification/xtcp-candidate-software-20261003.md)。

## 角色与注册

每个 provider 实例只注册一条 proxy，`proxy_type` 明确选择 TCP、UDP、STCP、HTTP、HTTPS 或 XTCP。`proxy_options` 只在 create 期间借用，client 和 session 各自复制实际需要的字符串；session 将注册完整编入输出区后立即清零释放其选项副本，client 保留副本供重连。未知类型、跨类型字段和超过联合注册容量的输入在联网前拒绝，不忽略错误选项。

| 类型 | 允许的选项 | 端口与本地业务 |
| --- | --- | --- |
| TCP | 无 | `remote_port=0` 请求分配端口；固定 IPv4/TCP 目标 |
| UDP | 显式 `udp_packet_size=1..65507` | `remote_port=0` 请求分配端口；固定 IPv4/UDP 目标 |
| STCP provider | 非空 `secret_key`，最多 128 UTF-8 字节 | `remote_port=0`；固定 IPv4/TCP 目标；FRPS 默认只允许已鉴权 provider 的 user |
| HTTP | `custom_domains`／`subdomain` 至少一项 | `remote_port=0`；HTTP Host 路由后转固定 TCP 服务 |
| HTTPS | 同 HTTP | `remote_port=0`；HTTPS SNI 路由，TLS 在固定本地服务终止 |
| XTCP provider | 非空 `secret_key` 和显式 `xtcp_options` | `remote_port=0`；双方证明后才连接固定 IPv4/TCP 目标；仅维护的候选对端 |

域名最多四项，每项最多 253 ASCII 字节，使用合法 DNS label／A-label，可显式带 `*.`。重复域名按 ASCII 大小写折叠拒绝；subdomain 是最多 63 字节的单个 DNS label。NewProxy 输出含 wire header 和 cJSON 打印余量共最多 1024 字节；单项合法不保证组合仍在此范围内。压缩、代理级额外加密及自定义 `allow_users` 没有消费入口。

注册地址按认证后响应的实际长度持有，不截成 256 字节。状态只报告 `remote_address_length`（不含 NUL）；`efrp_get_remote_address`／`efrp_session_remote_address` 接收含 NUL 容量的输出缓冲区，容量不足返回 `EFRP_CAPACITY_EXCEEDED` 及所需长度，并清空首字节。`NULL, 0` 可查询长度；它仍返回容量不足。STCP 与 XTCP provider 的合法地址为空，其他类型要求非空。清理会清零释放地址；响应地址只是展示事实，不能改变固定本地目标。

STCP visitor 使用独立 `efrp_stcp_visitor_config_t` 和 `efrp_stcp_visitor_create`，不注册 provider proxy。该角色的官方 FRPS/frpc 回环、双流大正文、错误认证和 worker 恢复已通过软件验证；实板和 Base 组合仍未验收。visitor 的严格 TLS、Token Login 与已鉴权 run ID 是每条 NewVisitorConn 的前置；每次访问提交共享 secret 的请求签名，再校验已认证传输上的目标名称和响应错误，拒绝后关闭该连接。READY 还须完成首次认证 Pong并绑定显式本地 listener。listener 不自动绑定通配地址，失联立即回收监听和已接受连接；不自动改用其他代理类型。

## UDP 数据报与来源所有权

UDP 实例仅向 ClientHello 声明官方 `udpPacketCodecs:["binary-v1"]`，只接受服务端精确选择该值；其他 provider 不声明 UDP codec，也不接受未经声明的选择。工作流仍独立执行 magic／NewWorkConn／StartWorkConn，之后使用 MESSAGE 类型 19 的 binary-v1 数据报帧，不把数据报作为原始字节流转发。

`esp_frp_udp.h` 是无分配、无 socket 的 codec。MESSAGE payload 包含两字节消息编号，wire 的八字节 header 单独处理。单包最多 65507 字节，整个 payload 最多 65536 字节；地址支持 IPv4、IPv6 和有界 UTF-8 zone，codec 的 IPv6 元数据不改变实际固定 IPv4 backend。decode 复制 IP，但借用输入中的 zone／payload；跨轮持有前必须复制。空数据报合法，截断、尾随字节、缺失来源、非法 flags 和声明长度不一致均拒绝。

UDP 工作组只允许一条活动 UDP stream，至多四个来源元组各自拥有一个 connected UDP socket，全部连到同一配置目标。来源元组以 family/IP/port/zone 区分，业务对端元数据不能替换目标。第五个来源的数据报整包丢弃并计数；来源 30 秒没有实际发送或接收则回收。工作流每 30 秒发送官方普通 Ping，健康空闲流不沿用 TCP 的 60 秒业务空闲回收。

活动 stream 按配置包大小懒分配接收帧、发送帧和本地接收区，不常驻申请 64 KiB。元数据最多保留 555 字节完成严格预检；合法且超过配置上限的帧排空到其精确边界后计丢弃，不能因为“太大”就跳过非法元数据。固定本地 recv 使用多一字节容量检测整包超限，整包消费并清零，不返回前缀。拆帧、粘帧和 StartWorkConn 后缀必须保持顺序；来源过期、RST、取消和 session 终止均回收其 socket 和业务缓冲。IDF 暂时关闭失败保留 fd 所有权供重试，业务字节立即清零；POSIX 不重试可能已复用的 fd。

`udp_received_datagrams` 表示本地 socket 已接受的数据报数，`udp_sent_datagrams` 表示完整回包已交给流传输的数量，均不是远端交付回执；`udp_dropped_datagrams` 和 `udp_expired_remotes` 是累计计数。client 跨重连累加计数，`udp_active_remotes`、active/waiting/cleaning 只反映当前尝试，清理后归零。UDP 本身不提供可靠交付或重排序保证。

## XTCP 会合与双方认证

XTCP 明确消费本仓维护源 [peer/frp](../../peer/frp/candidate-development.md) 的 `esp-frp-xtcp/1` 候选；原样官方 v0.71.0 没有这项绑定合同。普通代理和 FRPS QUIC 仍用官方互测。provider 使用 `EFRP_PROXY_XTCP`；visitor 使用独立 `efrp_xtcp_visitor_config_t`／`efrp_xtcp_visitor_create`，只持有目标、密钥和本地 listener。双方配置至多两个数字 IPv4 STUN endpoint、显式 peer profile 和可选单 UDP bind 地址／端口。create 复制输入字节、字符串、选项和 Flash 回调表且不联网；回调上下文及 Flash provider 上下文借用到 destroy 成功。visitor listener 在严格 FRPS 鉴权及首个认证 Pong 后才绑定。

服务端通过实际 TLS/Token control 签发当前 32 字节控制身份，不能用 caller 的 run ID 代替。provider 的 magic／NewWorkConn／StartWorkConn／SID 是单独的会合工作流，不承载业务。signal 的 nonce、SPKI、角色、proxy 与当前 control ID 受 secret HMAC 绑定；一次会合的 canonical manifest 同时绑定双方，并经各自严格控制传输送达。控制 frame 最多 4096 字节，按不超过 1024 字节的 AEAD plaintext record 顺序发送，过程中不插入 Ping 或其他 frame。

唯一 UDP fd 从 STUN 映射、认证探测延续到 peer factory；NAT 轮次含信令等待最多 60 秒。原生模式为 0..4，探测对候选地址、端口范围、TTL 和发送节奏有明确边界；要求额外随机监听 socket 的模式明确失败。不存在自动 STCP 或其他协议回退。manifest 在 peer 入场前核对真实 UTC 期限，入场后的握手与保留证明共享另外一个 10 秒绝对期限；已认证业务连接不因 manifest 到期中断。

peer provider 是 QUIC server，visitor 是 client。双方证书须满足本轮 SPKI、P256/SHA256、唯一角色 SAN/EKU、数字签名 KU、自签与真实日期，并验证实际 CertificateVerify。SAN 原始序列只能有一个固定角色 DNS，EKU 只能有对应的一个角色 OID，额外身份和未知 EKU 都拒绝；实际签名反例见[角色证书检查点](../verification/quic-peer-role-contract-checkpoint.md)。TLS exporter 绑定 canonical manifest；首条 native stream 0 严格交换双方完整 69 字节证明及 FIN，完成并释放后才开放 ID≥4 的业务 stream。每个实例最多一条 peer connection、两条业务流和一条 FRPS SID 等待流；visitor 会合期间最多保留一条已接受本地 socket。取消清零秘密和业务缓冲，所有者保留到 fd/native 引用真正释放；子 peer 的 CONNECTION_CLOSE 重试也由原 worker 推进。

主状态 READY 表示已鉴权 control 与首个 Pong；`status.xtcp` 单独报告当前 control 内的会合阶段、错误和计数，不能把主 READY 写成 peer 直连完成。host 的证书、NAT 和双方证明定向用例，以及公共 C provider/visitor 的严格 FRPS 鉴权、STUN、会合、打洞、双方证明、双流业务和取消／同实例重启已通过；异网实板、运行资源和 Base 组合仍未验收。

## 安全与验证边界

HTTP 与 HTTPS 的域名/子域路由不构成业务授权。公开互测分别检查 FRPS 入站客户端认证和本地服务的业务 Bearer 授权；HTTPS 保持本地服务证书验证，不在 FRP 组件中终止业务 TLS。错误 Host/SNI、重复代理、错误 STCP secret/user 和未知目标均有独立拒绝用例。

host 测试分别使用完整官方 FRPS、官方 frpc 及固定 wire/msg/Yamux API，公开临时 Token、证书和回环监听随测试清理。API fixture 的故障注入不冒充完整 FRPS 行为，transport echo 不冒充 FRP 会话。测试命令见[测试入口](../../tests/README.md)；实板和 Base 组合仍须独立核对资源、身份及恢复基线。

正式传输的原生 ID、ACK 借用和清理合同见[流传输与所有权](stream-transport.md)。STCP `allow_users` 的 user 是共享 Token 验证后绑定的 Login 字段；持有同一 Token 的调用者仍可选择该字段，它不建立每用户独立凭据。私有 proxy 的 secret 才是该代理的访问密钥边界。
