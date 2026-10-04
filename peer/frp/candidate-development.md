# XTCP 对端软件候选

此目录是 `esp-frp` 维护的完整 FRPS/FRPC 源码候选，来源固定为官方 v0.71.0、提交 `4a23aa181c1d7e28eecaa8216024ed753b9d27c8`，由精确 `git archive` 导入，保留上游 LICENSE 和源码声明。新增实现与变更直接写在该源树，构建不使用 overlay、补丁注入或第二套信令服务。候选版本是 `0.71.0-esp-frp-xtcp.1`。本轮没有改 `frp-service` catalog、生产部署或有效凭据。

FRPS 和 FRPC 是本源码的真实消费者，ESP 的 provider 与 visitor 消费相同候选 XTCP wire。新的 P2P ALPN 只有 `esp-frp-xtcp/1`。XTCP 信令只支持 wire v2，消息 ID 为 visitor 20、provider 21、response 22、work SID 23、report 24；官方原始 14–18 与 v1 XTCP 已删除。普通非 XTCP 代理的上游 wire 类型保持。原样官方 XTCP 对端不支持此候选，没有 KCP、旧自签无绑定路线或失败后转 STCP 的执行路径。

主 FRPS 控制链仍要求真实传输 TLS、正常 CA/主机名验证和非空 Token。客户端从当前成功 LoginResp 获得服务端 CSPRNG 生成的 32 字节 `xtcp_control_id`；该字段只在当前连接 RAM 中存在，不从用户、run_id 或持久配置推导。服务端实际 Control 注册此身份，异步信令检查与关闭撤销使用同一锁。关闭的身份不会因已排队 handler 再次入场，旧 provider 的延迟关闭不能删除相同代理名的新 owner。

同一次 visitor admission 同时检查 proxy 归属、实际用户 allow_users、当前真实控制身份、secret HMAC 和 ±5 秒请求时间；provider 回复还必须来自此代理的真实注册 owner。双方各生成本次 P256 私钥、角色证书和 32 字节 nonce。信令携带其证书 DER、SPKI SHA256 和 HMAC。服务端仅向对应两个严格控制连接分发同一 manifest 及对端证书。

manifest 是单次会合的 RAM 对象，不设持久 registry、凭据轮换或 generation。规范编码为 `EFRPXTC1`、代理 UTF-8 长度 u8/内容、SID32、provider/visitor control ID32、provider/visitor nonce32、provider/visitor SPKI SHA256、issued/expires UTC 秒 BE64。代理最长 128 字节，总长最大 377。admission 生命周期上界为 60 秒，以覆盖上游随机端口探测约 35 秒的真实路径；QUIC 握手和 proof 另有 10 秒绝对期限。有效期到期拒绝新 admission，不截断已建立的业务流。

P2P TLS1.3 双方必须提供角色证书并证明私钥。Go 使用信令下发的唯一 exact certificate 作为专用 RootCAs/ClientCAs，正常 X509 验证保持开启，同时核对 P256、self signature、角色 SAN/EKU、有效期和 SPKI pin。provider SAN 是 `esp-frp-xtcp-provider`，visitor SAN 是 `esp-frp-xtcp-visitor`。ESP 使用同一固定证书合同和真实 CertificateVerify，不混用 FRPS CA client 工厂。

首个保留双向 stream ID 0 仅承载 proof。TLS exporter label 为 `EXPORTER-esp-frp-xtcp-peer-v1`，context 是规范 manifest 的 SHA256，长度 32，禁止 early/0-RTT。proof 为 `XTP1`、sender role u8、manifest hash32、`HMAC-SHA256(exporter, "esp-frp-xtcp-proof-v1" || role || manifest_hash)`。两端明确确认同一次 SID/代理/控制身份/nonce/有效期的完整上下文后，才允许业务 stream；保留流必须 FIN，尾部额外字节拒绝。此确认解决相同密钥 pin 下跨 SID 或控制对象复用，身份私钥证明仍由 mutual TLS 承担。

UDP 探测采用 `XHD1`、JSON 长度 BE16、NatHoleSid JSON（最多 512 字节）、覆盖前述所有字节的 secret HMAC-SHA25632。旧 AES-CFB 探测格式不保留。SID、transaction_id、nonce、response 均有完整性保护；每轮 UDP 探测 nonce 使用新的 CSPRNG32，并编码为 64 字节小写十六进制；响应 SID、transaction_id 和 nonce 必须同时匹配本次请求。错误包不能延长绝对 read deadline，取消立即中断等待。多监听 socket 的读协程和随机发送协程必须同步取消并结束，只有胜出的原 UDP socket 能交给 QUIC，其他监听全部关闭；请求的监听数量无法创建时明确失败。探测只提供路由候选，进入后端仍必须完成 P2P TLS pin 和保留流上下文验证。

构建实际消费者：`go build -mod=readonly -tags noweb ./cmd/frps ./cmd/frpc`。该构建显式选择上游原生 console-only 制品，不依赖未提交的 Web dist；Dashboard/Web 管理界面不在此 XTCP 软件候选消费范围内。基础候选验证：`go test -mod=readonly -race ./pkg/xtcpbinding ./pkg/nathole ./pkg/msg`。C 核心是 `include/esp_frp_xtcp_binding.h` 与 `src/xtcp_binding.c`，双方使用同一独立固定向量。

当前已经通过 C/Go 编码向量、TLS 通道/角色/逐字段反例、真实 mutual QUIC、错误 SID/代理/证书/旧 ALPN 禁止业务流，以及认证 UDP 的逐字节损坏和取消期限测试。完整维护对端已经通过真实严格 FRPS Login→当前控制身份→双本地 STUN→认证 SID→双方 provider/visitor→保留流 proof→两条各 300001 字节后端业务，并在真实 control 关闭后收回流；全链路启用了 Go race detector。

完整 C 公共客户端已分别作为 provider 和 visitor，通过上述真实维护 FRPS 与桌面对端全链路。测试在 create 后破坏调用方 CA、Token、target、secret 和 options，证明客户端使用自己的副本；两条并发流各传输 300001 字节，停止后均关闭，原 worker 重新启动后再次完成两条流，撤销可信时钟后业务连接收回。错误 Token、错误 FRPS 主机名和不可信时钟均拒绝控制建立；错误 admission secret、用户和不存在的目标代理保持控制可用、后端连接数为零。每个 C 客户端停止、销毁后 fd 与 DNS 数量恢复基线。容量断言区分两个业务 slot、一个不拥有本地业务 socket 的 FRPS SID 等待流，以及 visitor 唯一已接受的会合 socket。

正式入口是主机测试构建中的 `ctest --test-dir <host-build> -R '^xtcp_client_upstream$' --output-on-failure`，它设置实际 `EFRP_XTCP_CLIENT_PEER` 后执行本源树的 `TestCClientFullCandidate`，Go 固定启用 race detector；本次 C peer 来自启用 ASan/UBSan 的 host 构建，CTest 本身不自动添加 C sanitizer 编译选项。手动复现时使用 `EFRP_XTCP_CLIENT_PEER=<host-build>/xtcp_client_peer go test -mod=readonly -race -count=1 -run '^TestCClientFullCandidate$' ./test/xtcpbinding`；没有此环境变量时独立 Go 包会明确跳过 C 进程互测，该跳过不算完成证明。此链路使用本机回环与两个真实 UDP STUN 监听；ESP 目标编译/容量结果见[软件检查点](../../docs/verification/xtcp-candidate-software-20261003.md)；异网 NAT、数据绕过 FRPS 的网络观测、资源峰值和五能力实板组合仍需各自验收，不能以本目录 host 结果替代。

公共头的 C++ 外部消费合同已于 2026-10-03 验证：[public_consumer_contract.py](../../tests/public_consumer_contract.py) 在临时父级 CMake 工程中引用当前源码，分别以 trace OFF/ON 构建并真实链接 C 导出。开启时核对 client、session、work、transport 与 Yamux 的全部诊断成员及类型，关闭时拒绝意外公开 trace 宏。该入口固定 OpenSSL host 构建与 `BUILD_TESTING=OFF`，支持显式本机 CMake/依赖前缀；程序不运行，结束后清理临时工程。此结果证明公共 ABI 配置向真实外部 C++ 消费者传播，不替代协议运行或实板证据。
