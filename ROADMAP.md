# ESP FRP Roadmap

只有独立 ESP32-C3 示例、`esp-base` 组合和 `esp-tool` 能力状态均通过才标 verified；尚未实现或未测保持明确状态。

| 阶段 | 能力 | 当前状态 | 验收 |
| --- | --- | --- | --- |
| R0 | TCP + TLS + Yamux + wire v2 + Token | 开发中：仅 wire 帧 parser | 官方 FRPS、C3 双流、慢读背压、认证负例、100 次回收 |
| R1 | UDP proxy | 未实现 | 边界、丢包、重排、突发与会话回收 |
| R2a | STCP provider / visitor | 未实现 | ESP 与官方 frpc 双角色互测、错误密钥 |
| R3 | HTTP/HTTPS proxy 与域名/子域 | 未实现 | Host/SNI、重复注册、并发大响应；HTTPS 终止在本地服务 |
| R4 | ngtcp2 QUIC transport | 未实现，需先冻结 TLS 后端 | C3 TLS1.3/ALPN frp/双流/峰值 heap 与 Flash，QUIC 不叠 Yamux |
| R2b | XTCP NAT 打洞 | 未实现，依赖 R1/R4 | 异网真实 NAT、绕过 FRPS 的数据证据、secret 与 peer 身份负例 |

顺序 R0→R1→R2a/R3→R4→R2b。不加入 KCP、静默 STCP 回退或替换硬件。ngtcp2 当前无直接 IDF Mbed TLS crypto helper，QUIC TLS 不能用普通 esp_tls 代替；资源原型不成立时记录结果再决定范围。XTCP 官方动态自签证书的 peer 身份边界单独验证，不把加密写成已认证。
