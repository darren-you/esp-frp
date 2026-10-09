# ESP FRP Roadmap

只有 ESP32-C3 与 ESP32-D0WD-V3 各自的独立示例、`esp-base` 组合和 `esp-tool` 能力状态均通过才标 verified；尚未实现或未测保持明确状态。

| 阶段 | 能力 | 当前状态 | 验收 |
| --- | --- | --- | --- |
| R0 | TCP + TLS + Yamux + wire v2 + Token | 开发中：独立 C3 样例已通过双流、认证负例和百次回收；ESP32 样例已通过固定 SDK 空输入构建，实板矩阵和两目标 Base/MQTT 组合待验收 | 官方 FRPS、两目标各自的双流、慢读背压、认证负例、100 次回收及 Base 组合 |
| R1 | UDP proxy | 软件候选：binary codec、完整数据报、四来源映射与回收已实现，host 官方互操作及 worker／同控制会话恢复已通过；双板/Base 组合未验收 | 边界、丢包、重排、突发与会话回收 |
| R2a | STCP provider / visitor | provider 与独立 ESP visitor 的官方双角色软件互测通过；实板未验收 | ESP 与官方 frpc 双角色互测、错误密钥 |
| R3 | HTTP/HTTPS proxy 与域名/子域 | 软件候选与官方 FRPS Host/SNI、业务授权、大响应、长地址互测通过；实板/Base 未验收 | Host/SNI、重复注册、并发大响应；HTTPS 终止在本地服务 |
| R4 | ngtcp2 QUIC transport | 正式 ACK／背压／丢包、完整 C TCP/UDP/STCP visitor 和真实 FRPS 进程重启及取消软件互测通过；含完整 XTCP 的同输入双目标样例编译、链接及原 1 MiB 容量门通过，C3 余 15520 B、ESP32 余 60320 B；实板/Base 未验收 | C3 TLS1.3/ALPN frp/双流/峰值 heap 与 Flash，QUIC 不叠 Yamux |
| R2b | XTCP NAT 打洞 | 官方 peer 绑定缺口已复现；维护 Go 当前控制身份与完整公共 C provider/visitor 的 STUN、单 socket 会合/打洞、双向认证与 reserved0 proof、双业务流、停止/重启软件互测通过；异网实板与 Base 未验收；依赖 R1/R4 | 异网真实 NAT、绕过 FRPS 的数据证据、secret 与 peer 身份负例 |

维护者于 2026-10-02 允许扩展软件提前按 R1→R2a/R3→R4→R2b 并行；两目标实板及最终验收仍以前述 R0 和[Base 原生业务与固件 OTA 首版](https://github.com/esp-space/esp-base/blob/master/docs/operations/ota-allocation-diagnostic-checkpoint.md)闭环为前置。软件测试不改变 verified 条件。不加入 KCP、静默 STCP 回退或替换硬件。ngtcp2 当前无直接 IDF Mbed TLS crypto helper，QUIC TLS 不能用普通 esp_tls 代替；资源原型不成立时记录结果再决定范围。XTCP 官方动态自签证书的 peer 身份边界单独验证，不把加密写成已认证。

当前冻结与失败保留见[软件检查点](docs/verification/xtcp-candidate-software-20261003.md)。最终 Mbed TLS ASan/UBSan 完整矩阵单次 52/52 通过，含完整 XTCP 双角色及 QUIC 关闭所有权回归；OpenSSL 基线 21/21 通过。C3 仅使用 SDK 官方寄存器保存恢复调用优化收敛容量，未更改原分区或移除协议/认证；其性能代价仍须实板测量。
