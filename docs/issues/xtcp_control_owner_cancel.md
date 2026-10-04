# XTCP 控制与代理资源归属修复

真实 maintained FRPS/FRPC 本机链路已复现旧缺口：公开删除 provider 代理而保留双方 Service 后，旧 QUIC 业务仍可回显。修复给每个真实 Control、每个 XTCP 代理派生现有 context；Control 仅在原 closeSession 时撤销，代理 Stop 直接撤销本实例。STUN、工作 SID 读取、QUIC 握手／保留流 proof、业务 Accept 和本地 backend Dial 使用真实 owner；普通代理 Dial 的原 Background 与 GracefulClose 等待语义保持。没有 registry、generation、额外 owner 层或失败 fallback。

旧源码行为红实际 exit1（非 Go 总测试超时）；race 真实链验证 Service 停止、公开删除后同名重加、仅断开 provider Control 自动重连三个场景，旧两业务流与两个空闲 backend 终止，新 owner 可真实回显。受影响单元 race、FRPC/FRPS noweb 离线编译与 vet 通过。pending SID 测试先证明实际 Read 已开始；STUN 取消后原 UDP 端口可重绑定，proof 双角色在真实 streamID0 开始 I/O 后可取消。

先前 fixture 错把读 deadline 当关闭、重复重设 global logger race、恢复观察小于现有 visitor20秒预算、重复 socket Close 的失败均保留；不作为最终资格。C peer 组合测试本次明确 skip，需 Root 的实际 C 组合入口。仅宿主软件资格；没有实板、外网 NAT、容量、Flash 时延或生产资格，saving=0。普通 strict TLS/v2 无条件协商 identity 是另一未修合同，本候选不改该路径。
