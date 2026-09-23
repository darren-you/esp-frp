# C3 协议异常输入与恢复验收

2026-09-23，同一 ESP32-C3 在锁定的 ESP-IDF / ESP lwIP 修正组合上，完成 36 项控制协议和工作流场景。每项均核对实板状态、销毁资源，再重启隔离的官方 FRPS v0.71.0，以两条 TCP 流逐字节验证恢复。此记录不代表完整 P4、Base/MQTT 组合或长稳通过。

## 对端和时间来源

公开入口为 [crypto-interop 的单设备 fixture](../../tests/crypto-interop/README.md#单设备协议-fixture)。它复用 host 的官方 TLS、Yamux、wire、Token 和 AEAD API，精确校验登录身份和代理名；非法 Yamux header 由固定字节构造，不实现第二套服务端多路复用。私有配置限制唯一监听地址、设备源 IP、场景和期限，每个进程只处理一条连接。

第一轮 `p4-protocol-20260923` 没有获得 SNTP 同步，80 秒内始终 `trusted=0`、客户端未启动，不能算协议验收。宿主对同一时间源和其当前三个解析地址的 UDP 查询也未收到响应；仅证明当时未响应，不推断供应商或网络故障根因。该轮原应用、整机 Flash、UUID/revision 5、Wi-Fi、Bridge 和临时网络规则均已恢复，失败记录保留。

最终轮 `p4-protocol2-20260923` 改用私有本机 SNTP fixture 的实时宿主时钟。宿主已开启网络校时，并在本轮与新鲜 HTTPS 响应 Date 比较，相差不足 1 秒。C3 仍经真实 UDP 123 请求、匹配 originate timestamp 的 SNTP 响应和 SDK 同步回调建立可信时间，没有串口直接设时、硬编码时间或放宽证书日期校验。此项是受控时钟下的协议矩阵，不重复声称公共 NTP 可达性通过。

DNS 和 SNTP 服务由普通用户监听高端口；临时 PF 规则只转发核对后的单块板卡到本机的 UDP 53/123。系统 DNS、Clash、生产服务与设备持久配置均未修改。

## 实板结果

| 范围 | 结果 |
| --- | --- |
| 4 个正例 | LoginResp 紧随 AEAD 尾数据、4096 字节控制 payload、单条 65536 字节 AEAD 明文、ReqWorkConn 突发均进入 READY；最大记录与突发请求观察到有界拒绝 |
| 控制容量 | 4097 字节控制 payload 返回 `EFRP_CAPACITY_EXCEEDED`；超出 65552 字节密文加 tag 上限的 AEAD 记录返回 `EFRP_PROTOCOL_ERROR` |
| 语义及认证 | 错代理名、错误字段类型、转义重复键、未知消息、重复 Pong 返回协议错误；篡改 tag 和错误 Pong 返回认证失败 |
| 截断与关闭 | Login、wire 帧、AEAD 记录及 Yamux header 截断返回 `EFRP_TRUNCATED`；完整流 FIN / TLS close_notify 返回 `EFRP_SESSION_CLOSED` 并进入退避 |
| 真实期限 | 注册与首次 Pong 的 10 秒期限返回 `EFRP_TIMEOUT`，进入退避；未推进测试时钟 |
| 8 个 Yamux 场景 | 错版本、类型、SYN+ACK、超 credit DATA、窗口增量溢出、未打开流均返回协议错误；控制流 RST 返回 `EFRP_STREAM_RESET`；截断独立验证 |
| 7 个无效工作流 | 名称、错误回执、超长、截断、非法端口、重复键、部分帧超时分别返回预期 work 错误；控制通道保持 READY，未新增本地目标连接 |
| 空闲工作流 | 合法 StartWorkConn 建立唯一回环连接，真实 60 秒空闲后回收并报告 TIMEOUT；期间认证心跳继续，控制通道保持 READY |
| 每项恢复 | 先完整 destroy，再连接重新启动的官方 FRPS、重新鉴权并验证双流；不把 fixture 结束标记当作设备通过 |

协议/认证错误进入 FAILED，不自动重试；完整关闭和响应超时进入 BACKOFF。重复 Pong 的首个合法消息可能先发布 READY，再由第二个消息终止会话，该调度结果没有被误判为永不就绪。工作流错误只计入 work 状态，不改变控制会话的成功状态。

包括初始连接，共 74 条 1024 字节流逐字节通过，每个方向累计 75776 字节。这是异常后的短业务恢复证明，不替代先前的大载荷压力测试，也没有证明同一故障会话内的完整工作流隔离矩阵。

## 资源与恢复

73 份销毁后样本的任务/socket 均为 7/1，heap 范围 228180–230852 字节，首末十份中位数 229868/228572 字节；不同故障场景的释放采样不等于长期无泄漏证明。分配失败、panic、看门狗均为零。

本轮最低 heap 54232 字节，采样最小连续块 45056 字节。worker/main 最低栈余量为 5072/1948 字节，其他任务至少 1180 字节；这些较轻负载下的数字不能覆盖此前大载荷最低 heap 46328 字节的事实，48 KiB 组合目标仍未证明。

每轮都重新核对同板 UUID、revision 5、两份完整 Flash、分区与有效 ota_0，仅写入应用槽。最终恢复整个原应用槽，两份完整回读与实验前基线逐字节相等，原 UUID、revision、Wi-Fi 和 Mac Bridge 已验证。fixture、FRPS、DNS、SNTP、串口 monitor 均退出，单板 PF 规则清空、全局 NAT 规则未变，原系统 SDK 未改。

## 软件验证与剩余范围

本轮固件代码只增加工作请求、拒绝、待处理与清理计数的样例输出；没有修改 FRP 库或 SDK 实现。共享测试增加最大记录、超长输入及非法 Yamux，并让 host / device 使用精确身份和显式 Token。受影响的 `session_upstream` 与 `work_faults_upstream` ASan/UBSan 回归通过，前者含 107 条官方 FRPS 会话和 28 个协议 fixture。初次把超长 AEAD 的预期写成容量错误；核对既有 `aead.c` 和单元合同后改为协议错误，保留失败日志。

最终 C3 构建通过，所有 SDK 配置值与上一轮相同；一次构建命令漏带 C3 默认配置而失败，修正显式 target/defaults 后重建，没有用错误 target 制品刷写。工程结构检查和精确 SDK 检查通过；结构门禁不代替协议验证。

源码、锁、私有输入、设备/服务日志、ELF/map、固件、恢复字节和摘要保存在 ESP Tool 忽略目录的上述两轮 receipts，目录/文件为 0700/0600；公开仓只保存脱敏说明与通用 fixture。

工作流双向半关闭、DATA 附 FIN、预备流长期等待、慢流及已释放流排空、活跃流 RST 与另一条部分握手并存等完整 MCU 组合仍待补齐。Base/MQTT 同时运行、资源峰值、发布纳管和 72 小时长稳尚未完成；人工断电继续按维护者决定暂缓。
