# C3 DNS 配置失败与 DNS/TLS 实板验收

## 首次失败

2026-09-23，将独立 `tcp_proxy` 样例从数值 FRPS 地址切换为隔离域名，并设置 `sample_dns_ipv4` 后，C3 获得 station IP，但立即报告 `dns_config_error=20481`。尚未启动 SNTP 和 FRP，也未发送实验域名查询；该轮不能算 DNS、TLS 或连接生命周期通过。

锁定 ESP-IDF v6.1 的 `esp_netif_set_dns_info()` 明确拒绝零地址。样例原先用该 API 清空备用及 fallback DNS，触发 `ESP_ERR_ESP_NETIF_INVALID_PARAMS`。这是样例装配错误，与先前的 lwIP 零窗口 ACK 根因不同，不需要新增 SDK 修改。

修正保留合法主 DNS 的 `esp_netif` 设置，使用 `tcpip_callback_wait()` 在 lwIP 线程调用 `dns_setserver(i, NULL)` 清空其余位置。等待成功后才启动 SNTP；失败继续明确退出，不退回 DHCP 解析器。

## 实验边界

使用相同 ESP32-C3、同一精确 SDK 锁、独立官方 FRPS v0.71.0 和仓外私有输入。FRP 使用真实域名与匹配 SAN，CA、主机身份和日期校验保持开启。SNTP 使用由原时间服务解析得到的实际 IPv4，可信条件仍来自设备收到的同步结果，不能由主机写入系统时间冒充。

Mac 的系统服务已占用 53 端口；实验 DNS 使用普通用户进程监听局域网高端口。临时 PF 规则仅匹配已核对板卡的当前 station 源地址、Mac 目标地址和 UDP 53，将该流量转到 fixture；板上仍发送标准 UDP 53 查询，原 SDK DNS 实现未改端口或回调。规则、服务进程和配置均只存在于本次实验，结束后核对恢复。没有修改系统 DNS 设置、Clash 配置、生产 FRPS 或设备持久配置。

每轮重新枚举并核对 USB、UUID、revision 5、两份一致的完整 Flash、分区和有效 ota_0，仅写入实验应用。结束后恢复完整原应用槽，双份全量回读，并核对原 Wi-Fi 与 Mac Bridge。人工断电仍按维护者要求暂缓。

## 证据与状态

首轮私有证据为 ESP Tool `provisioning/receipts/private/p4-dns-20260923/`。包含失败串口记录、源码、输入、编译产物和恢复回执。该轮完整原固件、Wi-Fi、Bridge 与临时 PF 规则已恢复；清理脚本首次将 Python 虚拟环境入口与实际 Homebrew 进程路径作字面比较，误报 DNS 进程归属，随后按精确脚本路径核对并停止，没有将失败删改为首次通过。

修正后的独立 SDK 构建及第二轮 `p4-dns2-20260923/` 实板矩阵通过：

| 范围 | 实际证据 |
| --- | --- |
| 真实 DNS | 收到 48 个来自已核对板卡源地址的 FRP 域名查询；域名 SAN、严格 TLS、Token、代理与首次 Pong 成功 |
| DNS 失败与恢复 | NXDOMAIN、零地址与完全不回复均在 CONNECTING 阶段报告 `EFRP_DNS_ERROR`，退避后恢复；无响应由真实 SDK 重试与回调结束，不用测试时钟推进 |
| 迟到 DNS stop | 5 轮中，零等待返回 WOULD_BLOCK；50 ms 调用均在 50 ms 返回 TIMEOUT，句柄保留、状态为 DRAINING；释放迟到响应后 stop 成功，没有额外 READY |
| 迟到 DNS destroy | 5 轮 50 ms TIMEOUT 均保留句柄；响应到达后 destroy 清空句柄，再 create/start 并重新鉴权成功 |
| SDK 自行超时后迟到响应 | stop 等待真实 SDK 回调 6660 ms 后成功；随后发送旧查询响应，设备继续 STOPPED，没有新建连接或 READY |
| TLS 拒绝 | 错主机名、已过期、尚未生效、非受信签发密钥均在 TLS 阶段进入 FAILED；错误为 `EFRP_TLS_TRUST_ERROR`，verify flags 分别为 4、1、512、8，没有自动重试；每项换回有效证书后恢复 |
| Token 拒绝 | 官方 FRPS 拒绝错误 Token，设备在 AUTHENTICATING 阶段进入 FAILED / `EFRP_LOGIN_REJECTED`；恢复原实验 Token 后重新登录并转发成功 |
| 业务字节 | 共 18 条流逐字节通过，包含 10 条 65536 字节与 8 条 1024 字节流，每个方向累计 663552 字节 |
| 释放与资源 | 6 份销毁后样本均为 7 个任务 / 1 个回环 listener，heap 228580–229580 字节；分配失败、panic、看门狗均为零 |

本轮最低 heap 57308 字节、采样最小连续块 45056 字节，worker/main 最低栈余量 5104/2044 字节，其他任务至少 1196 字节；RSSI -78 至 -66 dBm。此矩阵的载荷和时序不同于先前 300001 字节压力矩阵，不能用本轮较高的最低 heap 覆盖此前 46328 字节的事实，也不证明完整组合已达到 48 KiB 目标。六次释放不足以代替百次或长稳结论。

第二轮已恢复完整原应用槽，两份全量回读等于本轮实验前基线，同 UUID、revision 5、Wi-Fi 和原 Bridge 均通过。临时 DNS/FRPS 已停止，专属 PF 转发规则清空，主 NAT 规则与实验前相同；原系统 SDK 未变。此轮没有修改 FRP 库的网络、协议或 SDK 实现；修改限于样例的 DNS 装配、实验命令和诊断。

完整异常 wire/AEAD/Yamux/work 输入的 MCU 矩阵、Base/MQTT 组合、资源峰值及 72 小时长稳仍待完成，P4 保持实施中。
