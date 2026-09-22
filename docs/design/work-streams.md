# 工作流与固定目标转发

`src/work.c` 是组合会话的内部工作流实现，与控制层共享唯一 Yamux，不创建线程或 timer。每条流发送 wire v2 magic 和 Token 签名的 NewWorkConn，读取 StartWorkConn 后转发原始业务字节；不重复 Hello、不叠加控制 AEAD。外层严格 TLS 始终覆盖传输。

## 目标、容量与状态

单一 proxy 的 `local_ipv4[4] + local_port` 就是配置 allowlist 的唯一项，create 复制输入；所有工作流只能连接该固定目标。StartWorkConn 的 src/dst 地址和端口只按类型、长度和范围验证，不能改变路由。消息必须匹配完整 proxy name，拒绝未知字段、重复解码键、错误类型、错误消息和超长 payload；服务端 error 单独记为 WORK_REJECTED。

三个工作槽对应最多两条 CONNECTING/ACTIVE 流和一条 SENDING/WAITING 预备流，加上控制流共四个 Yamux 槽。每轮从不同槽开始推进，避免固定首槽独占输出。尚在清理的 socket 计入连接上限；第三条实际业务 StartWorkConn 被 RST，不打开第三个本地连接。ReqWorkConn 待办最多三条，突发超过上限计数拒绝；拒绝不销毁正常的控制会话和其他业务流。

NewWorkConn 输出有 10 秒期限；收到 StartWorkConn 的首字节后，完整帧必须在 10 秒内到齐。健康的预备流可以长期等待，不打开本地 socket，不阻塞其他流。官方 FRPS 把补充连接保存在 workConnCh；客户端单方面定时关闭未被取走的预备流会留下失效条目，所以下一次业务之前不能仅按“等待了多久”关闭它。预备流在会话停止或对端结束时收回。

活跃流连续 60 秒无业务进展即回收；有数据等待本地写入或 Yamux 输出时，连续 2.5 秒无进展即结束该流。Yamux 自身还限制 ring 阻塞、迟到数据排空、协议窗口和 framing；无法保持同步时才结束整个会话。共享 transport 存在队头阻塞，回归证明慢流结束后另一条流可继续，不承诺零阻塞。

## 字节与关闭所有权

每槽使用 4096 字节握手 payload 区和各 1024 字节的两方向暂存；StartWorkConn parser 只消费一帧，后缀立即归业务方向，不能丢弃或再次解析。握手完成后清空 JSON 工作区。每次仅搬运接受的前缀，未消费字节保留到下一步，输出成功只意味着相应层接管了数据。

远端 Yamux FIN 必须等全部先前数据写入本地后，才调用本地 close_write；本地 EOF 必须等此前响应交给 Yamux 后，才排队 Yamux FIN。两个方向独立，因此收到一个方向 FIN 后，另一方向仍能传输。双向结束后使用连接层的普通 finish 保留 TCP 尾数据；网络错误、RST、期限、协议拒绝和取消走终止清理。

单条 work 失败只计入 status.work.last_error/failed 并收回该槽，正常双向结束且本地清理完成计入 completed。local_sent/local_received 是本地 socket 接受或读到的字节，不是远端交付回执。session destroy 在本地 fd 尚未释放时返回 WOULD_BLOCK 并保留整个对象；不能先 free 后让 lwIP 清理访问悬空对象。

## 已验证范围

- 实际官方 FRPS v0.71.0、严格 TLS、HeartBeats/NewWorkConns scopes：100 轮并发双流，200 次本地连接，每流两方向分别核对 300001 字节，全部结束后 fd 回到基线。另有本地拒绝、第三流容量、本地 RST 和活动中取消四项。
- 12 个官方协议 API 场景：StartWorkConn 与业务粘连、两个方向分别先 FIN 再反向传输、预备流长期等待后再使用、错误 proxy/服务端 error/超长/截断/越界端口/重复键、握手和活跃空闲期限，以及真正慢读阻塞与另一条流继续完成。预备等待和两类长期限使用测试 owner 的单调时钟推进；慢读 2.5 秒背压使用真实 I/O。
- 真实 FRPS 使用的 golib Join 在任一方向 EOF 时关闭双方；因此真实服务端字节测试在 EOF 前交换应用回执，严格的反向半关闭能力由官方 Yamux/wire 对端单独证明。不能把组件支持扩大为官方 FRPS 提供端到端半关闭。

C3 当前会话对象共 127728 字节，每条连接对象 56 字节，另需 TLS、lwIP、cJSON 和任务栈。仅编译通过，尚未验证 MCU 堆峰值、内存不足时的清理、完整 worker/退避与 Base/MQTT 组合；host 测试不替代这些完成条件。
