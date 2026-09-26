# Yamux 客户端核心

`include/esp_frp_yamux.h` 与 `src/yamux.c` 实现首版 FRP 所需的客户端多路复用子集。它没有 socket、任务或回调，调用方持有 `efrp_yamux_t` 并由同一个 worker 调用所有 API；会话对象应置于静态存储或受控堆，不放在 C3 的小任务栈中。会话层已将其接入 TLS、AEAD、FRP 登录与代理控制，完整实板验收仍在继续。

协议依据为 FRP v0.71.0 固定的 [Yamux 规范](https://github.com/fatedier/yamux/blob/d0154be01cd6bcb13bd89fe9c3614b2b9395bc72/spec.md)。源码独立按 pull 接口和有界存储组织，不移植上游 Go 状态机或缓冲实现。

## 存储与流量控制

- 总上限四条本地发起的奇数 ID 流。每条流在成功 `open` 时分别申请 1024 字节接收 ring；`release` 清零释放该流 ring，最终 `destroy` 清零释放尚未释放的 ring，然后才可重新 `init` 或回收调用方拥有的 mux 对象。分配失败返回 `EFRP_NO_MEMORY`，不消耗流 ID 或控制队列。输出共用一个 1024 字节 DATA 缓冲及 12 字节帧头，另有八个控制帧槽。没有每流 256 KiB 或 6 MiB 实体缓冲。
- 每流接收和发送初始信用均为 262144 字节。收到 DATA 头时预留整个声明长度的接收信用，随后逐段写 ring；超信用立即终止会话，合法大帧不因超过 ring 而失败。
- 自动 WindowUpdate 按流轮询，在持续有收发需求时与 DATA 交替占用输出位置；待发 SYN/FIN/RST/PING/GOAWAY 等控制队列仍优先。没有待发业务时继续直接排空信用，不等待虚构数据。避免某条持续接收流或连续窗口回补饿死其他方向。
- 应用 `read` 消费数据后累计待归还信用。`output` 生成 WindowUpdate，只有 `consume_output` 确认其全部字节进入 transport 后才增加接收信用；部分发送不提前增加。对端 WindowUpdate 只增加发送信用，检查 uint32 溢出；允许官方 FRPS 的 6 MiB 窗口增量。
- `write` 复制并报告本次接受的字节数，最多一块 1024 字节，遵守发送信用。`EFRP_OK` 不证明业务端收到数据。输出缓冲与控制队列满时返回 `EFRP_WOULD_BLOCK`，不覆盖待发字节。

搬运块大小按 work 的 1 KiB 读写单元收敛；接收 ring、输出队列与会话 transport 暂存可在不同层分别持有未消费字节。此变化只影响每次调用可消费的前缀和内存占用，初始信用、合法 DATA 大小及 EOF/背压语义不变，调用方仍须按实际 `written`/`consumed` 推进。

## 调用顺序

1. 在新 transport 上 `init`，每轮 I/O 前使用单调毫秒时间 `tick`；时钟倒退终止会话。
2. `open` 分配流并排队 SYN。允许 SYN 发送后、收到 ACK 前发送数据；ACK 证明对端接受，RST 明确拒绝。
3. 取得 `output` 的只读字节，按 transport 实际写入长度调用 `consume_output`。部分写入保留原序列；网络失败关闭会话，不重新发送已接受前缀。
4. 将 transport 字节交给 `feed`，严格保存 `consumed` 后的剩余输入。ring 满导致 `WOULD_BLOCK` 时停止 transport 读取，继续排空本地目标与输出，再恢复 feed。零长度 feed 可继续处理等待控制队列位置的完整帧头。
5. 逐流 `read` 消费字节；DATA 附 FIN 时，完整 DATA 收齐后才记录远端 FIN，ring 中的数据读完后才返回 EOF。本地 `close_write` 只关闭发送方向，仍允许继续接收。
6. 仅在 RST 后，或双向 FIN 且 ring 排空后 `release`。ID 不复用，达到 uint32 范围上限后拒绝新流。会话终止时调用 `destroy` 回收未释放的流 ring，再释放 mux 自身；重复 `destroy` 安全。`info` 只返回状态快照；结构体其他字段供存储布局使用，不由调用方修改。

`finish` 仅判断 transport EOF 是否截断帧；即使帧边界完整，意外断连也须由会话 owner 结束所有业务流。任何负的会话错误都需要停止 transport、销毁上层会话并重新初始化，不能继续发送遗留 output。

## 关闭、背压与期限

FRP 的 control/work stream 均由客户端发起；服务端发起的偶数 SYN 返回 RST，不分配业务流。DATA/WindowUpdate 上的 ACK、FIN、RST 分别更新确认、半关闭与重置状态；合法 ACK+FIN 和 DATA+FIN 保留先读完数据再 EOF 的语义。重复 ACK/FIN、重复或错误方向 SYN、未知未来 ID、非法类型/flags、窗口溢出、超信用及异常 GOAWAY 会终止会话。正常 GOAWAY 禁止新流，已存在流可继续收敛。

| 条件 | 本核心行为 |
| --- | --- |
| ring 满且后续 DATA 无法消费达 2500 ms | 排队 RST，清空该流 ring，按帧剩余长度排空；控制队列无容量则终止会话 |
| 输入残帧或输出连续 5000 ms 无进展 | 终止会话 |
| 残缺帧头、等待控制槽的帧头累计 5000 ms | 终止会话；零星字节不延长绝对期限 |
| 关闭流的当前 DATA 排空累计 5000 ms | 终止会话；零星字节不延长期限 |
| 已释放/拒绝流的单条 DATA 超过 256 KiB，或会话累计跳过的网络 DATA 超过 1 MiB | 终止会话，不无限排空 |
| 发起流 10000 ms 未获 ACK | RST；等待 owner 释放槽 |
| 主动 PING 5000 ms 未获匹配 ACK | 终止会话；同一时刻最多一个主动 PING |

多个流共享一条 transport；一个未消费的 DATA 会阻挡后面的其他流或控制帧。小 ring 不消除这个队头阻塞，本实现通过停止读取、有限等待及必要时 RST/关闭会话控制资源。业务本地 socket 的连接、空闲和预备流生命周期由 work 模块处理，重连调度由单 worker 执行。

## 已验证与剩余范围

Host ASan/UBSan 覆盖逐字节与粘帧、256 KiB DATA、小 ring 背压、部分输出、延后信用回补、FIN/RST、四流容量、队列满恢复、迟到数据、窗口溢出、ID 耗尽、绝对期限、1000 次流槽复用及持续收发下双流信用和 DATA 公平性。可选上游测试在真实回环 TCP 上重建 100 个会话，每次两条流各执行 300001 字节的双向比较、PING 和双向 FIN；不把回环测试计为 C3 或 TLS 验收。

ESP-IDF v6.1 / ESP32-C3 的独立组件编译已通过。[同输入 C3 QEMU 容量复测](../operations/c3-yamux-stream-ring-capacity.md)已在 Base READY 和 64 KiB guest 存活时越过旧 mux 分配失败，真实 client 到达认证阶段；随后 OpenETH RX buffer 分配失败，尚未完成 Login/注册/Pong。完整 C3/FRPS 资源原型已组合 TLS、64 KiB AEAD 工作区、控制解析和本地 socket，仍须按当前存储版本完成业务并发、故障与资源验收；本核心的静态大小不等于完整客户端峰值，也不证明 100 次实板连接释放。
