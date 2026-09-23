# DNS 与 TCP 建连生命周期

`esp_frp_connect.h` 负责一次 IPv4 DNS→TCP 连接尝试，向 TLS 提供非阻塞 send/recv 回调；`create_ipv4` 则复制明确的四字节地址，跳过 DNS，在 step 中连接固定本地目标。后者拒绝 0 与 >=224 的首字节、零端口。IDF 使用 SDK lwIP；每个句柄至多持有一个 DNS 请求与一个 socket，不创建附加任务、定时器、备用地址列表或重连器。已接入组合会话、工作流和单 worker。

## DNS 所有权与取消

create 深拷贝主机名，经 `tcpip_try_callback` 把解析请求交给现有 lwIP TCP/IP 任务，再在该任务调用 `dns_gethostbyname_addrtype(..., IPV4)`。返回 cached/IP 结果和异步回调走同一完成路径。主机名仅允许 ASCII DNS 标签，标签最长 63、整体最长 253 字节，可使用 IPv4 字面量；不自动改写目标、改地址族或轮询多个返回地址。

SDK 回调只把 IPv4/错误写进该请求，然后用 C11 release/acquire 原子标记发布完成；不调用应用、TLS 或 worker 回调，不保留调用方主机名指针。owner 看到完成标记后才能释放请求。取消标记可以在提交但尚未执行时阻止真正查询。

lwIP 没有撤销已发 DNS 查询的 API。查询已发时，取消和 10 秒 DNS 期限只终止逻辑连接尝试：状态进入 DRAINING，结果立即记录 CANCELLED/TIMEOUT，后续返回 WOULD_BLOCK，直到 SDK 成功/失败/自身超时回调收敛。迟到成功也不得打开 socket。destroy 在此期间返回 WOULD_BLOCK 且保留句柄；owner 继续 step，只有 destroy 返回 OK 才释放并把指针置空。未收敛前不能启动该实例的下一轮尝试。

因此应用 deadline 不等于 DNS 资源立即消失，也不承诺固定毫秒内 destroy 完成；收敛依赖 SDK TCP/IP 任务和 DNS timer 正常运行。每个实例始终保留至多一个请求，不用脱离 owner 的线程或泄漏 ticket 换取表面取消。后续 worker 的 stop 必须等待这条路径完成。

## TCP 与关闭

DNS 成功后释放请求，创建唯一 IPv4 TCP socket，固定 `O_NONBLOCK`、`TCP_NODELAY` 和取消关闭策略，再执行一次 connect。CONNECTING 使用零等待 select 和 SO_ERROR 确认结果；connect 返回 EINPROGRESS 或 fd 可写本身均不能证明连接成功。TCP 从创建尝试起有独立 10 秒绝对期限。调用时钟必须单调且无加法溢出。

原始 send/recv 允许部分进度、EAGAIN/EWOULDBLOCK/EINTR；接收 EOF 保留 socket，发送方向仍可用。网络错误进入清理；OPEN 状态不自行重连或设置业务空闲期限。fd 只在 OPEN 时借给 owner 做就绪等待，调用方不能关闭或修改 socket 选项。TLS 的入队/发送不是对端交付凭证，完整业务转发另行裁决。

取消和未完成的 destroy 使用取消关闭语义，不承诺排空或 FIN：在 connect **之前**固定 `SO_LINGER={1,0}`，避免在已拒绝连接上才设置选项而失败，也避免 lwIP 默认最长 20 秒的 FIN 分配重试等待。IDF 必须开启 `CONFIG_LWIP_SO_LINGER=y`，否则编译拒绝。

正常工作流先把该方向业务字节交给 send，再调用 `close_write` 发出 SHUT_WR，接收方向仍可使用；成功后拒绝新 send，重复 close_write 幂等。临时错误可重试。IDF 在半关闭前设置 5 秒正 linger；`finish` 仅在同时观察到接收 EOF 和成功的写半关闭后尝试关闭，复用已经设置的 linger。若尚有未确认的本地 TCP 尾数据，lwIP 非阻塞 close 返回 WOULD_BLOCK 并保留 fd，工作流在独立的 5 秒单调时钟窗口内重试。窗口到期转取消，工作流结果记为 TIMEOUT；这不等于远端业务已处理，也不承诺 5 秒时 fd 必然释放。

macOS 实测在两端均关闭后设置 SO_LINGER 会返回 EINVAL，因此 POSIX 在 SHUT_WR **之前**关闭 abortive linger；之后若发生错误/取消则尽力恢复 RST 设置并始终清理 fd，不因已失效选项持续等待。IDF 半关闭前设置正 linger，避免 finish 时重复设置选项遇到暂时性 mailbox 失败而丢弃尾数据；临时 ENOMEM/ENOBUFS 返回 WOULD_BLOCK 并保留 OPEN 状态供下轮重试。两平台使用各自正常关闭路径，SDK 内存压力下的实际时长仍待实板验证。

取消正 linger 时先尝试恢复零 linger。lwIP 的 `setsockopt` 或 close 若因 mailbox/内存暂时失败，每次调用只尝试一次，返回 WOULD_BLOCK，保留 fd 与句柄所有权；后续 step/destroy 重试，只有真实 close 成功才进入 CLOSED，destroy 才释放对象。状态中的 `system_error` 记录当次暂时失败，取消最终成功后清零。若底层持续拒绝操作，清理可超过正常排空窗口；不能通过释放仍持有 fd 的对象伪造完成。POSIX 测试侧不重复 close 可能已释放的 fd。SDK socket API 仍需 TCP/IP 任务调度，不把非阻塞网络 I/O 宣称为硬实时执行上限。

## 测试边界

- `dns_test.c` 直接编译真实 `dns_lwip.c`，以最小 API fixture 驱动提交失败、缓存命中、异步错误、IPv6/空地址拒绝、提交前取消和迟到结果；修改调用方输入后验证仍使用原主机名。1000 次 pthread 完成/取消竞争通过 ASan/UBSan 及单独 ThreadSanitizer，包含完成发布后先释放再 join。
- `connect_test.c` 对接真实回环 TCP：100 次双向二进制传输和 fd 释放，接收 EOF 后继续发送，另外覆盖真正发送背压、RST、拒绝连接、CONNECTING 取消/期限，以及 100 次 pending DNS 取消/期限。DNS 在该测试由确定性 fixture 提供；不得把它计作宿主或 MCU 的实际 DNS 网络验收。
- 新增 100 次固定 IPv4 连接，修改输入后仍使用原目标，不调用 DNS；接收 EOF 后写入多段二进制，在对端尚未读取应用数据时执行 close_write/finish，随后验证完整尾数据与正常 EOF。覆盖 finish 前置条件、重复半关闭、半关闭后 send 拒绝及 fd 释放。
- `connect_linger_test.c` 只在 host 编译连接层的 IDF linger 分支并注入暂时性选项/close 失败，验证半关闭重试、finish 不重复设置正 linger、取消在真实 close 前保留所有权，以及成功关闭后可销毁。它不模拟 SDK TCP/IP 任务调度、实际 TCP ACK 或实板清理时长。
- `tls_peer.c` 的 113 条 Go TLS 网络连接改用当前 TCP 连接层；拆分 I/O、证书拒绝、取消和期限继续验证。该链路包含真实 TCP/TLS，解析仍是仅测试回环 fixture。
- IDF v6.1 / C3 已验证缺少 SO_LINGER 的编译拒绝与启用后的链接；独立 C3 工作流已有实板场景。持续内存压力下的 `setsockopt` / close 失败与五秒窗口到期后的真实清理时长仍需实板验证，host 注入不能替代。

host 正常库不包含 SDK DNS/连接层，导出 `EFRP_HAS_CONNECT=0`；IDF 为 1。host 的 `connect_host_test`、linger 注入、DNS fixture 和 lwIP API fixture 只用于测试，不安装进公开库或固件，不提供生产目标回退。命令见 [测试入口](../../tests/README.md)。
