# 严格 TLS 传输

`esp_frp_tls.h` 是基于 ESP-IDF Mbed TLS 的单 owner 非阻塞引擎。它负责 TLS 握手、认证加解密、写入队列、期限与释放；外层提供已连接的 transport 和非阻塞 send/recv 回调。host 已接入 [TCP 连接层](connection-lifecycle.md) 验证；完整 IDF worker、Yamux 与 FRP 控制会话尚未装配，host 互操作不能计作完整 FRPC 或实板验收。

## SDK 与信任

- 芯片固定验证 ESP-IDF v6.1 / ESP32-C3，使用 SDK Mbed TLS 4.1.0 与 PSA。host 对应测试使用官方完整 Mbed TLS 4.1.0 发布包，芯片移植与 host 源码分别构建。密码原语和证书解析由 SDK 提供，本仓不实现 TLS 协议栈。
- 必须显式提供 CA PEM（1–16384 字节，不含结尾 NUL）与预期主机身份（1–253 字节 ASCII）。CA 解析任何非零返回均拒绝，包括只成功解析部分证书的 bundle；输入在 create 返回后不再借用。主机名同时交给证书身份校验和 SNI。
- 固定 `VERIFY_REQUIRED`，最低 TLS 1.2；SDK 启用 TLS 1.3 时允许协商 1.3 的证书认证临时密钥模式。禁用会话票据与重协商，不提供跳过校验、明文回退或备用目标。
- 必须启用 `CONFIG_MBEDTLS_HAVE_TIME_DATE=y`，并保留 `CONFIG_MBEDTLS_HAVE_TIME`、SNI 和 TLS 1.2；缺失会直接编译失败。SDK 默认没有启用证书日期校验，调用方工程必须明确设置。
- create 要求 owner 声明实际系统墙钟已同步，且系统时间不早于 2024-01-01；该下限只是误配置检查，不能证明时间来源可信。证书有效期由 Mbed TLS 使用真实系统墙钟检查。owner 仍负责同步及信任状态，TLS 引擎不启动 SNTP。
- 使用标准 TLS ClientHello，不发送 FRP 旧式自定义首字节；官方 v0.71.0 服务端支持标准 TLS 入口。上层 Token 与控制 AEAD 必须继续按 wire v2 执行，外层 TLS 不替代它们。

## 所有权、背压与期限

create 初始化 PSA、解析 CA、创建 SDK TLS 对象，但不执行网络 I/O。SDK 分配可能失败，成功后返回句柄；调用方传入的输出句柄必须为空。唯一 owner 顺序调用所有 API，回调不得重入。引擎不创建 DNS 请求、socket、任务或定时器，也不关闭外层持有的 socket。

`step` 每次最多推进一次 SDK 握手、发送或关闭操作。`WOULD_BLOCK` 配合 `want` 告诉 owner 等待读/写就绪；`WANT_NONE` 表示内部推进，可以再次调度。回调必须为真正非阻塞 I/O，`OK` 只能报告 1..请求长度字节，`WOULD_BLOCK` 和接收 EOF 必须报告零；越界、空成功或发送 EOF 会使会话永久失败。该接口不保证密码计算的硬实时执行上限。

write 把最多 4096 字节复制到自有队列，调用方可立即复用输入；accepted 只代表入队。owner 必须调用 step 排空。Mbed TLS 的 WANT 重试始终使用相同指针与长度；只有 SDK 确认发送后才清零并移动偏移。队列非空时拒绝新写入并对 read 返回背压，外层负责公平调度及完整双向转发验收。

所有期限使用 owner 传入的单调毫秒，拒绝倒退和加法溢出：握手从 create 起 10 秒；每次写入从入队起 5 秒；close 从首次请求起 5 秒，不因局部进度延长。close 先排空已入队数据再发送 close_notify；它不等待对方通知。无待发送数据的 OPEN 状态没有独立空闲计时器，后续 worker/Yamux 负责连接活性；owner 必须持续调用 API 才能裁决期限。

cancel、失败或正常关闭立即释放 SDK 会话/配置/证书并清零待发明文、解除回调借用；句柄及诊断留到 destroy。之后不再调用 transport，owner 应关闭 socket 并最终 destroy。收到 close_notify 返回 EOF；无通知的 TCP EOF 返回 TRUNCATED；网络错误、信任错误、TLS 错误、超时和取消分别报告。终止会话不可重新使用。生产代码只初始化共享 PSA，不全局销毁它，以免影响 MQTT 等消费者。

## 已验证范围

测试命令见 [tests/README.md](../../tests/README.md)，使用公开临时 CA、随机回环端口与 Go 标准 TLS 服务端，不读取生产凭据：

- TLS 1.3 的 100 次真实连接、TLS 1.2 一次、强制部分读写一次。每次接收 70001 字节（含完整大小 TLS record），再发送并回显 200001 字节，逐字节比较；每次关闭外层 fd 并检查不可复用。
- split 用例把发送/接收分别限制为 17/19 字节，并交替模拟 WOULD_BLOCK；入队后覆盖调用方缓冲，确认队列拥有原字节。
- 错误 CA、错误主机名、过期、尚未生效的证书全部拒绝，并保留证书错误位。覆盖握手取消/绝对期限、阻塞写入取消/期限、关闭期限、正常关闭与裸 TCP EOF。
- 参数、未可信时间、部分无效 CA bundle、时钟倒退/溢出、回调违规和 100 次握手前取消。host 显式启用 SDK allocator hook 后，在 create 的每个分配位置注入失败，释放会话并清理该隔离测试进程的 PSA 后核对剩余分配为零；这不等于 MCU 全生命周期资源证明。
- ASan/UBSan 与独立 C3 编译；未启用日期校验的负向构建确实由编译守卫拒绝。编译探针使用默认分区，只用于链接验证，不是本板可刷制品。

尚未验证 MCU 握手动态峰值、全部分配失败阶段、联合 AEAD 的内存与栈、完整 TLS/Yamux/FRPS 双流、DNS/连接取消及 72 小时长稳。上述缺项必须在后续真实集成中完成。
