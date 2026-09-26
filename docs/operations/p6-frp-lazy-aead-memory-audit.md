# P6-03：控制 AEAD 逐块分配与总内存审计

2026-09-27 基于公开 `esp-frp@36e1506` 审计 FRP 接收完整 64 KiB 控制记录时的内存所有权。该提交已把单笔 65,552 字节连续申请改为最多 16 笔 4 KiB 申请；本轮只改动这些块的**申请时机**：验证长度头后，每个密文块的首字节实际抵达时才申请对应块。记录格式、64 KiB 明文上限、完整 GCM tag 认证后才交付和失败清零语义不变。

## 已确认的分配路径

| 时点 | 持有者与申请 | 释放点 |
| --- | --- | --- |
| 客户端创建 | `client.c` 深拷贝 CA，`client_port_idf.c` 建立 6 KiB worker 栈及同步资源 | `efrp_destroy` 在 worker 退出后释放 |
| TLS 创建与 OPEN | `tls_mbedtls.c` 为 TLS 对象、解析后 CA、Mbed TLS 会话及其内部记录缓冲持有堆；解析用 PEM 临时副本在 `mbedtls_x509_crt_parse` 返回后即释放 | TLS 失败、关闭或 destroy 释放 SDK 会话和 CA |
| 会话登录 | 固定 C3 编译尺寸：`session.c` 会话对象 17,848 字节、Yamux 5,552 字节、握手借用区 4,096 字节，三笔合计 27,496 字节，未计 allocator 元数据与 TLS | `finish_login` 清零释放握手区；会话失败或 destroy 释放其余两笔 |
| 登录之后 | 会话对象与 Yamux 至少仍占 23,400 字节。会话对象内的握手对象与认证控制区共用 union；四条 Yamux ring、三条工作流的收发缓冲、transport/control 分层暂存及 264 字节 AEAD reader 均包含在上述固定尺寸内 | 工作槽完成后清零复用；会话终止后清零释放 |
| 控制记录接收 | reader 内有 16 字节 tag。每个明文密文块实际到达时申请一笔最多 4,096 字节，末笔按剩余明文长度申请；满 64 KiB 记录认证前同时持有 **65,536 字节**。PSA 解密另使用 512 字节输入、编译上界不超过 1,024 字节的输出和密码库状态 | 认证成功后按消费进度清零释放；坏 tag、申请失败、取消或销毁清零释放所有已申请块 |
| 控制帧解析与工作流 | 认证后 JSON 解析会有 cJSON 临时堆分配；首次收到 StartWorkConn 数据时另按需申请共用 4 KiB JSON 区，本地连接对象/Socket 也可能存在 | 解析返回后清理 cJSON；工作握手结束、失败或取消时释放共用区；Socket 清理由工作流收敛 |

`session.c` 的 1 KiB transport、control 接收及发送暂存各自承担部分 TLS、Yamux、AEAD 和 wire 输入输出的背压与尾数据所有权；`yamux.c` 的四条 ring 和输出暂存承担流信用与传输确认。它们在同一时刻可能保留不同字节，当前没有证据证明可直接别名复用。会话握手/控制的较大静态区已经通过 union 复用，握手借用的 4 KiB 区也在 AEAD 开始前释放。

## 为什么第 15 块失败

[前次固定五组件 QEMU 切片](https://github.com/esp-space/esp-container/blob/8eb805f3f12cb3cd836e9833acb4aca878ae80e7/docs/operations/five-component-qemu-capacity-probe.md)在 Base READY、64 KiB guest 存活、**未创建 FRP 会话与 TLS**时，8-bit free／最大连续块为 66,588／45,056 字节。旧分块 reader 读完合法长度头后预申请全部块；14 笔共 57,344 字节成功后，free 为 9,188 字节但最大连续块仅 3,584 字节，第 15 笔 4,096 字节因此返回 `EFRP_NO_MEMORY`。reader 把先前 14 块清零释放，free 回到进入前。单看总 free，满长明文本体就需 65,536 字节，剩余 1,052 字节尚未支付 16 笔 allocator 元数据、会话/TLS/网络及密码库费用，仍不具备并发预算。

[当前精确五仓完整 wire QEMU 切片](https://github.com/esp-space/esp-container/blob/f07e50feca346194b58351593167e32f37798515/docs/operations/five-component-qemu-capacity-probe.md)在 guest 存活时报告 65,480／45,056 字节；即使忽略所有其它费用，free 已比明文本体少 56 字节。该切片两次完整 4 KiB 测试记录均已认证并核对，满 64 KiB wire 在第 15 块申请处失败、未进入认证。两轮数字属于无真实 FRP 会话、无网络流量的软件原型，不能外推实板峰值。若本轮逐块申请后只投喂 nonce 和长度头，reader 将正确地报告**零块申请**；该结果不再能用来判断完整记录容量。必须投喂真实密文与 tag、完成 GCM 认证并逐字节核对交付，才能判定满长路径。

## 本轮局部修正与边界

`src/aead.c` 原来在合法 4 字节长度头解析完毕时，为宣称的明文长度立即申请全部块，即使对端尚未发出密文。现在第一字节进入某块时才申请该块；一个只有长度头的连接不占满 64 KiB，部分记录只占已抵达块。申请失败返回已消费的精确输入前缀，并保持原有粘性失败、已持有块清零释放和密钥清零；坏 tag 仍不会交付明文。

此修正**不降低完整记录的 65,536 字节峰值**，也不使 Base READY + 64 KiB guest + 64 KiB FRP 记录在 C3 上通过。若产品确需三者严格同时存活，必须从真实组合运行预算与需求时序裁决，而不能把只收到记录头、改小 FRP 官方上限、跳过 tag 认证或将未经认证的字节交给业务当作通过。当前没有引入 Flash 暂存、全局缓冲或协议降级。

## 验证

`tests/aead_test.c` 在同一公开 PSA 后端验证：合法完整长度头零申请、密文首字节逐块申请、完整 64 KiB 记录 16 块且认证后才交付、16 个任意分配失败点各自清零回收、坏 tag 粘性拒绝、末字节截断取消回收。主机使用官方 Mbed TLS 4.1.0 内含 TF-PSA-Crypto 1.1.0 与 AppleClang ASan/UBSan；官方 FRP v0.71.0 互操作及完整会话用真实后端。`ctest --output-on-failure` **19/19 通过，297.47 秒**，其中 `session_upstream`、`work_upstream`、`client_upstream`、`aead_upstream` 及双 target 握手互操作均通过；`git diff --check` 通过。

构建使用 `-DEFRP_MBEDTLS_SOURCE_DIR=/absolute/path/to/mbedtls-4.1.0 -DGEN_FILES=OFF -DEFRP_TEST_UPSTREAM_CRYPTO=ON -DEFRP_TEST_UPSTREAM_YAMUX=ON`，C flags 为 `-fsanitize=address,undefined -fno-omit-frame-pointer -g -DMBEDTLS_PLATFORM_MEMORY -DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS`。软件验证无法代替固定 IDF 的 C3 编译、运行态容量及实板安全验收；本轮没有连接或写入设备。
