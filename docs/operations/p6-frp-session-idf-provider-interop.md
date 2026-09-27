# FRP 会话与 IDF Flash provider 集成回归

2026-09-27。此前完整 Mbed TLS host 的官方 FRPS 会话使用 `flash_store_fixture.c` 假存储；C3 QEMU MTD 探针直接调用正式 IDF provider 和 Flash reader，未执行会话。此回归将正式 `src/session.c`、`src/aead_flash.c`、`src/idf_flash_store.c` 接成同一路径。设备分区函数由 `tests/session_idf_flash_fixture.c` 提供 host shim，维持真实 Flash 的先擦后写、位只能从 1 变 0、范围和 owner 独占约束。正式 provider 的分区校验、`recover`、lease、写后回读、reader 认证及 session 状态均未替换。

`session_idf_flash_upstream` 在随机本机回环端口运行官方 FRPS v0.71.0、正式 Mbed TLS 客户端及三个连续控制会话，随后运行三种官方协议 API fixture：

1. 64 KiB 合法 AEAD 记录含一个 NewProxyResp 和多个有界 ReqWorkConn，session 处理全部 16 个 4 KiB 明文窗口并有界拒绝超额请求；测试要求 scratch 完整擦除两次（boot recover、begin）、写入 65,536 字节、至少读取 `18 × 65,536` 字节（写回读一次、初次认证一次、16 次窗口复验）。
2. 同样 64 KiB 记录只篡改最终 GCM tag。session 必须返回 `EFRP_AUTHENTICATION_FAILED`，工作请求与拒绝计数均为零；正式 provider 已写入密文，但销毁后 lease 和 owner 必须释放。
3. 小记录坏 tag 拒绝，不允许访问 scratch；每轮启动只发生一次 recover 擦除。

每个子进程都从模拟旧密文开始，重新 bind 正式 provider、调用 `efrp_aead_flash_store_recover`，执行测试后核对 `active_lease == 0`、状态 IDLE、owner claim/release 次数相同。正式 session 的对象分配/清零检查与原 `session_upstream` 共用，`session_peer.c` 只通过编译选项选择测试后端。回归使用公开合成 Token、临时 CA 和随机回环端口，不读取真实配置或设备凭据。

复现（依赖准备见[测试入口](../../tests/README.md)）：

```bash
cmake -S . -B build-tls -DBUILD_TESTING=ON \
  -DEFRP_MBEDTLS_SOURCE_DIR=/absolute/path/to/mbedtls-4.1.0 \
  -DEFRP_TEST_UPSTREAM_CRYPTO=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -DMBEDTLS_PLATFORM_MEMORY -DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS"
cmake --build build-tls --target session_idf_flash_peer session_peer
ctest --test-dir build-tls -R '^session_(idf_flash_)?upstream$' --output-on-failure
```

本轮 mac-ci-1 使用 AppleClang 21、Mbed TLS 4.1.0、ASan/UBSan 构建，新增 `session_idf_flash_upstream` **1/1 通过**，原 `session_upstream` **1/1 通过**。三轮官方 FRPS 均只有 boot recover 擦除 65,536 字节，没有 scratch 写入。满长正确记录：擦除 131,072、写入 65,536、读取 **1,179,648** 字节（`18 × 65,536`），owner claim/release **2245/2245**；满长坏 tag：擦除 131,072、写入 65,536、读取 **131,072** 字节，owner **197/197**；小记录坏 tag：仅启动擦除，零写入、零读取。三种模式结束时均无活动 lease，ASan/UBSan 没有报错。

此项验证把 host 官方协议和正式 provider 的接口接在一起，属于集成合同测试。假分区没有 ESP 的物理 MTD 时序、掉电故障点或真实 storage owner；C3 QEMU 的 MTD 字节实验另见[运行记录](p6-c3-flash-scratch-qemu.md)。两项合起来仍不能替代 Base 候选分区 `0x3e6000`、OTA owner 并发、ESP32/C3 实板、真实 Flash 延迟/磨损或完整产品容量验收。
