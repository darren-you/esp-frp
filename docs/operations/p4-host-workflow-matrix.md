# P4-04 主机工作流矩阵（2026-09-23）

## 验证对象与结论

本轮只验证公开 `master` 候选提交 `dd9d52ae183c0db069ba302cf850b620f61800fb`（tree `22c2a8dce28c8b566eb031f62d2c0df4a0831627`）。运行前后 `git status --porcelain` 均为空。一次全新构建运行完整 Mbed TLS/官方 FRP host CTest，17/17 通过，总耗时 180.39 秒；所有下表场景使用同一源码提交。此次未修改 FRP 实现或测试判据。

这是 P4-04 的 host/local 软件证据。测试使用本机回环 TCP、官方 FRPS v0.71.0 和官方协议 API；没有刷写 C3，也没有获得同一候选在真实 Wi-Fi/lwIP/FreeRTOS 上的完整矩阵结果。P4-04 的实板验收继续保持进行中。

## 固定输入与复现

- 宿主：macOS arm64，Apple Clang 21.0.0，CMake 3.31.10，Go 1.26.1；cJSON 由 CMake `find_package(cJSON 1.7.19 EXACT CONFIG REQUIRED)` 从 `/opt/homebrew/lib/cmake/cJSON` 解析。
- Mbed TLS 4.1.0 完整发布包 `mbedtls-4.1.0.tar.bz2` SHA-256：`377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10`，含 TF-PSA-Crypto 1.1.0。Go 模块由仓内 `tests/crypto-interop/go.mod`、`go.sum` 锁定官方 FRP v0.71.0，运行时使用 `-mod=readonly`。
- 本轮从固定 SDK 的 `export.sh` 取得 CMake 等主机工具，`tools/sdk.py check` 已确认 IDF `fff9895c82d744c7237be8847347bdd1b07c6643` 与 lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`。host 回环测试不运行设备 SDK 网络调度。

在独立 checkout 中切到上述候选提交，准备经摘要校验并解包的 Mbed TLS 发布包，然后从仓库根执行：

```bash
source /absolute/path/to/locked-esp-idf/export.sh
python3 tools/sdk.py check --path /absolute/path/to/locked-esp-idf
cmake -S . -B /tmp/esp-frp-p4-04-host-dd9d52a -DBUILD_TESTING=ON \
  -DEFRP_MBEDTLS_SOURCE_DIR=/absolute/path/to/mbedtls-4.1.0 \
  -DGEN_FILES=OFF -DEFRP_TEST_UPSTREAM_CRYPTO=ON -DEFRP_TEST_UPSTREAM_YAMUX=ON \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g -DMBEDTLS_PLATFORM_MEMORY -DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS'
cmake --build /tmp/esp-frp-p4-04-host-dd9d52a --parallel 4
ctest --test-dir /tmp/esp-frp-p4-04-host-dd9d52a --output-on-failure --parallel 2 -V
```

本轮实际使用的 Mbed TLS 解包目录是 `/tmp/mbedtls-4.1.0`。详细本机输出位于 `/tmp/esp-frp-p4-04-ctest-dd9d52a.log`，SHA-256 为 `978cade24189dc210926458aa97ddfddf56cfe131671a34ab5afc96b6f4811b4`；该临时日志不作为公开仓的运行依赖。

## 同一候选的结果

| 范围 | 测试与实际断言 | 结果 |
| --- | --- | --- |
| 官方 FRPS 双流压力 | `work_upstream`：100 轮，每轮两条并发业务流，共 200 条固定目标本地 TCP 连接；每条流的两个方向各逐字节核对 300001 字节。工作状态 `completed=200`、`failed=0`、`peak=2`，结束后 fd 回到基线。 | 通过，160.17 秒 |
| 慢流背压与健康流 | `work_faults_upstream` 的 `work-stall`：对阻塞的慢流发起 32 MiB 写入并收到错误；第二流完成 64 字节回显。工作状态 `completed=1`、`failed=1`、`peak=2`，fd 回到基线。 | 通过 |
| 双向半关闭与尾数据 | `work-tail-fin`、`work-local-fin` 分别验证 StartWorkConn 后紧随业务、远端先 FIN 与本地先 FIN 后反向传输；各自 `completed=1`、`failed=0`，本地两个方向分别计数 300001 字节，fd 回到基线。真实 FRPS 的 Join 在任一方向 EOF 时会关闭双方，反向半关闭由官方协议 API fixture 验证。 | 通过 |
| RST、部分握手与容量 | 真实 FRPS 的 `local-rst`、`capacity`、`cancel-active`、`refused` 四项通过；`work-shared` 在旧活动流 RST 清理时保留新流部分握手及 300001 字节尾数据，状态 `completed=1`、`failed=1`，fd 回到基线。 | 通过 |
| 预备流与拒绝 | `work-spare` 在测试 owner 的单调时钟推进超过空闲期限后仍保持 `waiting=1`、`active=0`，恢复后完成双向 300001 字节；其余工作流 API fixture 的错误名称、服务端拒绝、超长/截断、非法端口/重复键、握手期限和空闲回收均通过。 | 通过 |
| 百次生命周期与多路复用 | `client_upstream`：100 次实际客户端创建/登录/停止/销毁及回调、owner、fd 清理，另有 worker 上三轮双流；`yamux_upstream`：100 次回环 TCP 会话、每次两条 300001 字节双向流及 FIN/PING。 | 通过 |
| 连接清理与整套回归 | `connect_linger` 验证暂时性 socket option/close 失败后仍持有并最终释放 fd；`session_upstream` 包含官方 FRPS 控制会话和 28 项协议 fixture。完整 CTest 17/17，无失败。 | 通过 |

预备流和活跃空闲的长期限在 host 测试中使用测试 owner 的单调时钟推进；慢读背压使用真实回环 I/O。该矩阵不能给出 ESP32-C3 的 heap、最大连续块、任务栈、socket/计时器资源或弱信号恢复结论。下一步仍需在获准设备上，以同一候选和固定 SDK 完成十轮双流、背压、FIN/RST、预备流、百次释放的统一实板矩阵，并按既有恢复基线收尾；Base/MQTT 组合另由 P4-05 验收。
