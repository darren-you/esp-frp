# 协议核心测试

## 架构拓扑

```mermaid
flowchart LR
    cmake["根 CMake / CTest"] --> wire["frame_reader_test.c"]
    cmake --> mux["yamux_test.c"]
    cmake --> aead["aead_test.c：记录边界与认证"]
    cmake --> handshake["handshake_test.c：协商、顺序、资源清理"]
    wire --> lib["esp_frp C 静态库"]
    mux --> lib
    aead --> lib
    handshake --> lib
    cmake -->|"可选"| upstream["interop：固定 Go Yamux"]
    upstream <-->|"回环 TCP"| peer["yamux_peer.c"]
    peer --> lib
    cmake -->|"可选"| crypto["crypto-interop：官方 FRP / golib"]
    crypto <-->|"双向字节"| cp["aead_peer.c"]
    cp --> lib
    crypto <-->|"Hello/Login 与加密尾数据"| hp["handshake_peer.c"]
    hp --> lib
    cmake -->|"显式 Mbed TLS host"| tls["crypto-interop/tls.go：Go TLS"]
    tls <-->|"随机回环 TCP"| tp["tls_peer.c / tls_contract_test.c"]
    tp --> lib
    cmake --> dns["dns_test.c + 实际 dns_lwip.c"]
    dns --> stub["lwip-stub：仅 API 驱动"]
    cmake --> tcp["connect_test.c + 实际 connect.c"]
    tcp --> fixture["dns_fixture.c：仅回环测试结果"]
    tcp <-->|"真实 TCP"| socket["进程内回环服务端"]
    cmake -->|"完整 Mbed TLS host"| session["crypto-interop/session.go：官方 FRPS"]
    session <-->|"真实控制会话"| sp["session_peer.c"]
    sp --> lib
    session --> faults["session_fixture.go：官方 API 异常对端"]
    cmake --> work["crypto-interop/work.go / work_fixture.go"]
    work <-->|"双业务流及故障"| wp["work_peer.c"]
    wp --> lib
    wp --> fixture
    cmake --> client["client_peer.c / client_contract_test.c"]
    client --> worker["实际 client.c + 仅测试 POSIX 调度"]
    worker --> lib
    worker --> fixture
    session <-->|"真实重启与双流"| client
    dependency["esp-lwip/tests/zero-window：依赖独立回归"] --> sdk["显式实际 lwIP 源码"]
    sdk --> zero["双向零窗口、序号边界与回绕"]
```

默认需 C11、CMake >= 3.16、OpenSSL >=3.0 和 cJSON 1.7.19 开发库；在仓库根执行：

```bash
cmake -S . -B build -DBUILD_TESTING=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
cmake --build build
ctest --test-dir build --output-on-failure
```

[lwIP 零窗口回环回归](https://github.com/darren-you/esp-lwip/blob/master/tests/zero-window/README.md) 是单独的 SDK 缺陷复现入口，直接编译显式提供的依赖源码，不混入 FRP host 通过结论。原始官方 SDK 会失败；[sdk-lock.json](../sdk-lock.json) 已锁定通过该回归的修正源依赖，不用预期失败规则将原始 SDK 标绿。SDK 身份与脏内容守卫使用 `python3 -m unittest discover -s tools/tests -p 'test_*.py'` 验证。

OpenSSL 不在系统路径时添加 `-DOPENSSL_ROOT_DIR=/absolute/path/to/openssl`；cJSON 不在系统路径时用 `-DCMAKE_PREFIX_PATH=/absolute/path/to/cjson`。ESP-IDF 构建固定使用 SDK PSA API 与 manifest 中精确锁定的 espressif/cjson，不使用 OpenSSL。

POSIX host 默认另外运行 `connect` 与 `dns_adapter`，需要系统线程库。前者使用真实 socket 与仅测试 DNS 结果；后者直接编译实际 lwIP 适配代码，使用 API fixture 驱动 SDK 回调次序。正常 host 库不包含这些 fixture 或 SDK 连接层。DNS 竞争可单独用 ThreadSanitizer 验证：

```bash
cc -std=c11 -Wall -Wextra -Werror -g -fsanitize=thread \
  -Iinclude -Isrc -Itests/lwip-stub \
  src/dns_lwip.c tests/dns_test.c -pthread -o /tmp/esp-frp-dns-tsan
/tmp/esp-frp-dns-tsan
```

ASan 与 TSan 需分别构建。上述驱动验证所有权及竞争，不计作真实 SDK DNS 网络或 C3 调度验证，范围见 [连接生命周期](../docs/design/connection-lifecycle.md)。

AES-256-GCM 和 Hello/Login 官方互操作需 Go >=1.25，添加 `-DEFRP_TEST_UPSTREAM_CRYPTO=ON`，分别运行 `aead_upstream` 和 `handshake_upstream`。测试直接调用官方 FRP v0.71.0 的握手、Token 鉴权与读写 API；两方向、64 KiB、多记录及拒绝范围见 [crypto-interop](crypto-interop/README.md)。可以同时打开两个上游测试选项。

生产 PSA 适配器也能在 host 运行相同 CTest。准备官方 [TF-PSA-Crypto 1.1.0 发布包](https://github.com/Mbed-TLS/TF-PSA-Crypto/releases/tag/tf-psa-crypto-1.1.0)，使用完整 `tf-psa-crypto-1.1.0.tar.bz2`（SHA-256 `a0b011b7f2c427cc8ee70116bb2d859543014534ae4d7020a69613aec10dc1b4`），解包后显式传入其根目录：

```bash
cmake -S . -B build-psa -DBUILD_TESTING=ON \
  -DEFRP_PSA_SOURCE_DIR=/absolute/path/to/tf-psa-crypto-1.1.0 \
  -DGEN_FILES=OFF -DEFRP_TEST_UPSTREAM_CRYPTO=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS"
cmake --build build-psa
ctest --test-dir build-psa --output-on-failure
```

显式 PSA host 模式不再链接 OpenSSL。发布包包含生成文件，`GEN_FILES=OFF` 避免把上游代码生成工具引为本项目依赖。不要把 Espressif SDK 内经移植的 TF 子树当作独立官方 host 包；它依赖 SDK 的头文件与配置，生产芯片适配只由 IDF 编译验证。上面两个构建目录选择不同密码后端，用于交叉验证。

严格 TLS 测试使用官方 [Mbed TLS 4.1.0 完整发布包](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.1.0)，文件 `mbedtls-4.1.0.tar.bz2` 的 SHA-256 为 `377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10`。包内自带 TF-PSA-Crypto 1.1.0，不得同时设置 `EFRP_PSA_SOURCE_DIR`。需 POSIX 与 Go >=1.25：

```bash
cmake -S . -B build-tls -DBUILD_TESTING=ON \
  -DEFRP_MBEDTLS_SOURCE_DIR=/absolute/path/to/mbedtls-4.1.0 \
  -DGEN_FILES=OFF -DEFRP_TEST_UPSTREAM_CRYPTO=ON -DEFRP_TEST_UPSTREAM_YAMUX=ON \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -DMBEDTLS_PLATFORM_MEMORY -DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS"
cmake --build build-tls
ctest --test-dir build-tls --output-on-failure
```

该模式自动增加 `tls_upstream`，由 Go 标准 TLS 服务端生成临时 CA/证书并启动 C peer；包含 TLS 1.2/1.3、四类证书拒绝、部分 I/O、100 次连接、取消和期限。`MBEDTLS_PLATFORM_MEMORY` 仅为 host 分配失败注入；未开启时不执行分配注入段，其余合同测试仍执行。PSA 的独占输入模式与 SDK 对齐。TLS 测试总期限 180 秒，证书输入和监听均在测试内清理，详见 [TLS 合同](../docs/design/tls-transport.md)。

完整 Mbed TLS 模式也增加 `session_upstream`，总期限 240 秒。它在本机启动实际官方 FRPS，验证百次注册、Token 心跳、工作请求、部分 I/O、拒绝和取消；另外以官方协议 API 构造 17 种尾数据、解析、认证、EOF 和超时场景。所有配置使用公开 fixture，监听仅回环，子进程和临时证书结束后清理；范围见 [控制会话](../docs/design/control-session.md)。

同一模式的 `work_upstream` 用实际 FRPS 验证 100 轮双业务流，共 200 条本地连接，每流双向各 300001 字节；总期限 240 秒。`work_faults_upstream` 总期限 180 秒，包含四个真实 FRPS 拒绝/取消场景和 12 个官方 API 半关闭、尾数据、解析、期限与慢流场景。连接目标是独立回环业务 listener；正常结束与取消均检查 fd 基线，详情见 [工作流](../docs/design/work-streams.md)。

可选互操作需 macOS/Linux 与 Go >= 1.23；`tests/interop/go.mod` 和 `go.sum` 固定 FRP v0.71.0 的实际 Yamux replacement。首次运行可能下载该公开依赖，不读取生产配置或相邻源码：

```bash
cmake -S . -B build -DBUILD_TESTING=ON -DEFRP_TEST_UPSTREAM_YAMUX=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Go 测试启动随机回环 TCP 端口和本仓构建的 C peer，结束时回收进程、连接与监听；CTest 有 120 秒总期限。上游测试验证其实际 6 MiB 最大窗口配置与本核心 4 KiB ring 的互操作。该测试没有 TLS、FRP wire 登录或真实 MCU；边界和验收范围见 [Yamux 核心](../docs/design/yamux-core.md)。

完整 Mbed TLS 模式另外运行 `client_upstream`（240 秒）和 `client_contract`。前者使用实际 `client.c`、POSIX 测试调度和实际 FRPS，验证百次创建/注册/停止/销毁、同实例重复 start、双向业务和活动双流取消、真实 FRPS 重启恢复，以及 DNS 迟到、退避、取消、并发调用、回调收敛和信任/认证终止；后者检查配置边界、三个 host 创建分配点失败及配置清零。长退避阶梯通过仅测试单调时钟推进，实际 FRPS 恢复使用真实时钟。测试解析器不发送真实 DNS 查询，pthread 不能代替 FreeRTOS 的实机资源证明。

可以把完整 Mbed TLS 命令中的 `-fsanitize=address,undefined` 替换为 `-fsanitize=thread`，在独立构建目录运行 `ctest --test-dir <目录> -R '^client_' --output-on-failure`，检查 worker、外部 API、状态副本与迟到测试 DNS 的竞争。不可同时开启 TSan 和 ASan。停止和线程退出检查见[客户端生命周期](../docs/design/client-lifecycle.md)。

`session_peer` 将实际 `session.c` 的 allocator 单独替换为测试计数器，TLS、密码与对端保持真实。首轮分别注入对象、完整 AEAD 接收区和 Yamux 分配失败，再验证握手配置拒绝回滚；每次正常/失败会话销毁均检查三块内存已清零且无残留。
