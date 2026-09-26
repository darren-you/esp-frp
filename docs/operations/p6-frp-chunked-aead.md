# P6-03：FRP C3 控制 AEAD 连续内存检查点

2026-09-26，基于独立分支 `codex/frp-dual-target@a7e9f7c` 实现并验证本轮未并入 Base 的 FRP 变更。输入是 [五组件 ABI 2 QEMU 切片](../../../esp-container/docs/operations/five-component-qemu-capacity-probe.md)：Base READY 后第二次 64 KiB guest 存活时，8-bit free 为 66588 字节，最大连续块为 **45056** 字节，FRP/MQTT/OTA 仅深链接、FRP 会话数为零。旧 `efrp_session_create` 在此之前即申请 65552 字节连续 AEAD 区，比该最大块多 **20496** 字节，确定无法在这个时点完成该笔申请。

## 本轮存储合同

- 会话创建时申请会话对象、4096 字节握手接收区和 Yamux。LoginResp 完成后复制密钥与 run ID，销毁握手并清零释放 4096 字节借用区；握手后的控制区继续复用会话内互斥存储。
- AEAD reader 在 4 字节长度头合法且计数允许后才申请块。明文长度为 `密文加 tag 长度 - 16`；按实际长度申请最多 `ceil(65536 / 4096) = 16` 个块，每块最多 4096 字节，末块不补齐。16 字节 tag 存于 reader；零明文记录不申请块。原调用方提供连续 65552 字节区的接口仍可用。
- PSA 与 host OpenSSL 都对这些私有块做完整 AES-256-GCM 验证。PSA 继续使用不重叠的 512 字节输入及有界输出；块内可能暂存尚未认证的解密结果，但 `plaintext` 在完整 tag 验证成功前只返回 `WOULD_BLOCK`。AAD、nonce、方向密钥、64 KiB 明文上限及失败原因均未改变。
- 已消费块立即清零释放；tag、认证或分配失败清零释放全部已申请块并清除 reader 密钥，错误保持粘性；会话取消/销毁也清零释放未消费块。握手临时区在成功切换、失败和销毁时清零释放。

## 可重现的软件验证

| 证据 | 结果 |
| --- | --- |
| 官方 Mbed TLS 4.1.0 发布包 | SHA-256 `377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10`；内含 TF-PSA-Crypto 1.1.0 |
| 真实后端 host | AppleClang + ASan/UBSan + `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS`，完整 CTest **17/17**；含官方 FRPS `session_upstream`、百轮双流 `work_upstream`、官方 AEAD/握手及 TLS 互操作 |
| 分块专测 | 1/4096/4097/65535/65536 字节记录与逐字节、4096 字节拆包；最大合法记录确实为 16 块、合计 65536 字节，最大单笔 4096 字节；末字节 tag 篡改无明文交付，16 块全清零释放；记录截断销毁与第 8 块分配失败同样全清零释放 |
| 固定 SDK C3 编译 | `tools/sdk.py check` 通过；IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c` / lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`，空输入样例构建成功，镜像 125696 字节，SHA-256 `72295225444e121b5ced1d6f3bbcd0158abae1a2887e1093f5bca27754dad484` |
| 固定 SDK C3 编译尺寸 | 会话对象 **17848** 字节、其中 AEAD reader **264** 字节；Yamux **5552** 字节；握手临时区 **4096** 字节。三笔初始申请合计 **27496** 字节，不含 allocator 元数据、TLS、密码库及网络资源 |

Host 测试使用仓外解包的官方发布包，命令形态：

```bash
cmake -S . -B /absolute/path/to/build-tls -DBUILD_TESTING=ON \
  -DEFRP_MBEDTLS_SOURCE_DIR=/absolute/path/to/mbedtls-4.1.0 -DGEN_FILES=OFF \
  -DEFRP_TEST_UPSTREAM_CRYPTO=ON -DEFRP_TEST_UPSTREAM_YAMUX=ON \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g -DMBEDTLS_PLATFORM_MEMORY -DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS'
cmake --build /absolute/path/to/build-tls
ctest --test-dir /absolute/path/to/build-tls --output-on-failure
```

C3 在 `mac-work-1` 的仓外 `esp-frp` basename 副本使用上述固定 SDK、独立 build/sdkconfig 和公开 `inputs.example.h`。构建不连接串口、没有注入 Wi-Fi/Token，也没有刷写设备；空输入启动会在网络前拒绝。

## 容量判定边界

本轮只消除单次 65552 字节申请。满 64 KiB 记录仍需合计 65536 字节动态块；即使先不计会话对象、Yamux、TLS、MQTT、Container 与 allocator 元数据，也只比上述 QEMU guest 存活时的 66588 字节 free 少 1052 字节。该切片**没有运行 FRP 会话或网络流量**，因此不能据此宣称 FRP 与 guest 并发、Base/MQTT/OTA 峰值或 64 KiB 记录在同板可用。P6-03 保持未验收；下一次必须在同一候选镜像中启动真实 FRP/TLS 与 guest、采样 free/最大连续块/分配失败，并分别进行 C3 和 ESP32-D0WD-V3 的实板组合验证。没有缩减协议记录或 guest 限额。
