# wire v2 控制 AEAD 记录层

本层实现官方 FRP v0.71.0 的 `aes-256-gcm` 控制通道保护。`src/aead.c` 提供密钥派生与发送端，`src/aead_flash.c` 是控制会话唯一接收端；ESP-IDF 构建调用 `crypto_psa.c`，host 默认调用 `crypto_openssl.c`。不自研 AES、GCM、SHA-256、HKDF 或随机数。

## 握手与密钥

会话层先验证 ServerHello 成功、选择的算法已被广告且恰为 `aes-256-gcm`、随机数长度，以及 LoginResp。随后把**实际发送和收到的原始 Hello payload**交给 `efrp_aead_derive`，不能重新序列化 JSON。当前 derive 仅检查输入边界，不承担 JSON 或协商验证；Token 必须非空且不超过 1024 字节，两个 Hello 各为 1–65536 字节。

摘要为 SHA256：固定 ASCII `frp wire v2 crypto transcript`，之后按客户端、服务端顺序拼接 `0x00 + 标签 + 0x00 + uint64be(payload 长度) + payload`；标签分别是 `client hello` 和 `server hello`。HKDF-SHA256 的 IKM 是原始 Token，salt 是上述摘要，32 字节输出的 info 分别为：

- `frp wire v2 control aead aes-256-gcm client-to-server`
- `frp wire v2 control aead aes-256-gcm server-to-client`

客户端读密钥为 server-to-client，写密钥为 client-to-server。调用方在构造 reader/writer 后立即清除临时 `efrp_aead_keys_t`；对象在失败或 destroy 时清除自己的密钥。

## 记录格式与失败语义

每个方向先发送 12 字节随机 stream nonce，然后重复 `uint32be(ciphertext + tag 长度) + ciphertext + 16 字节 GCM tag`。每条记录的 AAD 是不变的 stream nonce 加该记录的四字节长度头；记录 nonce 从 stream nonce 开始按 96 位大端递增。

- 单条明文最多 65536 字节；接收端允许认证有效的空记录。发送端的空 write 不产生记录或输出。
- 完整记录认证成功后才由 `plaintext` 暴露。认证失败清空接收窗口、tag 与密钥；长度非法、计数耗尽、存储失败、密码库失败均为粘性错误，必须关闭 reader 并重建会话。
- nonce 不允许回绕；全 `ff` 的 nonce 对应记录不交付。每方向最多 2^32 条记录；每次会话必须重新生成 Hello 随机数及方向密钥。
- nonce、密文、tag、合法范围内长度头或握手原文被修改均不能通过认证；重放、乱序和方向反射也不能通过。
- EOF 只检查 nonce/长度头/记录体是否截断。空流、恰好 nonce 或完整记录边界的 EOF **没有被认证**，不能据此判定业务或会话成功。

不完整记录的时间限制由 transport/会话 owner 负责；本层无时钟、socket 或任务。外层严格 TLS 不替代控制 AEAD。work stream 不重复控制 Hello/AEAD。

## 内存与 API 所有权

所有公开对象先零初始化，单 owner 使用，成功关闭后才可重新 init。调用方缓冲区必须独占，且不得与输入或对象存储重叠；不能直接读取内部工作区推断明文是否可信。

| 资源 | 合同 |
| --- | --- |
| FRP 会话接收窗口 | 会话独占 4096 字节，与 wire parser 借用的 `json_rx` 分离；小记录在窗口中认证，大记录将密文写入独占 65536 字节 Flash scratch。大记录完成认证后，每次交付前重新读回并复验整条密文；已消费窗口立即清零 |
| 发送缓存 | 33–65568 字节；4128 字节缓存每次最多接收 4096 字节明文 |
| Flash reader 对象 | C3 静态大小 248 字节；另由会话提供 4096 字节窗口，不含密码库临时内存或产品 provider 状态 |
| PSA 单次工作块 | 512 字节输入和 SDK 上界输出，输出编译约束不超过 1024 字节；另有操作状态和 tag |
| 密码库资源 | SDK 可内部动态分配；每记录导入 volatile AES key，最终 abort operation 并 destroy key |

`feed` / `write` 返回消费的前缀长度；剩余输入由调用方保留。存在未消费明文时 feed 返回 WOULD_BLOCK；存在未消费输出时非空 write 返回 WOULD_BLOCK。消费可以分批，已消费数据立即清零；返回 OK 或消费数量不代表 transport 已发出或对端已执行。

Flash scratch 的 lease、启动恢复、失败隔离与重试见 [Flash 暂存 reader](flash-backed-aead.md)。本候选尚未接入真实设备分区，不能据 host 软件测试推断设备容量通过。

IDF 的 `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS` 不保证重叠缓冲有效。适配器通过 multipart AEAD 的独立输入/输出小块运行，检查输出边界后将认证后的窗口交付。Flash 路径在每个窗口交付前重新认证并检查首次密文摘要；不会分配一份完整 64 KiB 明文。存储形状不改变官方记录长度、AAD、nonce 或认证条件。

## 验证与剩余工作

host 回归覆盖逐字节/边界拆分、部分读写、64 KiB 与多记录、空记录、篡改/错误密钥/重放、截断、计数边界、lease 争用和清理失败重试。可选测试直接调用官方 FRP 的 `NewClientCryptoContext` 和 `NewAEADCryptoReadWriter`，覆盖两后端各 12 组双向用例、10 组拒绝用例；小发送缓存 33 字节、4128 字节和最大缓存均有交叉验证。具体入口见 [tests](../../tests/README.md)。

当前唯一接收路径已通过 OpenSSL、独立 PSA 与 Mbed TLS host 互操作；固定 ESP-IDF 双目标空输入 sample 已编译、分区表与 app size 已由官方工具核对。真实设备 Flash/PSA、掉电和 Base 产品容量尚待验证。

协议依据：[FRP crypto](https://github.com/fatedier/frp/blob/v0.71.0/pkg/proto/wire/crypto.go)、[FRP 方向密钥装配](https://github.com/fatedier/frp/blob/v0.71.0/pkg/util/net/conn.go)、[golib AEAD](https://github.com/fatedier/golib/blob/v0.8.2/crypto/aead_stream.go)。
