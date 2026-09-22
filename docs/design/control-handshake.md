# 控制流握手

`esp_frp_handshake.h` 实现固定 FRP v0.71.0 的 Hello/Login 交换。调用前必须已建立严格 TLS 和新的 Yamux 控制流；本层不验证证书、不创建 socket、worker 或计时器。当前完成协议核心与 host 官方交叉验证，完整客户端和实板尚未完成。

## 输入与字节顺序

init 深拷贝 Token 并构建全部输出，不保留配置指针。Token 非空、最多 1024 字节；hostname/user/client_id/previous_run_id 各最多 128 字节且为有效 UTF-8；时间为调用方提供的正 Unix 秒。主机、端口、证书及时间可信性由后续 transport owner 负责。

输出顺序是 magic、ClientHello、Login。Hello 声明 TCP、TLS、TCPMux、JSON 与唯一 `aes-256-gcm`，不广告 UDP；32 字节 client random 来自密码随机源。Login 使用产品身份 `esp-frp/0.1.0`、`esp-idf`、`riscv32`，pool_count 固定 0，允许提交上次 run ID。版本身份不冒充官方 frpc。

Token 鉴权按官方要求为 `hex_lower(MD5(Token || decimal(unix_seconds)))`；SDK/OpenSSL 实现 MD5，本仓只装配输入。它不替代外层严格 TLS 或后续控制 AEAD。时间直接以经过整数格式化的 JSON number 输出，不经过 double，host 验证覆盖 `INT64_MAX`。公开 `efrp_token_auth` 可由后续 heartbeat/work scope 装配调用；本轮未实现这些消息的 scope 状态。

ServerHello 必须先于 LoginResp，算法只能为已广告的 AES，message codec 必须为 JSON、UDP codec 必须为空，server random 必须为 32 字节的规范 Base64。ServerHello 非空 error 返回 NEGOTIATION_FAILED。LoginResp 必须为 wire message type 2，error 非空返回 LOGIN_REJECTED，成功必须有非空且不超过 128 字节的 run_id。服务端 version 可缺省，不用于放宽协议校验。

派生使用实际发送的 ClientHello 与收到的 ServerHello 原始 payload；不重新编码服务端 JSON。密钥仅在合法 LoginResp 后移交给调用方，登录拒绝会清除已派生密钥。

## 边界、错误与所有权

- 握手接收缓存固定使用调用方前 4096 字节；单条 Hello/LoginResp 超出该范围返回 CAPACITY_EXCEEDED。这是握手 JSON 上限，后续 AEAD 仍保留完整 65552 字节接收工作区。
- cJSON 调用前限制深度 8、结构标记数量 128 和有效 UTF-8；拒绝 BOM、编码 NUL、非法控制字符、重复键（含转义别名）、未知字段与额外尾部 JSON。字段按固定上游对象结构和类型校验。cJSON 分配失败与解析失败不能由该库 API 精确区分，接收端统一 fail closed 为 PROTOCOL_ERROR；构建输出失败为 CAPACITY_EXCEEDED。
- 所有对象先零初始化，单 owner 使用；输入、输出对象与借用缓存不得重叠。输出可分批消费，已消费部分立即清零；配置提交或网络执行不能从 write/consume 推断。
- 输出全部交给 transport 后才接收响应。`efrp_wire_feed_one` 在单帧边界停止，使握手在 LoginResp 后立即退出；feed 返回消费的精确前缀。调用方必须保留剩余字节，同次读取可能已经包含控制 AEAD 的 nonce 和首记录。
- owner 在每次 I/O 驱动前调用 tick，采用单调毫秒时钟；从 init 起 10 秒的绝对期限不随部分进展延长。回退时钟被拒绝。未完成握手时 EOF 始终失败，即便恰在 ServerHello 结束处。
- 非参数类协议/密码/期限错误为粘性错误，清除 Token、方向密钥、输出和接收缓存；销毁后才能重新初始化。外层必须关闭失败连接。
- `take_result` 只允许一次，复制密钥/run ID 后清零并归还借用缓存，解除 frame reader 引用；之后 destroy 不再写该缓存。调用方可立即将它重新用于 AEAD。调用方创建 AEAD 对象后清除临时密钥。

本次 C3 编译中的握手对象为 5968 字节，另需 4096 字节借用接收区；cJSON 和密码库有临时分配。这不是完整客户端的峰值或连续块结论。握手 DONE 仅表示语义交换完成；完整客户端还需通过控制 AEAD、代理注册和运行状态才能报告 ready。

## 验证

`handshake_test` 覆盖每个拆分步长、每个 EOF 截断点、粘连的 AEAD 尾部、重复/错序消息、JSON 负例、期限、参数界限和清零；逐个拒绝 cJSON 分配并计数确认中间对象全部释放。生产代码不更改全局 cJSON allocator。

可选 `handshake_upstream` 直接用官方 FRP 解码 C 客户端的 Hello/Login，并用 `TokenAuth.VerifyLogin` 校验；官方生成 ServerHello/LoginResp，紧接第一条 AEAD Pong，C 解密并回写后由官方解密/解析。两个后端各通过 9 组正例（含八种输入分块与大整数时间戳）、6 组拒绝（算法、随机数长度、登录拒绝、握手摘要变化、错误 AEAD 密钥和截断）。它没有运行完整 FRPS listener、TLS、Yamux 组合或 MCU；完整实板矩阵继续待做。

来源：[官方登录交换](https://github.com/fatedier/frp/blob/v0.71.0/client/control_session.go)、[Token](https://github.com/fatedier/frp/blob/v0.71.0/pkg/auth/token.go)、[消息定义](https://github.com/fatedier/frp/blob/v0.71.0/pkg/msg/msg.go)。
