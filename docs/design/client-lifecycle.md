# 客户端生命周期

`esp_frp.h` 组合严格传输、Hello/Login、控制 AEAD 和固定目标工作流。TCP 使用 DNS/TCP、Mbed TLS 和 Yamux；显式 QUIC 使用 DNS/UDP 与原生 bidi，不叠 Yamux。provider 与独立 STCP/XTCP visitor 共用一个 worker；候选 XTCP 的 child peer 使用同一流接口。目标为固定 ESP-IDF v6.1 / ESP32-C3 与 ESP32-D0WD-V3；host 通过相同 `client.c` 和仅测试调度适配验证。独立 sample 位于 `examples/tcp-proxy`；真实 SDK DNS、FreeRTOS 调度与资源、实板 FRPS 和 Base/MQTT 组合仍须验收。

## 配置与所有权

create 复制服务主机、CA、Token、身份、代理名和唯一 IPv4/port 本地目标，不保留输入字节指针。CA 最大 16384 字节且长度不含 NUL；Token 最大 1024 字节；服务名最大 253 ASCII 字节，其余字符串最大 128 UTF-8 字节。配置不可原地修改，变更走 stop/destroy/create。证书格式与真实 FRPS 信任由 worker 在所选传输的 TLS 阶段验证，任何 FRP 凭据均在严格认证完成后发送。QUIC 必须显式选择 `EFRP_QUIC_PROFILE_P256_AES128_X25519`；TCP 的 quic_profile 必须为零。类型化 proxy options 和 XTCP options/secret 在 create 时验证并复制；XTCP 的 STUN 输入为至多两个数字 IPv4/port，不隐式增加 DNS 或探测 socket。配置和候选对端边界见[协议扩展](protocol-extensions.md)。

回调与 context 借用至 destroy 成功。`time_is_trusted` 必须快速返回当前系统墙钟的可信状态；库同时检查墙钟不早于 2024 年，并启用证书日期校验。该条件在连接期间持续检查，失去信任进入 failed。组件不启动 SNTP，不自行修改网络配置。

每实例恰好一个 worker 独占主传输、会话、XTCP controller/child peer 和工作 socket。create 创建一个空闲任务；stopped 期间该任务阻塞在四项有界命令队列，不做 I/O。IDF 使用 6144 字节任务栈、优先级 5、静态 TCB/队列/锁，以及一项二值完成信号；资源都归实例。栈余量必须由实板测量，不能用该预算声称通过。

## 启停与状态

start 返回 OK 只代表 START 已入队。状态依次可能经过 connecting、tls_handshaking、authenticating、registering；provider 只有代理注册成功且收到首次 Token 认证 Pong 才报告 ready；visitor 不发 NewProxy，控制登录完成、收到首次认证 Pong，且本地 listener 绑定成功后才报告主 ready。XTCP 的会合/peer 状态另见 status.xtcp，主 READY 不代表 peer READY 或业务已连通。READY 是本次运行状态，不能代替版本的实板验收。

阶段变化在 worker 中调用 `on_event`，payload 只在回调内有效；回调外保留状态应使用自己的副本。`efrp_get_status` 可从回调或外部任务调用，复制受锁保护的快照。回调不能阻塞业务，start/stop/destroy 在 worker 内均返回 INVALID_STATE，避免自等待或释放自身。

生命周期调用通过独立 API 锁串行化，另一调用尚在执行时返回 WOULD_BLOCK，不阻塞等待该锁。对象寿命由调用方管理，destroy 不得与任何外部调用并发，包括 get_status。

stop 发送一次 STOP，随后等待唯一 worker 取消业务：先停止工作流和应用传输 I/O，全部本地连接、主 FRPS/child peer socket 和迟到 DNS 回调必须收敛。QUIC 丢弃旧业务报文，仅尝试发送一次加密 CONNECTION_CLOSE；EAGAIN 保留该关闭包与 owner 并由原 worker 重试；5 秒绝对期限只约束此报文，届时丢弃关闭包并删除协议借用、清零业务缓冲。迟到 DNS 或 SDK socket 关闭未成功时仍保留句柄与所有权，返回 WOULD_BLOCK 并继续收敛，不能在五秒时伪造 stop 完成。清理期间为 draining，不能启动另一连接。SDK DNS 没有取消 API；取消结果不表示回调已结束，故 stop 的等待期限到达时返回 TIMEOUT，句柄和停止请求继续有效。零期限返回 WOULD_BLOCK；重复 stop 等待同一请求，不重复入队。

worker 在清理完成后发布 stopped，等该事件回调返回才确认 STOP 完成。仅 stop 返回 OK 证明 I/O 与回调已全部停止；单看 stopped 快照不能证明其事件回调已经返回。再次 start 前不会有任何新回调。

destroy 先完成同一 stop，再发送 EXIT 并等待任务退出。IDF worker 最终自行挂起，外层确认是真正 suspended 后删除任务并释放栈/TCB，避免自行删除后依赖 idle task 的延迟回收；正常队列等待被 SDK 识别为 blocked，不混为退出。host 使用 pthread_join。destroy 成功清零 CA、Token 和实例，释放并将句柄置 NULL；任何失败或超时均保留句柄。

stop 是主动取消，不承诺排空业务或优雅关闭；已有工作流正常 FIN 路径仍独立成立。

## 故障与重连

网络错误、DNS 错误、期限、会话正常结束以及 TLS 上的裸 TCP EOF 可重试。TLS 裸 EOF 保留 TRUNCATED 错误供诊断，但以 TLS 终止状态识别它属于传输中断；经过认证的 FRP 帧截断仍为协议失败。主控制尝试的证书、认证、协商、协议、容量、资源分配和密码失败进入 failed，保持校验强度；维护者修正配置或运行条件后 stop/start，配置变化则重建实例。

XTCP admission 或 child peer 的拒绝/失败记录在 status.xtcp 并清理本次会合，主控制仍可保持 READY 与心跳；无法安全处理控制流或清理所有权的错误仍可终止主会话。

重试只能在上一尝试完全释放后调度。同实例只保存一个绝对单调时钟截止时刻，用命令队列的有限等待实现，不新建 esp_timer、FreeRTOS 软件定时器或重连任务。指数上限依次为 1、2、4、8、16、30 秒，实际等待在当前上限的 50%–100% 间抖动，之后保持 30 秒上限；随机失败进入 failed。连续 ready 至少 60 秒才在下一次失败时重置阶梯，短连接不会引发快速重连风暴。显式 stop/start 重置阶梯。

连接活动期间每次推进有界 I/O，然后最多等待一个 1 ms 请求周期；IDF 向上取整为至少一个 tick，避免默认 tick 配置下忙循环。停止命令会唤醒队列等待，包含长退避；主 FRPS 的每次连接至多一个 DNS 请求和一个 socket：TCP 或 QUIC UDP。XTCP 另在一轮会合中用同一个 UDP socket 完成 STUN、认证探测及 peer handoff，不轮询备用目标或失败后转其他协议。

状态记录尝试、重试、成功会话、Pong 与工作流累计计数；工作流 active/waiting/pending/cleaning 是本次尝试的瞬时值。错误、失败阶段、socket errno 和 TLS 库错误/验证标志用于诊断；TLS 验证标志在传输握手完成或 draining 时采集，UINT32_MAX 表示未采集；它不取代持续可信时间与实际连接状态。READY 根据已认证主传输、角色所需注册和首次 Pong 的实际转换确认。工作流字节计数表示本地 I/O 接受或读取的字节，不是远端业务收据。同实例自动重连及 stop/start 沿用已经验证的 run ID，但重新执行严格传输、Hello/Login，以及 provider 的代理注册；visitor 和 XTCP peer 仍分别完成其认证步骤。stop 成功只保证本地资源和回调收敛，不是 FRPS 已注销身份的确认；新实例通过可选 `run_id` 请求身份；调用方可传入已有稳定设备 UUID，也可复用旧实例状态中的已鉴权 run ID。create 深拷贝该值，最多 64 UTF-8 字节；未鉴权前状态中的 run ID 保持为空，仍须重新完成严格传输、Token 登录和角色所需注册。相同 run ID 的新控制连接只有通过官方服务端鉴权后才能取代旧连接；错误 Token 不会撤销旧控制连接。未提供该值且同一非空 client_id 仍在线时，官方服务端会明确拒绝，不把身份冲突当作认证成功。

## 验证边界

`client_upstream` 在实际官方 FRPS 上进行百次创建/注册/停止/销毁，另测一个实例的十次重启、三轮双业务流和两个活动连接的取消。每次 stop 后事件计数稳定，destroy 后 fd 恢复基线。服务端真实停止并在原端口重新创建，验证自动恢复到新的 ready 会话。

故障用例覆盖迟到 DNS、停止超时保留句柄、另一线程 stop 期间的有界拒绝、stopped 回调未返回、四阶段取消、失去可信时间、错误证书身份、错误 Token 和创建资源失败。网络测试同时释放/覆盖原始 CA 与配置字符串，验证深拷贝；另以非空 client_id 和显式 run_id 验证销毁后新实例完成登录并沿用已验证身份。新增官方 FRPS 冷实例回归将旧进程暂停、保留服务端控制连接，验证错误 Token 不改变旧 READY 状态，再以同一稳定身份在旧连接到期前完成替换；不依赖旧进程 RAM 或新增 NVS。退避阶梯通过测试时钟推进；真实服务重启使用真实时钟。`client_contract` 验证普通与类型化 XTCP 配置负例、provider/visitor 创建分配点失败、回滚和复制凭据清零。ASan/UBSan 与 TSan 必须分开构建。

正式 QUIC TCP/UDP/STCP visitor 已通过实际官方 FRPS 进程的业务、取消与重启；XTCP 公共 C provider/visitor 已通过维护候选的控制身份、双本地 STUN、会合、双方证明、双流 300001 字节、同 worker 停止/重启、时钟撤销和 fd/DNS 基线。正式矩阵与窄安全配置见[软件检查点](../verification/xtcp-candidate-software-20261003.md)。

pthread 调度、回环 DNS fixture 和两个 ESP target 编译只能证明各自范围。尚不能据此宣称实际 SDK 的任务/计时器/heap 稳定、Wi-Fi 切换成功，或完整实板与 72 小时组合验收通过。
