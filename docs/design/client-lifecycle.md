# 客户端生命周期

`esp_frp.h` 组合已有 DNS/TCP、严格 TLS、Yamux、Hello/Login、控制 AEAD 和固定目标工作流。目标为 ESP-IDF v6.1 / ESP32-C3；host 通过相同 `client.c` 和仅测试调度适配验证。独立 sample 位于 `examples/tcp_proxy`；真实 SDK DNS、FreeRTOS 调度与资源、实板 FRPS 和 Base/MQTT 组合仍须验收。

## 配置与所有权

create 复制服务主机、CA、Token、身份、代理名和唯一 IPv4/port 本地目标，不保留输入字节指针。CA 最大 16384 字节且长度不含 NUL；Token 最大 1024 字节；服务名最大 253 ASCII 字节，其余字符串最大 128 UTF-8 字节。配置不可原地修改，变更走 stop/destroy/create。证书格式与真实对端信任由 worker 在 TLS 阶段验证，任何 FRP 凭据均在严格 TLS 完成后发送。

回调与 context 借用至 destroy 成功。`time_is_trusted` 必须快速返回当前系统墙钟的可信状态；库同时检查墙钟不早于 2024 年，并启用证书日期校验。该条件在连接期间持续检查，失去信任进入 failed。组件不启动 SNTP，不自行修改网络配置。

每实例恰好一个 worker 独占连接、TLS、会话和工作 socket。create 创建一个空闲任务；stopped 期间该任务阻塞在四项有界命令队列，不做 I/O。IDF 使用 8192 字节任务栈、优先级 5、静态 TCB/队列/锁，以及一项二值完成信号；资源都归实例。栈余量必须由实板测量，不能用该预算声称通过。

## 启停与状态

start 返回 OK 只代表 START 已入队。状态依次可能经过 connecting、tls_handshaking、authenticating、registering；只有代理注册成功且收到首次 Token 认证 Pong 才报告 ready。READY 是本次运行状态，不能代替版本的实板验收。

阶段变化在 worker 中调用 `on_event`，payload 只在回调内有效；回调外保留状态应使用自己的副本。`efrp_get_status` 可从回调或外部任务调用，复制受锁保护的快照。回调不能阻塞业务，start/stop/destroy 在 worker 内均返回 INVALID_STATE，避免自等待或释放自身。

生命周期调用通过独立 API 锁串行化，另一调用尚在执行时返回 WOULD_BLOCK，不阻塞等待该锁。对象寿命由调用方管理，destroy 不得与任何外部调用并发，包括 get_status。

stop 发送一次 STOP，随后等待唯一 worker 取消业务：工作流与 TLS 先停止，全部本地连接、FRPS socket 和迟到 DNS 回调必须收敛。清理期间为 draining，不能启动另一连接。SDK DNS 没有取消 API；取消结果不表示回调已结束，故 stop 的等待期限到达时返回 TIMEOUT，句柄和停止请求继续有效。零期限返回 WOULD_BLOCK；重复 stop 等待同一请求，不重复入队。

worker 在清理完成后发布 stopped，等该事件回调返回才确认 STOP 完成。仅 stop 返回 OK 证明 I/O 与回调已全部停止；单看 stopped 快照不能证明其事件回调已经返回。再次 start 前不会有任何新回调。

destroy 先完成同一 stop，再发送 EXIT 并等待任务退出。IDF worker 最终自行挂起，外层确认是真正 suspended 后删除任务并释放栈/TCB，避免自行删除后依赖 idle task 的延迟回收；正常队列等待被 SDK 识别为 blocked，不混为退出。host 使用 pthread_join。destroy 成功清零 CA、Token 和实例，释放并将句柄置 NULL；任何失败或超时均保留句柄。

stop 是主动取消，不承诺排空业务或优雅关闭；已有工作流正常 FIN 路径仍独立成立。

## 故障与重连

网络错误、DNS 错误、期限、会话正常结束以及 TLS 上的裸 TCP EOF 可重试。TLS 裸 EOF 保留 TRUNCATED 错误供诊断，但以 TLS 终止状态识别它属于传输中断；经过认证的 FRP 帧截断仍为协议失败。证书、认证、协商、协议、容量、资源分配和密码失败进入 failed，保持校验强度；维护者修正配置或运行条件后 stop/start，配置变化则重建实例。

重试只能在上一尝试完全释放后调度。同实例只保存一个绝对单调时钟截止时刻，用命令队列的有限等待实现，不新建 esp_timer、FreeRTOS 软件定时器或重连任务。指数上限依次为 1、2、4、8、16、30 秒，实际等待在当前上限的 50%–100% 间抖动，之后保持 30 秒上限；随机失败进入 failed。连续 ready 至少 60 秒才在下一次失败时重置阶梯，短连接不会引发快速重连风暴。显式 stop/start 重置阶梯。

连接活动期间每次推进有界 I/O，然后最多等待一个 1 ms 请求周期；IDF 向上取整为至少一个 tick，避免默认 tick 配置下忙循环。停止命令会唤醒队列等待，包含长退避；每次连接仅一个 DNS 请求和一个 TCP socket，不轮询其他目标。

状态记录尝试、重试、成功会话、Pong 与工作流累计计数；工作流 active/waiting/pending/cleaning 是本次尝试的瞬时值。错误、失败阶段、socket errno 和 TLS 库错误/验证标志用于诊断；TLS 验证标志仅在 draining 时从 TLS 层采集，此前的 UINT32_MAX 表示未采集，不能当作实时信任指示器。READY 由成功 TLS、注册和 Pong 的实际状态转换确认。工作流字节计数表示本地 I/O 接受或读取的字节，不是远端业务收据。同实例自动重连及 stop/start 沿用已经验证的 run ID，但重新执行严格 TLS、Hello/Login 和代理注册。stop 成功只保证本地资源和回调收敛，不是 FRPS 已注销身份的确认；新实例默认不继承旧实例的 run ID；调用方可从旧实例状态获取已经验证的 run ID，通过可选 previous_run_id 显式传入新实例。create 深拷贝该值，最多 128 UTF-8 字节，仍须重新完成 TLS、Token 登录与注册。未提供该值且同一非空 client_id 仍在线时，官方服务端会明确拒绝，不把身份冲突当作认证成功。

## 验证边界

`client_upstream` 在实际官方 FRPS 上进行百次创建/注册/停止/销毁，另测一个实例的十次重启、三轮双业务流和两个活动连接的取消。每次 stop 后事件计数稳定，destroy 后 fd 恢复基线。服务端真实停止并在原端口重新创建，验证自动恢复到新的 ready 会话。

故障用例覆盖迟到 DNS、停止超时保留句柄、另一线程 stop 期间的有界拒绝、stopped 回调未返回、四阶段取消、失去可信时间、错误证书身份、错误 Token 和创建资源失败。网络测试同时释放/覆盖原始 CA 与配置字符串，验证深拷贝；另以非空 client_id 和显式 previous_run_id 验证销毁后新实例完成登录并沿用已验证身份。退避阶梯通过测试时钟推进；真实服务重启使用真实时钟。`client_contract` 验证 16 个配置负例、三个 host 创建分配点失败、回滚和复制凭据清零。ASan/UBSan 与 TSan 必须分开构建。

pthread 调度、回环 DNS fixture 和 C3 编译只能证明各自范围。尚不能据此宣称实际 SDK 的任务/计时器/heap 稳定、Wi-Fi 切换成功，或完整实板与 72 小时组合验收通过。
