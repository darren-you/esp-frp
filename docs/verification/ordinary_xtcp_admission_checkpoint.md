# 普通 FRPC 与 XTCP 控制准入软件检查点

## 修复范围

普通 TCP／UDP 配置只发起普通 Login；严格 TLS、Token 和 v2 transport 可用本身不表示该配置需要 XTCP 控制身份。只有实际启用的 XTCP provider 或 visitor 才申请 `esp-frp-xtcp/1` 控制绑定。XTCP 继续要求配套实现、明确 CA 校验、非空 Token 运行时和 v2，不新增公开能力开关，也不在协商失败后退回普通或官方 XTCP。

此前普通配置会无条件申请 XTCP 身份，官方固定源码 `4a23aa181c1d7e28eecaa8216024ed753b9d27c8` 的 FRPS 不返回该字段，普通 TCP／UDP 因而登录失败。该真实 CLI 失败与官方 FRPC 同配置的 999 字节回显对照由外层验证保存；本检查点不以候选 FRPS 回环替代普通官方 FRPS 验证。

## 更新与登录边界

- 配置发布与控制实例安装均使用既有 `cfgMu → ctlMu` 锁顺序。ordinary → XTCP 更新先发布完整新配置，捕获未绑定的旧 Control，在锁外只关闭该旧实例；既有 `keepControllerWorking` 等其 Done 后按新配置重新 Login。不取消 Service，不在旧 pm／vm 上启动 XTCP，不新增重连 registry 或 generation。
- 每次 Dial 从当前配置取得是否需要绑定的快照。收到 LoginResp 后、Control 安装和 Run 之前，在同一配置锁下复核；需求改变时关闭本次真实 connection／connector，沿原退避重试当前配置。没有合法控制身份的连接不能启动 XTCP。
- 初次登录等待 LoginResp 期间移除最后 XTCP 后，旧协商的失败不能触发 `loginFailExit` 取消当前合法 ordinary 配置；成功但已经过时的旧绑定响应也必须废弃。需求未变化时，原初次登录失败退出语义保持。
- `NewService` 在创建管理监听前拒绝不满足前提的初始 XTCP；公开 `Control.Run`／`UpdateAllConfigurer` 同时检查 TLS／Token／v2 运行时和身份，不能仅凭公开字段中一个形状正确的 32 字节值启动 pm／vm。
- 每个实际 Control 使用既有 xlog `Spawn` 创建独立日志前缀，worker 启动后不再改共享前缀。中间候选曾在 worker 启动后写入共享前缀，race 检查自然失败；失败日志保留，随后修正。
- `UpdateAllConfigurer` 的 nil 保持既有异步受理语义，不代表新 XTCP 已注册或业务连接已经成功。调用方仍读取真实状态与业务结果。
- 公开更新仍可先于或并发于 `Run`。中间候选新增的 Service.ctx guard 与 Run 初始化产生真实 race，已删除该新增 guard，沿用既有 Control.ctx 和安装前 Service 取消校验；没有为该 guard 再加状态或初始化锁。正式回归以已经取消的父 context 避免联网，并验证并发公开更新的最终配置保留和 Run 自然退出。

## 已执行的软件验证

所有 Go 命令固定 `GOPROXY=off`、`GOSUMDB=off`、`GOTOOLCHAIN=local` 和 `-mod=readonly`，未升级依赖。

1. v2 相关六包完整 `go test -race -count=1 -timeout=90s -v` 自然退出 0：55 个顶层测试，113 行 PASS，一包没有测试；其中 C 客户端测试明确跳过，因为这次命令没有设置 C binary。
2. 新 LoginResp gate 使用真实回环 TLS、正式默认 Connector、明确测试 CA、Token 验证、v2 Hello 及后续 AEAD 控制消息，覆盖旧 XTCP 失败／成功响应期间移除配置、等待 ordinary 响应期间新增 XTCP，以及 60 次并发更新只注册最终配置。过时连接必须真实结束，读超时不得冒充回收。该 gate 是可控 wire peer，不能声称是完整 FRPS。
3. 真实候选 FRPS／FRPC 完整 strict TLS、STUN、HMAC SID、mutual QUIC 和 proof 链路通过 ordinary → XTCP 动态新增；仅在新绑定控制上注册，两个独立 300001 字节后端回显通过，关闭后两个真实空闲后端连接结束。相关旧 provider 卸载、同名重加、Control 重连与取消测试也在完整 race 命令通过。
4. 前继 v1 单独显式传入外层构建的实际 `xtcp_client_peer`，`TestCClientFullCandidate` 在 race 下自然退出 0，无跳过：C provider／visitor、两条 300001 字节业务、停止／重启、时钟撤销及六类严格控制／visitor 负例通过。实际 C binary 摘要记录在前继私有 receipt；本轮未构建或修改该 C binary。v2 保留这份历史结果，不沿用 v1 的整树 C／Go 资格；外层组合需对 v2 源码执行新的实际 C 测试。
5. `go vet -tags=noweb` 覆盖 client 子包、nathole、xtcpbinding、测试及 FRPC CLI，自然退出 0。

以上是当前候选的软件资格，不证明设备写入、异网 NAT、双板堆预算、Base 组合镜像、正式签名与生产发布。原编译装配失败、真实 race 失败和每次实际退出收据均保留，不用后继成功覆盖。
