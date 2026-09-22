# 客户端实现合同

首版固定官方 FRPS v0.71.0，TCP + 严格 TLS + Yamux + wire v2 + Token，一条 TCP proxy，最多两条活跃业务流、一条预备流和一条控制流。当前完整客户端尚未实现；本文件定义后续公开 esp_frp.h 的行为边界。

生命周期为 create/start/stop/destroy，公开符号统一 efrp_。每个实例单 worker 独占 transport、parser、会话和计时器；外部经有界队列请求。create 深拷贝配置和证书输入；事件载荷只在回调内有效。stop 等待 I/O 和回调收敛，destroy 返回后无回调；不在回调中同步 stop/destroy。

启动成功只表示任务开始，不等于 connected。状态区分 stopped/connecting/authenticating/registering/ready/backoff/failed；错误区分网络、TLS 信任、Token、wire、AEAD、容量、取消和 deadline，认证失败不得关闭校验重试。只保留一个重连定时器与一次连接尝试。

顺序为 TCP→TLS→Yamux 控制流→v2 magic→Hello/Login→控制 AEAD；work 流单独发送 magic/NewWorkConn，读取 StartWorkConn 后转业务，不重复 Hello 或控制 AEAD。严格校验 CA、主机名、SNI 和可信时间，AEAD 完整认证后才解析控制消息。

Yamux 初始窗口 256 KiB，不每流分配等大缓冲。小 ring 消费后补 credit；慢流有时限，超时 RST 并有界排空，无法保持 framing 则结束会话。DATA 大于 ring 必须增量处理，非法 credit/溢出必须失败。预备流异步等握手，不能阻塞单 worker。work 本地目标必须命中配置 allowlist。

独立 sample 不依赖 `esp-base`，不自动擦 NVS。官方 FRPS 互操作、C3 内存分配、双流、TLS/AEAD 负例和 100 次连接释放通过后才能标为 ready；host 帧测试不是这些结论。
