# C3 scratch 整区擦除与 Flash owner 争用

2026-10-13。联合 OTA 单次实验在 `prepare` 返回 `resource_failure`，原镜像完整保留、生产配置恢复。该次 `prepare` 为 799586299..804283657 us；OTA 的获取失败计数从 0 增至 1，最大等待为 511361 us，释放失败为 0。FRP 完成 claim 从阶段开始的 1 增至结束的 2。547114 us 的 FRP 最大持有上界在实验前就已存在，是同 boot 历史值，不能冒充这一次擦除的独立时长。MQTT partial 未在原 hold 内准入，本次没有最大满输入资格。

## 软件缺陷与修复

Base 消费的精确 FRP 0.2 输入为 `fbf238f145749c3fe97fc3a51fadfb11293691af`。修复前的 `src/idf_flash_store.c`：`recover`／`begin` 在一次 `with_owner` 中擦除整个 `0x10000` scratch。Base 原 owner 获取预算是 500000 us，竞争者每失败一次等待一 tick；FRP worker 优先级 5，OTA task 优先级 4。整区长占用与这一预算不相容；仅拆操作、随即重取，也无法保证低优先级任务得到中间窗口。这是已确认的软件缺陷，但现有实板聚合观测不能证明它是本轮失败的唯一原因。

provider 改为 16 个 4096 B 扇区逐次 claim／erase／release，在相邻扇区间释放 owner 后固定阻塞两 tick。一个 tick 可能与等待者同 tick 唤醒，仍由优先级 5 先取；两个 tick 给一 tick 轮询留下中间运行机会。私有 provider guard 在整轮擦除中保持，其他消费者只获得共享 Flash owner，不获得 scratch lease。总让出为 30 tick，不改 Base 的获取期限、锁身份、候选分区或线上配置。

全部扇区成功后才发布 lease。首次获取失败且没有任何 Flash 操作可重新 begin；任何部分擦除、操作或释放错误、回调漏调／重调／吞错均隔离，重新 recover 必须从头擦完整区。活动 lease 仍拒绝 recover，clear 仍只撤销 RAM lease，GCM 认证与窗口复验不变。

## 验证

- 在上述精确 0.2 源码上应用两文件生产补丁，OpenSSL ASan／UBSan host **10/10**；正式 Mbed TLS 的 `aead_flash`、`idf_flash_store`、`session_upstream`、`session_idf_flash_upstream` **4/4**。另一 0.3 工作树的 OpenSSL ASan／UBSan host **18/18**，结果与 0.2 分开记录。
- IDF adapter 回归对 recover／begin、16 个扇区、6 类失败逐一注入，共 **192** 个用例，检查未完成擦除不发 lease、未擦尾部不被触碰、隔离后拒绝访问、完整重恢复，以及让出期间的并发 clear。旧 0.2 provider 被新增单扇区断言拒绝，负对照符合预期。
- C3 QEMU 使用锁定的 ESP-IDF 6.1 与真实 FreeRTOS、正式 provider 和真实 MTD 分区操作。仅测试 wrapper 加入每扇区 40 ms 固定合成延迟，并将释放对齐到等待者本 tick 已失败的合法相位。优先级 5／4、等待者一 tick 轮询、500000 us 预算保持：零 tick 负对照等待 **507502 us** 失败；一 tick 负对照等待 **511232 us** 失败；生产两 tick 的 recover／begin 分别在第一扇区后 **60303／61803 us** 获得 owner。后两者均继续完成全部 16 扇区。
- 同一 QEMU 应用完成 65536 B 记录认证、17 次全记录复验、坏 tag 零交付及第二次启动完整擦除；主机独立核对 MTD 密文和擦除字节。正式 session/provider host 的满长正例擦除 131072 B、写入 65536 B、读取 1179648 B，claim／release **2275/2275**，无活动 lease 残留。
- ESP32、ESP32-C3 分别复用原 Base 冻结生产编译参数，仅将修复后的 FRP provider 编译为仓外独立对象；两目标通过，未重新链接、修改或发布 Base 镜像。

## 交付边界

生产差异仅为 `src/idf_flash_store.c` 和 `include/esp_frp_idf_flash_store.h`；原 0.2 已声明 FreeRTOS 依赖，无需更改组件清单或引入 0.3 的 QUIC／XTCP。修复与回归沿既有 0.2 分支保存；Base 必须显式锁定修复提交，分别通过官方 Component Manager 生成双目标依赖锁，再构建、签名并完成产品实板验证。上述软件检查本身没有修改 Base pin 或发布产品固件。

QEMU 的 Flash 延迟是合成输入，任务通知只选择测试相位，均不进入生产 provider。以上结果证明操作粒度、失败隔离及该实际调度相位下的修正，不证明实板物理时延、任意负载下的公平性或完整 R5。实板采用新候选后的联合运行、原 ID 结果、容量及恢复仍由 Base 任务独立验收；需要人工断电的项目继续暂缓。
