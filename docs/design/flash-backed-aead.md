# FRP 控制 AEAD 的 Flash 暂存

`esp_frp_flash_reader.h` 是 `src/session.c` 唯一的控制 AEAD 接收路径。它保持官方 FRP v0.71.0 的 stream nonce、记录长度、AES-256-GCM tag 和 64 KiB 明文上限，不改变 wire 字节。IDF 的 `esp_frp_idf_flash_store.h` 提供真实分区 adapter；独立样例绑定自己的实验分区，Base 必须显式传入自己的精确分区与既有 storage owner。host 通过不代表 Base 产品镜像容量或实板验收。

## 数据与认证边界

- 调用方提供独占的 4096 字节可按字节访问的 RAM 窗口。明文长度 `0..4096` 的记录在该窗口内完成整条 GCM 验证，不访问 Flash。正常心跳等小控制记录因此不会磨损暂存区。
- 大于 4096 字节时，provider 先擦除并独占恰好 65536 字节的 scratch。reader 只把密文按原顺序写入该区；16 字节 tag、长度头、nonce、方向 key、记录序号只在 RAM。写入/读取必须精确完成，不能把短写或短读报告为成功。
- tag 到齐后，reader 从 scratch 读回整条密文，完成 GCM 验证，同时计算 SHA-256，覆盖 AAD（stream nonce 与原长度头）、本条 nonce、记录序号、tag 和完整密文。验证失败清空窗口与 key、撤销暂存 lease，永久拒绝复用 reader。
- 首次验签后，每次最多交付 4096 字节。交付前**重新读回整条密文并完成 GCM 验签**，SHA-256 还必须等于首次读回的摘要，才返回本窗口。GCM 产生的临时明文在验证结束前仅存在调用方独占且其他任务不可观察的窗口，失败会清零。即使 scratch 在两个窗口间被改成另一条 tag 也正确的记录，摘要不符仍拒绝，不能拼接两条记录的明文。
- 已消费窗口立即清零。整条记录消费后撤销 lease 并允许下一条；空记录验证后立即释放。记录边界 EOF 本身不认证会话或业务成功。

## 存储所有权与中断

`efrp_aead_flash_store_t` 由产品装配实现。`begin` 在获得独占所有权且擦除 64 KiB 后返回非零新 lease；`write/read` 核对该 lease、范围及完整长度。`clear` 撤销 lease、隔离旧密文，可以把物理擦除延到下一次 `begin`，避免每条大记录擦两次。`clear` 失败时 provider 必须隔离该区域、拒绝新 `begin` 和旧 lease 的读写；reader 保留 lease，`close` 可重试，不能把失败当作释放成功。

设备每次启动都须在创建 FRP 会话前调用 `efrp_aead_flash_store_recover`。provider 此时撤销前一 boot 的任何 lease 并擦除中断记录，只有恢复成功才允许 `begin`。FRP 库无法单独证明产品已在启动顺序中调用；IDF provider 自行拒绝恢复前操作。掉电前可能保留的只有密文，没有 tag 或 RAM key。host 假分区测试验证旧 lease 在恢复后失效；真实设备掉电仍未验证。

IDF provider 在 bind 时逐项核对固定 `frp_scratch` label、data/undefined 类型、调用方传入的精确 offset、`0x10000` 大小、4096 字节擦除粒度及未加密、可写属性；bind 不擦除。每次 recover、begin、write、read 都通过调用方 `with_owner` 回调短暂获得 Flash owner，并验证该回调恰好调用 operation 一次且不吞掉操作错误。write 在返回前分块读回逐字节核对，能拒绝底层错误地报告成功的短写。`clear` 只在 provider guard 下撤销 RAM lease，下一次 begin 才擦除，不访问 Flash 或占用 owner；并发 guard 争用时失败并保留 lease 供重试。`with_owner` 的 claim/release 由 Base 按既有 storage owner 实现；独立样例只有本样例 Flash 操作，使用自己的原子独占标志。provider 不持有跨记录 owner token，不会把 OTA 锁住；OTA 占有 owner 时小记录完全走 RAM，大记录访问失败，随后仍可撤销 lease。此处只证明安全拒绝，业务并发活性还需产品验证。

## 成本与观测

对最大 65536 字节明文，首次验签加 16 个 4096 字节窗口共 **17 次全记录读与 GCM 验证**：至少写入 65536 字节密文，读回 `17 × 65536 = 1114112` 字节，并在 `begin` 时擦除 16 个 4 KiB 扇区。小于等于 4096 字节的记录没有 scratch 擦写。reader 暴露本生命周期的 `flash_records`、`flash_passes` 和 `flash_read_bytes`，provider 还应观测擦除次数、错误和每次耗时。高频大记录仍可能耗尽扇区寿命；本候选没有更改协议上限或擅自添加节流规则。

每次窗口调用会同步读取、哈希和解密整条记录。宿主时长不能推断 C3 的 Flash、PSA、Wi-Fi 和 watchdog 时长；实际设备需测最坏单步耗时、完整记录耗时与既有控制/心跳期限，并确认不会阻塞业务流或 OTA 的 Flash owner。真实设备的擦除失败、写入中断、并发和掉电恢复，以及独立样例双板峰值与 Base 产品装配，均尚未验收。

`efrp_config_t.flash_store` 和 `efrp_session_config_t.flash_store` 都是必填项；client/session 复制回调表，provider 对象和 `context` 必须存活至 destroy 成功。session 在登录完成后初始化唯一 Flash reader，独立 4096 字节窗口不与 wire parser 的 `json_rx` 重叠。`efrp_session_cancel` 后如 clear 失败，reader 保留 lease 与窗口；`efrp_session_destroy` 返回 `EFRP_STORAGE_ERROR` 并保留 handle，调用方应在 owner 可用后重试。client worker 的清理循环也等待此成功，才销毁 TLS/连接并允许重连。旧 RAM reader 和 ESP32 IRAM 实验分支不在当前运行路径。

host fake Flash 回归覆盖 4096/4097 边界、64 KiB 正例与错 tag、tag 前零交付、部分写入后报错、窗口复读中途报错、末窗消费时 clear 失败与重试、双 reader 争用、认证后篡改和有效记录替换、掉电后的旧 lease 失效。假 IDF 分区回归另验证精确几何、完整 64 KiB 记录的 17 次复读、OTA owner 占用时小记录绕过 scratch、大记录 begin/写入或窗口复读中安全失败、写回读发现短写、clear 隔离重试，以及错误 `with_owner` 调用次数和操作结果。OpenSSL、独立 PSA 与完整 Mbed TLS host 还运行官方 FRP/FRPS 互操作，包括会话内 64 KiB 正例、坏 tag 和 clear 失败重试。它们证明软件合同，不代替设备 Flash/PSA 芯片运行面与 Base 容量验收。
