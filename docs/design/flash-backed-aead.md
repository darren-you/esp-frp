# FRP 控制 AEAD 的 Flash 暂存候选

本页描述 `esp_frp_flash_reader.h` 的独立软件合同。它保持官方 FRP v0.71.0 的 stream nonce、记录长度、AES-256-GCM tag 和 64 KiB 明文上限，不改变 wire 字节。当前 `src/session.c` 仍使用分块 RAM reader；本候选尚未绑定设备分区或会话，也不代表 C3 容量验收。

## 数据与认证边界

- 调用方提供独占的 4096 字节可按字节访问的 RAM 窗口。明文长度 `0..4096` 的记录在该窗口内完成整条 GCM 验证，不访问 Flash。正常心跳等小控制记录因此不会磨损暂存区。
- 大于 4096 字节时，provider 先擦除并独占恰好 65536 字节的 scratch。reader 只把密文按原顺序写入该区；16 字节 tag、长度头、nonce、方向 key、记录序号只在 RAM。写入/读取必须精确完成，不能把短写或短读报告为成功。
- tag 到齐后，reader 从 scratch 读回整条密文，完成 GCM 验证，同时计算 SHA-256，覆盖 AAD（stream nonce 与原长度头）、本条 nonce、记录序号、tag 和完整密文。验证失败清空窗口与 key、撤销暂存 lease，永久拒绝复用 reader。
- 首次验签后，每次最多交付 4096 字节。交付前**重新读回整条密文并完成 GCM 验签**，SHA-256 还必须等于首次读回的摘要，才返回本窗口。GCM 产生的临时明文在验证结束前仅存在调用方独占且其他任务不可观察的窗口，失败会清零。即使 scratch 在两个窗口间被改成另一条 tag 也正确的记录，摘要不符仍拒绝，不能拼接两条记录的明文。
- 已消费窗口立即清零。整条记录消费后撤销 lease 并允许下一条；空记录验证后立即释放。记录边界 EOF 本身不认证会话或业务成功。

## 存储所有权与中断

`efrp_aead_flash_store_t` 由产品装配实现。`begin` 在获得独占所有权且擦除 64 KiB 后返回非零新 lease；`write/read` 核对该 lease、范围及完整长度。`clear` 撤销 lease、隔离旧密文，可以把物理擦除延到下一次 `begin`，避免每条大记录擦两次。`clear` 失败时 provider 必须隔离该区域、拒绝新 `begin` 和旧 lease 的读写；reader 保留 lease，`close` 可重试，不能把失败当作释放成功。

设备每次启动都须在创建 FRP 会话前调用 `efrp_aead_flash_store_recover`。provider 此时撤销前一 boot 的任何 lease 并擦除中断记录，只有恢复成功才允许 `begin`。FRP 库无法单独证明产品已在启动顺序中调用；provider 必须自行拒绝恢复前操作。掉电前可能保留的只有密文，没有 tag 或 RAM key。伪 Flash 测试验证旧 lease 在恢复后失效；真实分区、掉电和启动接线仍未验证。

scratch 的独占范围必须由 Base 的 Flash 操作 owner 与 OTA、包槽、配置提交共同裁决。FRP 单 owner 不等于全设备 Flash 互斥；provider 也不能覆盖身份、NVS、app 或 product package 分区。当前候选不声明任何正式分区 offset，不调用设备擦写 API。

## 成本与观测

对最大 65536 字节明文，首次验签加 16 个 4096 字节窗口共 **17 次全记录读与 GCM 验证**：至少写入 65536 字节密文，读回 `17 × 65536 = 1114112` 字节，并在 `begin` 时擦除 16 个 4 KiB 扇区。小于等于 4096 字节的记录没有 scratch 擦写。reader 暴露本生命周期的 `flash_records`、`flash_passes` 和 `flash_read_bytes`，provider 还应观测擦除次数、错误和每次耗时。高频大记录仍可能耗尽扇区寿命；本候选没有更改协议上限或擅自添加节流规则。

每次窗口调用会同步读取、哈希和解密整条记录。宿主时长不能推断 C3 的 Flash、PSA、Wi-Fi 和 watchdog 时长；实际会话接入前必须在固定候选镜像上测最坏单步耗时、完整记录耗时与既有控制/心跳期限，并确认不会阻塞业务流或 OTA 的 Flash owner。还需验证真实 provider 的对齐、加密分区行为、擦除失败、写入中断、读回错误、并发与启动恢复。只有这些与独占分区、双板峰值和产品装配全部闭合，才能替换当前会话 RAM reader 并讨论 P6-03。

当前 `efrp_session_create` 在没有 scratch provider 的情况下仍走现有分块 RAM reader；满长记录在内存不足时明确返回 `EFRP_NO_MEMORY`，本分支没有改变该行为或将软件候选宣传为会话能力。若现在加入可选 provider，需要同时维护两套 reader 的初始化、明文读取、消费、EOF、失败和释放分支，还要为新 reader 单独提供 4096 字节窗口：现有 `json_rx` 在控制解析时同时借给 wire parser，不能重叠。该接线会在尚无真实分区及全局 Flash owner 时形成长期双路径。因此本次只交付独立核心；待产品分区和单一 owner 冻结后，先实现真实 provider 与启动 `recover`，再在 `session.c` 的创建、登录完成、控制输入、EOF 和销毁五处一次性切换目标装配，验证 64 KiB 官方记录、期限、失败清理及双板组合峰值。

host fake Flash 回归覆盖 4096/4097 边界、64 KiB 正例与错 tag、tag 前零交付、部分写入后报错、首次认证后的窗口复读中途报错、末窗消费时 clear 失败与重试、双 reader 争用、认证后篡改和有效记录替换、掉电后的旧 lease 失效；故障后须清零窗口与 key，旧 lease 撤销后失效，若清理失败则隔离该 lease 并拒绝新 owner 抢占。调用方必须零初始化 reader，且在 `close` 成功前保留 reader 和独占窗口，失败后重试清理。OpenSSL 与官方 PSA host 后端分别运行同一测试。可选 `aead_upstream` 还把官方 FRP 发来的有效记录同时交给原 RAM reader 与本 reader，逐字节比对明文。它们证明本软件接口行为，不代替设备 Flash、PSA 芯片适配或完整 FRPS 会话验证。
