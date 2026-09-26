# C3 注册后完整 AEAD 记录容量复测

2026-09-27。本轮只扩充仓外 QEMU 容量探针，不修改 FRP 运行时代码、产品配置、记录上限或设备。目标是把已注册真实 FRP 会话存活时的完整 64 KiB 接收失败，定位到公开 AEAD reader 的实际分配点。C3 实板、真实 Wi-Fi 射频、Broker、OTA 与产品包分区仍不在本轮验证范围内。

## 输入和方法

以[前次工作槽惰性分配的 C3 `new/probe`](p6-frp-lazy-work-stream-capacity.md)为冻结输入；它在 Base READY、ABI 2 一页 64 KiB guest 与 OpenETH 共存时，已经到官方 FRPS `REGISTERED`、`ready=1`、`pongs=1`。Base 产品源码对应 `esp-base@058e965`；后续 `esp-base@968164c` 对该 C3 容量原型仅改变文档和 FRP 组件锁，应用源码不变。本轮从 `esp-frp@e5a6b0b` 覆盖组件 `src/` 和 `include/` 的差异文件，准备脚本校验关键源码 SHA-256；输出工程逐文件与该提交的 `src/`、`include/` 比较相同。其余 MQTT `9d6d95e`、OTA `2072731`、Container `8eb805f`、WAMR `26c235e` 和固定 IDF `578cf89` 沿用原 QEMU 容量切片。后来 Container `bf52b17` 的槽与产品 API 尚未接入这个旧容量原型；不得把本结果称作当前五仓产品装配验收。

[准备脚本](prepare-c3-registered-record-qemu.py)检查基线 `sdkconfig` 与探针源码、FRP 候选源码，再复制工程，增加两次调用：注册状态读回后先向独立 `efrp_aead_reader_init_chunked` 投喂完整 4 KiB 测试 wire，再投喂完整 64 KiB 测试 wire。真实 FRP client、TLS、控制 session 与 guest 全程仍存活。两条 wire 使用原切片的 AES-256-GCM 固定公开测试向量；成功时逐字节核对明文并消费，失败时记录 `consumed`、已分配块数、零明文交付和释放数。此 reader 与正式 C3 `efrp_session` 使用同一公开 `calloc/free` 分块路径，但它是额外的独立 reader，**没有由 FRPS 向 session 发送满长控制记录**。运行脚本只使用独立回环端口 `29183`，按启动 PID 结束 FRPS 和 QEMU，不操作物理板。

## 结果

固定 IDF 构建的测试键 RSA v2 签名镜像为 **1,249,280 B**，SHA-256 `12d8bba698b3b7cad11defaeaaa1646437910dc95012db822e413caa66840d70`；`espsecure v5.4.0 verify-signature` 核对第 0 签名块有效。`sdkconfig` SHA-256 `a66858cf817841457a8557a46ec18e5757e4889a5e31dffc0978adf8a277fb52`，与前次 C3 工作槽探针相同。构建后 `src/` 与 `include/` 逐文件校验均与 `esp-frp@e5a6b0b` 相同。官方 FRPS 回环监听 29183；QEMU 原始日志 SHA-256 `9d5ab483252efe1a560ca134a5c54468b71e1596192b1b9a539f254cc87738e1`，关键行见[脱敏摘录](p6-c3-registered-record-qemu-trace.txt)。20 秒到期后宿主停止 QEMU，FRPS 输出 `QEMU_FRPS_STOPPED`，无测试进程遗留。

| 同一 Base READY + guest + FRP 状态 | 结果 |
| --- | --- |
| guest 存活、事件调用 | `open/init/event/stop/close=0`、事件结果 3；随后 FRPS `client_phase=5`、`ready=1`、`pongs=1` |
| 正式 FRP 注册后 8-bit 堆 | free/largest/min = **20,096/9,216/4,612 B** |
| 独立 reader 完整 4 KiB wire | `feed=0`、`records=1`、4,096 B 逐字节核对、申请/释放 1/1；前后 free/largest 均为 20,096/9,216 B |
| 独立 reader 完整 64 KiB wire | 第 4 笔 4,096 B `calloc` 失败，`EFRP_NO_MEMORY=-20`；已消费 **12,304 B**（12 B nonce、4 B 长度、12,288 B 密文），`records=0`、明文核对 0 B、申请/释放 **3/3**；前后 free/largest 均为 20,096/9,216 B |
| 后续清理 | `efrp_destroy=0`；OpenETH 清理后 free/largest = 84,432/45,056 B；guest 第二轮 `probe_summary runs=2 failures=0` |

容量失败是此实验的**预期诊断结果**，`probe_summary failures=0` 只表示预期失败及清理都符合探针断言，不能解释成 64 KiB 记录成功。首次仪表试跑保留在仓外：它使用相同的新工作槽和 Yamux，但 AEAD/session 仍是旧基线；该结果不参与本表，也不跨源码版本合并数字。

在已注册会话的 **20,096 B** 空闲状态下，64 KiB 明文本体单独需要 65,536 B，必要缺口 **45,440 B**；16 笔分配器开销、密码库计算及其它网络负载还会增加峰值。注册后的 free 本身已低于五仓计划的 48 KiB 初始观察门槛。另一项直接探针已证明把 `MALLOC_CAP_32BIT` 当额外池不可行：同一注册状态下 8BIT 与 32BIT free/largest 数值一致，第 4 笔 4 KiB 申请失败，见 [C3 32BIT 实验](https://github.com/esp-space/esp-container/blob/bf52b17/docs/operations/c3-registered-32bit-qemu-capacity.md)。仅把 FRP 对象再缩小少量字节，无法补齐上述明文本体缺口。

## 可复现入口与边界

在持有前述冻结基线、固定 SDK、测试签名键和回环官方 FRPS fixture 的 `mac-work-1` 上，先把本仓完整 `e5a6b0b` 源码及两份脚本复制到仓外目录，再运行：

```bash
python3 prepare-c3-registered-record-qemu.py \
  /private/tmp/esp-c3-lazy-work-ab-20260927/new/probe \
  /absolute/path/to/esp-frp-e5a6b0b \
  /private/tmp/esp-c3-registered-record-exact-20260927 --port 29183
bash run-c3-registered-record-qemu.sh \
  /private/tmp/esp-c3-registered-record-exact-20260927 \
  /private/tmp/esp-c3-registered-record-exact-run-20260927 \
  /private/tmp/esp-c3-yamux-frps-qemu-20260927/frp_chunked_qemu.py
```

正式并发容量仍未验收。保留 64 KiB 认证记录和同时存活的 64 KiB guest，需要一个不向 guest 暴露未经认证明文、可承受完整密文并在掉电后清理的存储路径。当前 C3 4 MiB 分区的两个 app 槽及保留分区已占满；挪用 app、NVS、coredump 或三包槽均会破坏已有所有权与恢复合同。受管 Flash 暂存若作为候选，需与固件/包槽几何和单一存储 owner 一起设计，并对认证、读回、掉电及磨损做端到端验证；本轮不据此更改分区。
