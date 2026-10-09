# FRP 软件资格检查点

更新时间：2026-10-04。

扩展基线已由三机源码同步保存为 `5c50e71acdc4e1da45cf3730682d4323c9f6e618`。角色、撤销、QUIC 调度与确定性夹具已本地保存为 `00b36c3bc21bdf3a26718ddca4796ae37e59bb87`。后继 v6 再修接收信用分配错误；它们仍属于 0.3.0 软件候选，不构成正式发布、设备或 Base 原生业务组合验收。

## 已落实的修正

- QUIC peer 叶证书要求唯一角色 DNS SAN 和唯一对应 EKU，C 与维护 Go 对端使用相同角色合同。正例与真实错误证书入口仍执行严格验链、CertificateVerify 和 exporter proof。
- 普通 XTCP 配置的准入、控制连接撤销、重登录及关闭取消沿当前控制 owner 收敛；共享 Go peer 保持唯一实现，不建立旧协议或旧 owner 兼容路径。
- QUIC 原生流只有在实际接受数据或零字节 FIN 时才推进发送轮次。pacing 暂未接受数据时保留实际选中 slot，单流信用阻塞时跳过该流；发送环、ACK 借用生命周期、容量和期限保持。
- QUIC 应用读取先核对 native 流信用扩展结果，再交付并清零接收字节；真实首次队列分配失败沿原 NO_MEMORY／cleanup 合同返回，不把本块作为成功数据交付。不新增重试、容量或状态。
- 测试 logger 在包 TestMain 初始化一次；STCP 夹具继续推进原会话直到本地读计数成立；长载荷夹具在下一次 transport step 前填满真实发送环并验证 WOULD_BLOCK。三者保留原业务字节、断言和期限。
- 现有上游来源清单精确登记原样 AGENTS、CLAUDE 和两份 Dashboard HTTP decoder。工作区检查共用路径、类型、执行位及 SHA-256 校验，修改和新增文件继续进入第一方门禁。

## 软件验证

| 验证范围 | 当前结果 |
| --- | --- |
| 来源边界回归 | 113 项通过；实际 AGENTS 全量 83/83 最新、零漂移；实际响应合同 46 仓、2898 源码、零失败 |
| 维护 Go 受影响九包 | 新 C 客户端真实参与，race 303 个主／子测试通过、零跳过／竞态；同九包 vet 通过 |
| 合并 v4 完整 C 矩阵 | 50/53，通过修正后的 STCP、QUIC 客户端与角色合同；真实退出 8，完整失败日志保留 |
| 后继背压夹具 | 原完整 QUIC transport 入口通过，long 与 loss-reorder 均完整传输 514062 字节、双流 FIN 与回收；原负例、取消、重置和迟到 STOP 均保留 |
| 合并 v5 完整 C 矩阵 | 单独串行 52/53、真实退出 8；仅 direct visitor 仍失败，QUIC transport 与 provider 重启原入口通过。相对 v4 仅上述背压测试文件改变，未改 Go 或生产 C 源码 |
| v6 native 信用失败 | 同一真实 ngtcp2 首次队列 realloc 拒绝：旧源码退出 134、误报 OK 并交付 1024 B；修正后退出 0、NO_MEMORY 且交付 0 B。正常跨环读取和关闭后尾数据对照通过 |
| v6 ASan／UBSan | 原三个子场景通过、真实退出 0；218 个实际对象及最终链接带 sanitizer。覆盖新的错误清理路径，不代表 LeakSan 或全矩阵资格 |
| 合并 v6 完整 C 矩阵 | 单独串行 54/54、真实退出 0；新增 native 信用失败回归与原 direct／重启入口均通过，835 项冻结源码前后不变。未追认历史 visitor 超时根因 |
| C3／ESP32 SDK | 两份独立完整冷构建通过；每目标 99 项源码输入、36 个实际第一方 C 编译对象、59 个必要正尺寸符号核对通过 |

v4 的三个失败为 QUIC 长载荷夹具没有必然触发背压、XTCP direct visitor 双流未完成、C provider 重启后的双流读取超时。第一个在诊断中完整传输与回收但 blocked=0，已用真实环填满测试修正；另两项隔离诊断通过不追认为原失败已修复，原因仍待核实。v5 的 direct visitor 仍在该轮原 15 秒内未完成，请求发送 600002 B、响应收到 550912 B，completed=0、active=2；原断言继续失败。provider 重启原入口 v5 通过，但不追认为 v4 超时原因已查明。不得把它们无据归因于 CPU 负载。

三次稀疏诊断分别保留：两次 targeted visitor 和一次原完整 direct 序列均通过；完整序列前序退出后已观察到自有 goroutine 归零及 Transport 关闭成功。实际请求读取约 4.4 秒、响应写入约 4.6 秒，接近 Go 原 10 秒期限；这只证明本次进度与回收，不能反推 v5 原红的原因。上述 native 首次分配错误发生在信用队列首次创建，不作为晚期响应超时的解释。

## 双目标独立样例容量

| 目标 | 未签名 app 大小 | 原 factory 槽 | 剩余 |
| --- | --- | --- | --- |
| ESP32-C3 | 1033136 B | 1048576 B | 15440 B |
| ESP32 | 988272 B | 1048576 B | 60304 B |

采用原公开非空编译输入、精确 SDK／lwIP／QUIC 依赖、原配置和分区；新 QUIC 与证书源码实际编译。官方镜像解析、分区解码、依赖守卫与实际 cJSON 目录摘要核对通过。Component Manager 仅在私有目标源码更新生成的 manifest_hash 和 managed 组件，有效组件锁不变。没有扩大分区、启用 LTO、删除认证或把旧 app 当成新构建。

## 证据与未完成边界

受限原始日志和完整清单保留在本机证据区。v6 源清单 `ad89aeebaf8eee5c852241d61f01641e584cc742eed3a6a748f1489206f39e7d`；native 故障回归收据 `764385210e38ac216e26c26f2f803805556ed1cf4746ba553e4f03faa7882348`；sanitizer 收据 `deecd1550e20ec1b201b5bdd1f2ecc1139f80847ea00098c4d8e96bb5e4915af`；v6 完整 C 日志 `c5222aafb06289fc6adf6b61975696f4f2924c0ea45190d7707a21183a8ed41b`；v6 双目标 SDK 收据 `1f5061b510184b315bd2d7cc89d81ddb33f723cae46b1b692db4c9ed79a7440e`、完整清单 `d8f9348457ed719fd510aa2302a633f6360d938a030fd71ad984696155fabae9`、独立来源核对 `71f7f48e9ff112a0a738c863a72ccd6dd436ec78ad1269b7ad628829a04a0c14`。公开记录仅给出定位摘要：v4 源 `8f8269766a907adb0849e6b736b2c7300cbd1bbedfa5cdbc73f25ace942a336a`；v4 C 红日志 `54a247d7fca2fa3e4f866c31d65316a1fe5da853ba3e3654eff495b2cafc54e5`；v4 SDK 收据 `bbeb05f6a1e113e2b0a5867461512c2c58b5892d1fc987d2e3046bb98dede35d`；v5 源 `e2933d85d449e59bd2750a9905f7377a156333c9b55f6ca7fc75d766fa522302`；v5 C 红日志 `d68351f95c7275dab6be5c6afee8c6571c2d6639eba7dc3bfa82a3aef288aded`。原 v2 失败、纯诊断、针对修正与后继完整矩阵分别保存，不改写原结果。

历史 [扩展软件检查点](xtcp-candidate-software-20261003.md) 的 52 项结果仍绑定历史输入，不能直接继承为当前组合资格。后续设备验收仍以[Base 原生业务与固件 OTA 计划](https://github.com/darren-you/esp-base/blob/master/docs/operations/ota-allocation-diagnostic-checkpoint.md)的首版前置为准：异网 NAT、两目标实板、Base/MQTT/OTA 与原生业务组合资源、完整 native 生命周期与性能、Flash 成本与寿命、断电／72 小时及正式交付均未闭环。当前原生产品的内部堆／最大连续块／任务栈门分别为 16,384／24,576／1,024 B；本软件候选未取得这些实板资格。
