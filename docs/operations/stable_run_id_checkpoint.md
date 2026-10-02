# 稳定 FRP run ID 开发检查点

2026-10-02，本检查点记录组件 0.2.0 的源码与 host 验证；C3/Base 组合实板和容量尚未通过。

## 问题与合同

Base 五能力实验在联合 OTA 成功后通过 MQTT 重启，第三 boot 的 FRP 被官方 FRPS 以同 client_id 仍在线拒绝。旧控制连接未注销时，新实例使用服务端新生成的 run ID，不能接管相同设备身份。该拒绝是 LOGIN_REJECTED，不能由此认定为内存不足。

依据[官方 v0.71.0 注册控制连接](https://github.com/fatedier/frp/blob/v0.71.0/server/service.go)，客户端可提交自己的 run ID；服务端先验证 Login，再替换该 run ID 的旧控制连接并等待清理。组件可选字段从 previous_run_id 硬切为 `run_id`，无旧字段别名，限定为 64 UTF-8 字节；组件及 Login 产品版本为 0.2.0。调用方可提交已有稳定设备 UUID，或上次已鉴权的服务端 run ID；不提交则继续请求服务端生成。

请求值与已鉴权状态分开保存。create 深拷贝请求值，`status.run_id` 在成功 LoginResp 前保持为空；同实例后续重连沿用已鉴权结果。严格 TLS、Token、注册和首次认证 Pong 门保持。没有新增 NVS、身份生成或凭据更换机制。实际业务身份应使用服务端接受的可打印字符串；Base UUID 是有效 ASCII，不放宽服务端校验。

## 已验证的软件边界

- 官方 Mbed TLS 4.1.0／PSA 后端的 ASan/UBSan 23 项 CTest 全通过，301.18 秒；产品版本调整后六项握手／客户端回归通过，38.84 秒；新增响应长度边界后两项握手回归通过，2.11 秒。
- 独立 TSan 构建的两项客户端测试通过，42.02 秒，ASan 与 TSan 分开构建。
- 官方 FRPS 冷实例回归暂停旧客户端进程，保留服务端控制连接。错误 Token 新实例被拒绝，旧进程恢复后仍 READY；正确 Token 的独立新进程以相同身份在旧连接到期前登录并 READY，不继承旧进程 RAM 或 NVS。
- 配置检查覆盖 64 字节请求接受、65 字节拒绝、未鉴权状态为空、深拷贝及资源失败清零；握手检查拒绝超过 64 字节的 LoginResp。
- Base owner 使用最终新头的 ASan/UBSan 回归通过，核对请求 run ID 与既有 client_id 相同；生命周期 mock 不代表实板端到端结果。

## 尚未完成

固定 SDK 双目标编译、Base 精确依赖锁升级、新签名实验镜像和 C3 联合 OTA／MQTT 重启后的 FRP 恢复继续执行。先前失败证据保持不变。来源下载最低普通 heap 6500 B，48 KiB 门仍未通过；本次身份修正不作为容量优化。ESP32 实板、完整负载、掉电和长稳继续开放。

接口与生命周期见[客户端合同](../design/client-lifecycle.md)与[握手合同](../design/control-handshake.md)。

## 固定 SDK 与 C3 联合续验

2026-10-02，相同运行源码的固定 SDK C3／ESP32 独立样例与 Base 双目标签名构建、官方验签、host 回归通过。Base `ffc88efbbb259b32ca75c944776ba77328f731b6` 使用已有 UUID 请求 run ID；C3 代表业务的一次 WRITE 联合 OTA、一次 MQTT restart 后，目标与第三 boot 均经实际 FRP 认证状态核验，十二项消息计数、卸载及 A／C／原代码字节核对通过。143 份实板索引为 `effd1620aa917549bd660eb246e00b050f48e80fc0747a630be06b80f2da2988`，此前 109 份失败保持；88 份来源下载均 MQTT／FRP ready，但最低历史 heap 4124 B，48 KiB 门继续失败。详细输入与恢复边界见[Base 联合检查点](https://github.com/esp-space/esp-base/blob/master/docs/operations/c3_five_capability_run_id_checkpoint.md)。

本库身份修正已获得该 C3 功能切片证据；最大负载、组合容量、ESP32 实板、掉电、长稳与生产仍未验收。不能把前文阶段性的未完成说明或本次功能成功解释为五能力总验收。
