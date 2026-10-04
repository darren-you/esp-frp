# 固定官方 XTCP 边界复现

在本目录运行 `python3 run_official_fixtures.py`。入口固定读取未替换的官方 `github.com/fatedier/frp v0.71.0`，先执行 `go mod verify`，再复制其完整源码到临时目录，仅加入测试文件。原始官方源码、生产配置和设备均不修改。所有地址都是随机回环端口，所有密钥都是公开 fixture。

已实际复现的范围：

- UDP `MakeHole` 接受正确 SID/secret，拒绝错误 SID 和 secret。
- 官方 visitor 的真实 `QUICTunnelSession.Init` 与无 SID、代理或角色绑定的动态自签 QUIC 服务端交换数据。
- 官方 provider 的真实 `listenByQUIC` 将指定目标 UDP 地址之外的另一个来源送入真实 TCP 后端。该 peer 没有 provider secret 或 SID；严格 CA 客户端先对同服务端产生真实 X509 拒绝。
- 官方会合控制器的真实 `HandleVisitor` 拒绝错误用户的 PreCheck 和实际错误密钥，却在实际请求提供正确密钥时向 provider 通知该错误用户的非空 SID。
- 真实 `HandleClient` 拒绝不存在的 SID，却把错误代理名附到构造的活动 SID。此项是控制器方法级复现，没有声称已经通过完整已认证 FRPS 控制通道劫持会合。

成功连接要求攻击来源能触达 provider 的 UDP 并抢先进入其首个 QUIC 连接。这里没有证明任意 NAT 下的外网攻击，也没有证明异网打洞、数据绕过真实 FRPS 或任何 ESP 实板验收。源码推断、方法级复现、完整 host 消费链与设备结果分别记账。

修复候选唯一归属为 [`../../peer/frp`](../../peer/frp/candidate-development.md)，其 XTCP 信令和 P2P 协议已硬切，不能把与候选的互通称作原样官方互操作。普通官方 provider/STCP visitor/HTTP(S)/UDP 回归仍在原始官方测试模块执行。

## 正式 C 直连数据合同

[work_peer.c](work_peer.c) 使用正式 public peer factory 和统一 native stream，读取 fixture 提供的完整 canonical manifest，先校验本次 control/nonce/own-SPKI，reserved stream 0 上以真实 TLS exporter 验证相反角色的完整 69 字节 proof 及 FIN。provider 验完 visitor 才发送自己的 proof，visitor 先发后验。双方证明完成并释放 reserved owner 后才调用 `work_peer_init/step`；业务 stream 必须为 client bidi ID≥4。

[work_fixture.go](work_fixture.go) 必须从维护源 `peer/frp` 的 module 运行，实际导入该源的 `pkg/xtcpbinding.PeerTLS/ExchangeProof`。不替换本目录官方 module，不引入 runtime 测试 import。根 host CTest 的目标为 `xtcp_direct_work_peer`，也可执行：

```sh
cd peer/frp
go run -mod=readonly -race ../../tests/xtcp/work_fixture.go \
  -peer /path/to/xtcp_direct_work_peer
```

此 fixture 直接提供受控公开 manifest 文件，验证数据面，不声称覆盖 FRPS 已认证信令、控制对象撤销或真实 NAT。两角色各两条真实 300001 字节 TCP 流完成独立 FIN，要求 `requests=2 completed=2 failed=0 active=0`、双向字节均为 600002。provider 连固定真实 TCP 后端，visitor 在证明前已经持有两条实际 accepted socket，但不读取和转发业务。错 SID、proxy、角色、尾随和截断证明要求业务字节与后端 accept 均为零。额外真实 peer native credit=1 的正例要求第二条 accepted socket 在 `WOULD_BLOCK` 时保持 work 所有权；第三次 adopt 的 capacity 失败保持调用方 pointer，随后显式清理。
