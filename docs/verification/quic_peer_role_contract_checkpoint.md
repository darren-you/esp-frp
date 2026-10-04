# XTCP 唯一角色证书合同检查点

## 发现与修改

2026-10-04 对冻结的扩展候选进行审查，发现 C peer 检查仅要求包含角色 DNS SAN 和角色 EKU。同一 P256 密钥签出的正常证书增加第二个 DNS SAN 或第二个角色 EKU 后，原 C 检查仍返回 `EFRP_OK`，Go 检查拒绝。正常角色证书和错误角色证书的结果原本一致。此证据说明双方对唯一角色证书的准入合同不同，不证明业务授权被绕过。

C 的共享 peer 证书检查现在要求 SAN 序列只有一个固定角色 DNS，EKU 序列只有一个对应角色 OID。原有真实日期、自签名、P256 和 SPKI pin 检查保持；普通 FRPS CA 验证入口没有改变。

继续用真实自签证书核对 Go，发现 `crypto/x509` 的公开 SAN 列表不保留 `registeredID`、`otherName`，未知 EKU 也位于独立的 `UnknownExtKeyUsage` 字段。原检查因此接受角色 SAN 加这两类额外身份，以及角色 EKU 加未知 OID。Go 现在用官方 `encoding/asn1` 解码原始 SAN 扩展，要求只有一个 primitive DNS GeneralName，且内容与固定角色名相同；同时拒绝任何未知 EKU。检查仍在已有 `ValidateCertificate` 中，由信令准入与 `PeerTLS` 共同消费，没有平行证书解析器或新身份链路。

## 本次软件证据

- 公共 Go `NewIdentity` 生成当前 UTC 下有效的临时 P256 角色证书；用同一私钥实际签出额外 SAN、额外 EKU、错误角色及未知扩展变体。原 C/Go 对照的四个附加项不一致，行为检查自然退出 `1`。修复后两角色的十四份真实签名输入全部一致，检查自然退出 `0`。
- 新 `quic_peer_role_contract` 使用正式 C opaque PSA identity factory 和官方 Mbed TLS writer，分别为 provider/visitor 签出正常、额外 SAN、额外 EKU、错误角色四种证书。原生产 C 自然退出 `1`，修复后自然退出 `0`；两次均在完成 identity 释放后退出，不把 assertion abort 或超时当作行为红。
- Go 新 `TestPeerCertificateExactRoleExtensions` 对两角色分别覆盖未知 EKU、`registeredID` SAN、`otherName` SAN，先核自签名与同一 SPKI。原生产代码六例全部错误接受，定向测试自然退出 `1`；修复后新用例及既有角色、usage、pin 反例自然退出 `0`。
- C 微型检查和新增 C 用例实际以 ASan/UBSan 编译执行；新增 C 用例按 `-Wall -Wextra -Werror -Wconversion -UNDEBUG` 语法检查退出 `0`。

Mbed TLS 输入是官方 4.1.0 完整发布包，SHA-256 为 `377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10`。解包的 3900 个普通文件与已验证公开 host 库的源码逐字节一致；本次链接的是该 host 库的私有复制件。Picotls 输入来自锁定 `f07f1c8c68b237f1468bc1f1fe1b68aba3ff23b4` 的官方源码归档。本次微型入口直接编译正式 checker、wrapper 与 identity 源码，不修改正式依赖 guard，不把归档伪装成 Git checkout。

本次新增 C 用例已登记到正式 CMake。上述结果是微型 host 入口和 Go 定向入口的实际结果；本检查点尚未运行完整 CMake peer 回归、双目标 SDK 构建或设备验收。此前[扩展软件检查点](xtcp-candidate-software-20261003.md)保留其原始输入和证据，不自动给本次新源码 SHA 授予这些资格。proof 取消的真实 QUIC 回归由资源 owner 修复候选另行提供，不用本证书用例代证。

## 正式入口

准备真实精确依赖并完成正式 host 构建后，运行 `ctest --test-dir <host-build> -R '^(quic_peer_role_contract|quic_peer_security)$' --output-on-failure`。Go 在 `peer/frp` 运行 `go test -mod=readonly -count=1 -run '^(TestPeerCertificateExactRoleExtensions|TestExplicitCertificateRoleUsageAndSAN|TestPeerCertificatePinAndRoleRejectBeforeHandshake)$' ./pkg/xtcpbinding`。证书在测试当次生成，不读取生产凭据或固定历史日期。
