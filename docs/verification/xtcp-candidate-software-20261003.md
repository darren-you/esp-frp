# XTCP 开发候选软件检查点（2026-10-03）

本次完成了协议扩展的软件验证，以及 ESP32-C3／ESP32 的完整 ESP-IDF 编译、链接和原 1 MiB factory 分区容量检查。正式 Mbed TLS 单次完整 CTest 矩阵 **52/52 通过，包含 XTCP 全链路和两项新增关闭回归**；OpenSSL 矩阵 **21 项通过**。两个目标最终镜像都保留 XTCP 控制器、NAT、peer QUIC、证书生成，以及普通 TCP/TLS/Yamux 的实际链接。

这些证据属于 0.3.0 开发候选，不构成设备验收。没有连接、刷写或操作设备；未触达 `mac-ci-2`。两目标实板、Base/MQTT 组合、异网验证及[Base 原生业务与固件 OTA 首版](https://github.com/esp-space/esp-base/blob/master/docs/operations/ota-allocation-diagnostic-checkpoint.md)闭环仍是后续验收前置。

[同名机器摘要](xtcp-candidate-software-20261003.json) 保存最终 99 项快照清单、公开编译输入全文、依赖身份、配置差异、实际 sdkconfig／制品 SHA-256、59 个必要链接符号和各轮结果。大型 ELF、map、原始日志保留在本轮仓外目录，不写入 Git。机器摘要中的阶段前置仅保存当轮原事实，不作为现役实施合同；当前设备前置采用上文原生业务与固件 OTA 计划。协议边界见[协议扩展合同](../design/protocol-extensions.md)与[流传输合同](../design/stream-transport.md)。

## 软件互测证据

| 入口 | 实际结果 | 原始证据 |
| --- | --- | --- |
| 最终正式 Mbed TLS／ASan／UBSan 单次完整 CTest | **52/52，通过；71.94 秒**；包含 `xtcp_client_upstream`（23.94 秒），无跳过 | `/tmp/esp-frp-r1-20261003-posix-close-ctest.log` |
| 前一轮 Mbed TLS／ASan／UBSan CTest，排除 `xtcp_client_upstream` | 49/49，通过；71.65 秒 | `/tmp/esp-frp-r1-20261003-final-ctest.log` |
| 前一轮单独 CTest `xtcp_client_upstream` | 1/1，通过；22.64 秒 | 已记录的工具 stdout，session `99837`；未另存原始日志文件 |
| 前一轮 `TestCClientFullCandidate -race`，同一公共 C peer 的详细全链路 | 8 个子例通过；Go 总计 22.609 秒 | `/tmp/esp-frp-cxtcp-full.log` |
| 正式 OpenSSL／ASan／UBSan CTest | 21/21，通过；5.37 秒 | `/tmp/esp-frp-extensions-openssl-final-ctest.log` |
| C／C++ 公共头与 extern-C 审查 | 36 项语法检查、37 项声明检查通过 | `/tmp/esp-frp-public-headers-20261003.log` |
| 外部父 scope C++ consumer，TRACE OFF／ON | 两组真实 configure、compile、C link 通过；未执行程序 | `/tmp/esp-frp-public-consumer-script-20261003.log` |

前一轮 49 项与独立 1 项不是单次 `50/50` 执行；保留它们作为历史证据。修正 QUIC 关闭边界后，最后 fresh host 全目标构建退出 0，并实际执行单次完整 52 项，包括全链路 C 客户端；此次没有排除或跳过 XTCP。独立 CTest 的 `LastTest.log` 已被后续矩阵覆盖，不能把详细 Go 日志标成这次 quiet CTest 的原始日志。公开头／外部 consumer 回归另计，不加入最终 52／21 项数量。

普通 FRPS QUIC TCP／UDP／STCP visitor 使用固定官方 FRP 的真实互测；XTCP 使用本仓维护的 [peer/frp 候选](../../peer/frp/candidate-development.md)，版本 `0.71.0-esp-frp-xtcp.1`，基于官方 v0.71.0、SHA `4a23aa181c1d7e28eecaa8216024ed753b9d27c8`。维护 Go 源码另以 359 项 `*.go` 及 `go.mod`／`go.sum` 的完整文件集合冻结，SHA-256 `7f6bace157e8d70876ee1954a09d65a219eff69faa1b84c4fafeebc1e5992984`；清单纳入同名机器摘要。该值使用按路径排序的 JSON 数组、对象键排序、紧凑 UTF-8 编码后 SHA-256，算法与 C 构建输入的行式清单不同。

原样官方版本没有 `esp-frp-xtcp/1` 的控制身份及双方绑定合同，不能将候选结果写成未修改官方 XTCP 互操作。

XTCP 全链路由 [Go 测试](../../peer/frp/test/xtcpbinding/c_client_test.go) 启动真实候选 FRPS 和两个回环 UDP STUN 服务，再调用 [C 公共客户端 peer](../../tests/xtcp_client_peer.c)。provider 与 visitor 两个正例均经过严格 FRPS TLS／Token、当前 control 身份、STUN 映射、nonce／HMAC 探测、同 fd peer QUIC、双方证书验证与 exporter 证明，之后才开放业务。每个正例检查两条同时活动业务流，各自完整往返 300001 字节，并检查停止 EOF、原 worker 上重启、时钟失信撤销和 fd 基线回收。

另外六个实际入口负例分成两组：前三例为错误 Token、错误服务端 hostname、未可信时钟（`TIME_UNTRUSTED`），实测控制建立失败并同步停止、清理；这组三例没有 backend 计数 fixture。后三例为 visitor 的错误 secret／user／target，主 control 达到 READY，独立 XTCP 返回 `WORK_REJECTED`，实际 backend 连接计数保持零。主 READY 不等于 peer 已打通。host Flash fixture 和 worker 验证不能代表实板 Flash 或 FreeRTOS 资源。

NAT 接受上游原生合法模式 `0..4`。本轮修正此前错误拒绝 mode `0` 的条件，保留 `>4` 拒绝；不是协议回退。单测用真实双 UDP socket 交换完整 SID／nonce／HMAC，双向 PUNCHED 后保留原 fd，并检查错误 nonce 不续期、超时清理及 mode `5` 拒绝。fixture 以真实单调时钟推进有界收发，独立 ASan／UBSan 重复 30/30 次通过；日志 `/tmp/esp-frp-xtcp-nat-mode-zero-repeat.log`。`ListenRandomPorts` 要求额外监听 socket 的情形仍明确拒绝，不能借此声称所有 NAT 类型可用。

## 冻结输入与工具链

最终两个目标各自拥有独立源码、`managed_components`、sdkconfig 和 build 目录，避免 Component Manager 的目标解析相互覆盖：

- 最终：`/tmp/esp-frp-extensions-xtcp-final-targets-20261003/{esp32c3,esp32}/`。
- 初次失败与第二轮：`/tmp/esp-frp-extensions-xtcp-targets-20261003/{esp32c3,esp32}/`。
- 单选项隔离实验：`/tmp/esp-frp-extensions-xtcp-targets-20261003/esp32c3-save-restore/`。

最终 **source snapshot manifest 99 项** SHA-256 为 `1a9028df87965a40d487bce4a5cf6a46ee6f16cedf4066959cae179d6f349416`，逐项与本仓当前事实源一致。这是构建输入快照清单，包含 sample／tools README，不等同于 99 个编译单元。按相对 POSIX 路径排序，以 `SHA256 + 两空格 + path + LF` 拼接后再计算整体 SHA-256。排除 Component Manager 会按 target 更新的两份 `dependencies.lock`；两目标实际解析锁的 SHA 独立保存在机器摘要。含两份声明锁的 101 项声明快照 SHA 为 `4502617dfa51f6341fd09ab2536db354e4131f6dec5bfa5be994aa6310bb2a00`。

最终快照已包含 C3 专属默认选项、四份公共头的所有权注释、host CMake 的 `PUBLIC EFRP_LAB_TIMEOUT_TRACE` 传播，sample README 的最终容量事实，以及 QUIC 平台关闭所有权修正和两项 host CTest。四份头仅改注释，PUBLIC 宏传播仅影响 host TRACE ABI，两项新增 CTest 也只在 host 分支；两目标完成必要重编译／重新配置并再次通过容量检查。

| 依赖 | 本轮固定身份 |
| --- | --- |
| 唯一 ESP-IDF checkout | `/Users/darrenyou/.cache/darren-space/esp-idf-578cf89`；`578cf89c343e388db43ba1f4ddcd602fedcb763c` |
| 该 SDK 的 lwIP | `2758df4cd3666b3b2a5b53830148379326425c0d` |
| ngtcp2 v1.25.0 | `f9e9ff01ad2c8116bc09de4f644b0028a61486a6` |
| Picotls | `f07f1c8c68b237f1468bc1f1fe1b68aba3ff23b4` |
| IDF Python 环境 | `idf6.1_py3.14_env` |
| C3／ESP32 交叉工具链 | `esp-15.2.0_20251204`，GCC 15.2.0 |
| host Mbed TLS | 4.1.0；依赖归档校验见 [quic-lock.json](../../quic-lock.json) |

身份守卫直接消费 [sdk-lock.json](../../sdk-lock.json)／[quic-lock.json](../../quic-lock.json)和 [tools 入口](../../tools/README.md)，未改写依赖或绕过 checkout 校验。

公开编译输入为 `/tmp/esp-frp-extensions-xtcp-final-targets-20261003/public_compile_inputs.h`，SHA-256 `38c8d7ac3ed9e8efd316af5fbeaf0004fcae239e0aa270cc4b7b8399a9fe5a96`。它使用非空假 Wi-Fi 密码、假 Token 和 `.invalid` hostname，按真实 `inputs_valid()` 条件通过；CA 是公开的编译占位文本，不能用于实际 TLS 信任。输入文件原有“联网前停止”注释不描述这一份非空变体的实际校验结果；本轮仅编译，未运行它。样例配置选择默认 TCP，但下面的链接审计确认完整 XTCP／证书路径真实保留，不能声称在 ESP 上运行过 XTCP。

## 首次失败、真实容量失败与隔离实验

第一次两目标均在 GCC 15 的 `-Werror=misleading-indentation` 失败：`xtcp_codec.c` 五处（当时行 151、204、205、208、209），`quic_peer.c` 一处（当时行 33）。没有生成主应用 ELF／bin，未到容量门禁。对应 `build.log`、`build-keep-going.log` 和初次源码归档保留在初次目录；摘要为 `/tmp/esp-frp-extensions-xtcp-targets-20261003/build-results-generation-1.json`。修正实际代码布局，不放宽 warning。

第二轮已修布局、真实错误响应 shape 及原生 mode 0，并完成完整编译／链接。原分区 factory 为 **1048576 字节**，真实 bin 容量结果如下：

| 第二轮目标 | bin 字节／十六进制 | 编译／链接 | 原 factory 容量 | `idf.py build` 退出 |
| --- | --- | --- | --- | --- |
| ESP32-C3 | 1057568／`0x102320` | 通过 | **超出 8992 字节** | 2 |
| ESP32 | 988256／`0xf1460` | 通过 | 余 60320 字节 | 0 |

第二轮 99 项快照 SHA 为 `84d61f0db20876876d67f9a7e9d94dc10f2412c0aacc0da8efcbdd78d7a2f2f7`。摘要 `/tmp/esp-frp-extensions-xtcp-targets-20261003/build-results-generation-2.json` SHA-256 为 `738b19a79d538c6336377f65496f14f4b392b3f41c53d3b225a3fc61a6c81def`。该失败保留，不用后续通过覆盖它，也不能以 `idf.py size` 返回成功代替应用分区检查。

C3 的隔离实验复制第二轮源码与实际 sdkconfig 到新目录，只改变一个有效 Kconfig 值：`CONFIG_COMPILER_SAVE_RESTORE_LIBCALLS` 从关闭变为 `y`。所有其他有效配置逐项相同，无 LTO，没有删 TLS／QUIC／XTCP／Yamux 功能，也没有修改日志、队列或业务缓冲。

固定 SDK 的 `Kconfig:667–677` 和 `docs/en/api-guides/performance/size.rst:92` 给出该 RISC-V 选项：以 save／restore libcall 收敛函数序言／尾声，减少代码尺寸，代价是略低的性能。`tools/cmakev2/project.cmake:231` 实际加入 `-msave-restore`；`components/esp_libc/src/system_libs.lf:8` 把这些 libgcc helper 置于 `noflash` 段。实验 ELF 的 26 个 helper 全部落在 `.iram0.text`，区间 `0x40380000..0x4038edbe`，没有因 Flash 不可访问时的 helper 取指而改变合同。

隔离实验实际构建退出 0，bin **1033056／`0xfc360`**，比原第二轮减 **24512 字节**，原 factory 余 **15520 字节**。59 个必要符号全部保留且长度非零。实验 bin SHA-256 `8e506a2ced5b05bbc7f11bcc3e6119b37ad29e8e4c8cbce8cc1c3b3f6517cce3`，ELF SHA-256 `2eefb1d9047ea87607ea4fc79c8516675508d8922664e8eaa2f24a192a0ad3fa`；完整配置差异、IRAM 地址和符号清单见机器摘要及仓外 `experiment-results.json`。这是隔离实验制品，与最终 canonical 镜像分开记录。

## QUIC 平台关闭所有权修正

最后审查发现旧 QUIC cleanup 在 POSIX 的 `close()` 失败后保留 fd 并重试，与已有 connect／UDP／NAT 的平台合同不一致。同一真实 fixture 注入失败后让 OS 复用该编号，旧源码第二次 cancel 实际关闭了 foreign UDP socket，`fcntl` 存活断言失败；并非仅静态推测。

修正后 POSIX 只调用一次 close，随即清掉 fd 所有权并保留 errno 诊断；重复 cancel／destroy 不触碰真实复用编号。ESP-IDF 分支继续在暂时失败时持有原 fd 并返回 `WOULD_BLOCK`，直到真实 close 成功才释放。测试中的 IDF 分支使用 host 专用编译宏和真实 OS fd，不代表实板调度或压力验证。修改不改变协议、关闭报文期限或 IDF 的既有行为。

新增 `quic_cleanup_posix`／`quic_cleanup_idf` 两项 ASan／UBSan CTest 实际 2/2 通过，0.95 秒；旧源码为 1 项通过、POSIX 项失败。证据 JSON `/tmp/esp-frp-quic-cleanup-regression-20261003.json` 包含旧／新源码、同一 fixture 的 SHA 和两份 raw 日志，已纳入同名机器摘要。stage 6 的原 SDK 镜像、sdkconfig、源码 tar、peer 二进制和日志独立保留在 `/tmp/esp-frp-extensions-xtcp-final-targets-20261003/stage-6/`，不覆盖历史证据。

## 最终 canonical 两目标结果

实验结论落实到 [C3 专属 sdkconfig defaults](https://github.com/esp-space/esp-frp/blob/4e6a80904e054735981b160348bb7380bc9b8003/examples/tcp_proxy/sdkconfig.defaults.esp32c3)。ESP32 默认配置不加该 RISC-V 选项。随后从最终源码生成两个独立快照与 fresh sdkconfig，再编译完整应用；公共头注释、CMake／README 和最后 QUIC 关闭修正同步后重新编译并核对产物。

| 最终目标 | 编译／链接 | bin 字节／十六进制 | 原 factory 余量 | 原容量门禁 |
| --- | --- | --- | --- | --- |
| ESP32-C3 | 通过 | 1033056／`0xfc360` | 15520 字节／`0x3ca0` | 通过；退出 0 |
| ESP32 | 通过 | 988256／`0xf1460` | 60320 字节／`0xeba0` | 通过；退出 0 |

最终实际 sdkconfig 相对第二轮逐项比较：C3 唯一差异是 `CONFIG_COMPILER_SAVE_RESTORE_LIBCALLS=y`，ESP32 无差异。两目标保留 size 优化、silent assertions（断言／abort 仍有效）、IPv6、原 socket／Wi-Fi／TCP 缓冲配置和 X509／CRT／PK／ASN1 的四项 WRITE 配置。SoftAP 在原完整输入中已关闭，本次容量实验未再次修改它。所有第一方生产 C 编译命令均核对：C3 使用 `-msave-restore`，ESP32 不使用，全部无 `-flto`。

从最终 ELF 使用对应 `nm -S --size-sort` 核对两目标各 **59 个必要符号**，全部非零 `T/t/D`：包括 XTCP controller／NAT／codec／绑定 HMAC 和双方 proof、FRPS QUIC 与 peer factory、运行时证书生成、`verify_signature`／`verify_chain`／`sign_certificate`，及普通 `efrp_create`、TCP connect／TLS、work、Yamux adapter／读写／tick。唯一数据符号是 peer ClientHello 注册表 `D`；其余为真实代码。C3 最终 26 个 save／restore helper 仍全在 IRAM。检查不是以头声明或静态库存在代替实际链接。

[原 partitions.csv](https://github.com/esp-space/esp-frp/blob/4e6a80904e054735981b160348bb7380bc9b8003/examples/tcp_proxy/partitions.csv) 未修改：factory offset `0x10000`、size `0x100000`；独立 `frp_scratch` offset `0x110000`、size `0x10000`。CSV SHA-256 `3c2266004b96abda28f9a68e799521ce4e3f747e7d3ce90b7e666414f53d1cf4`；初次、第二轮、隔离实验、最终两目标的实际 `partition-table.bin` SHA-256 均为 `5f900b9e9930afe0f5ad7742849f0835a1d7ccd02c392fe34ab2130c7ff249d6`。没有扩大分区。

最终主要制品 SHA-256：

| 目标 | 文件（目标根相对路径） | SHA-256 |
| --- | --- | --- |
| esp32c3 | `sdkconfig` | `643e1dfb87699adf498ca64ad6f5b76c2af2d7e13e74512e4c74ab4b7bae5a0d` |
| esp32c3 | `build/esp_frp_sample.bin` | `b958ff897e2b8b002cb015e1e1552cb392d83aa58fe01b6428bf6fc2b941a5dc` |
| esp32c3 | `build/esp_frp_sample.elf` | `1c25025fb57ec43efd47cbbd1d47fd61771a88cd3a6d7eebf410f68cea053df7` |
| esp32c3 | `build/esp_frp_sample.map` | `14b0817a982fddbb3e8a0b810fc28d478761fd42ac7e04bf6f0989d0fdb5ae4c` |
| esp32 | `sdkconfig` | `3ab778b0aa3a090057c822f133f7a32489672308b01d424bf1df8bed3a3083ef` |
| esp32 | `build/esp_frp_sample.bin` | `3ba49c152d91fba112b4365e42fe9c29d27c449b9d45d2db602a3babbaaa694b` |
| esp32 | `build/esp_frp_sample.elf` | `45ecfb28f4ab006c855c6ed176c3cf58eec0348b4e0f6b21c6ace09db3ed55d7` |
| esp32 | `build/esp_frp_sample.map` | `df163888be2b43c0dfb0dd632d556a937f341e37242f1765bb006ed0fa57f510` |

每个最终目标根还有 `build-final.log`（公共头重编译）、`build-final-cmake.log`（最后 CMake 重新配置）、`build-final-snapshot.log`（stage 6 容量复核）、`build-final-close.log`（最后 QUIC 关闭修正的重新配置／编译／链接和容量检查）、`linked-symbols.txt`、`elf-sections.txt`、`size-memory.json`、`size-components.json` 和 `build/compile_commands.json`。实际 sdkconfig、bootloader、解析依赖锁、日志及这些审计输出的 SHA 也保存在机器摘要。

## 复现入口

以下 host 命令复用最终正式配置及二进制；从新目录构建时按 [tests/README.md](../../tests/README.md) 准备同一冻结依赖、Mbed TLS／ASan／UBSan 配置。两种 crypto 配置分开执行、分开记录；Mbed TLS 最终完整矩阵使用 `-j4`：

```bash
ctest --test-dir /tmp/esp-frp-r1-20261002-mbedtls -j4 --output-on-failure
ctest --test-dir /tmp/esp-frp-extensions-openssl-final --output-on-failure
```

详细 XTCP race 互测入口（最终二进制可再次执行；保留的 22.609 秒原始日志来自前一轮）：

```bash
cd /Users/darrenyou/darren-space/tooling/esp-frp/peer/frp
EFRP_XTCP_CLIENT_PEER=/tmp/esp-frp-r1-20261002-mbedtls/xtcp_client_peer \
  /opt/homebrew/opt/go/bin/go test -mod=readonly -race -count=1 -v \
  -run '^TestCClientFullCandidate$' ./test/xtcpbinding
```

最终 peer 二进制 SHA-256 为 `84bec342044db7fb9560d1aa38ea217a23401f0317cdd0124ffe1ea4e929d0b8`；最终 CTest 包含此公共 peer 的完整 XTCP fixture。前一轮 22.609 秒 verbose race 日志使用的旧 peer SHA 为 `b84010867bf95b8a7f7b3cab6f9e98a4ea7a7b6079b3bde9e8515d132e003816`，旧二进制已保存在 stage 6 archive，两个执行结果分开记录。外部 consumer 回归的本轮实际参数如下；该 Mac 的 CMake 不在默认 PATH，因此显式传入。它在临时父工程中分别验证 TRACE OFF／ON 的公开 ABI，之后清理临时目录，不运行构建出的程序。

```bash
python3 tests/public_consumer_contract.py \
  --cmake /Users/darrenyou/.espressif/python_env/idf6.1_py3.14_env/lib/python3.14/site-packages/cmake/data/bin/cmake \
  --cmake-prefix-path /opt/homebrew
```

下面命令用于仓外最终双快照的 IDF 构建。新建复现目录时分别复制所需输入；两个目标必须独立源码／Component Manager 目录，使用机器摘要中相同公开 input 内容。命令没有 `flash` 或设备访问：

```bash
export PATH=/Users/darrenyou/.espressif/python_env/idf6.1_py3.14_env/bin:$PATH
export IDF_PY_BUILD_JOBS=6
source /Users/darrenyou/.cache/darren-space/esp-idf-578cf89/export.sh
cd /Users/darrenyou/darren-space/tooling/esp-frp
python3 tools/sdk.py check --path "$IDF_PATH"
python3 tools/quic_sources.py check \
  --ngtcp2-path /tmp/esp-frp-quic-ngtcp2-git \
  --picotls-path /tmp/esp-frp-quic-picotls-git
for target in esp32c3 esp32; do
  target_root=/tmp/esp-frp-extensions-xtcp-final-targets-20261003/$target
  idf.py -C "$target_root/esp-frp/examples/tcp_proxy" \
    -B "$target_root/build" -D SDKCONFIG="$target_root/sdkconfig" \
    -D IDF_TARGET="$target" \
    -D EFRP_NGTCP2_SOURCE_DIR=/tmp/esp-frp-quic-ngtcp2-git \
    -D EFRP_PICOTLS_SOURCE_DIR=/tmp/esp-frp-quic-picotls-git \
    -D EFRP_SAMPLE_INPUTS=/tmp/esp-frp-extensions-xtcp-final-targets-20261003/public_compile_inputs.h \
    build
done
```

## 尚未闭合的验收

C3 容量只余 15520 字节，已通过本轮完整镜像的原门禁，但不是未来新增功能的容量保证。官方选项的性能代价尚无实板测量，不能从代码尺寸推导 CPU 时序、worker 堆栈、最低 heap、QUIC 长期运行或 Flash 停用窗口的资源余量。

回环 STUN／peer 正例证明实际软件入口和身份／所有权／清理链路，不证明跨运营商、真实 NAT 路由器或异网可用性。两目标硬件、异网矩阵、Base/MQTT 组合及原生业务首版前置仍未闭环；本检查点不放行设备验收或发布。后续按当前 typed API 与固定依赖实施，不增加自动协议回退。
