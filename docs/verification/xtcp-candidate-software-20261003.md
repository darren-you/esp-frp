# XTCP 开发候选软件检查点（2026-10-03）

本文维护稳定技术合同、设计理由与固定验证方法。任务目标、动态清单、当前结论和阶段证据统一维护在根仓 Issue：[ESP FRP 后续协议扩展](https://github.com/darren-you/darren-space/issues/49)。原执行记录按该 Issue 的迁移快照链接追溯，不在本文维护第二份进度。

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

## 软件与实体证据边界

回环STUN／peer验证协议入口、身份／所有权和清理方法；异网NAT、两目标实体、Base/MQTT组合、CPU时序/堆栈/heap/QUIC长稳/Flash停用窗口必须分别以实际场景核验，软件容量不作未来新增能力保证。 typed API及固定依赖不会引入自动协议回退。
