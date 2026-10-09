# FRP 会话唯一 Flash reader 与真实 scratch provider 候选

本收据对应 2026-09-27 的 FRP 独立候选，基线为 `ad539009c946d3a7fbbc1d133cf8c1279db33daa`。会话已硬切到唯一 `efrp_aead_flash_reader_t`，`efrp_config_t`、client 与 session 全链要求真实 store；旧 RAM reader 实现及公开 API 已删除。IDF provider 位于 FRP 源仓，Base 可用既有 storage owner 接 `with_owner`，独立 TCP 样例使用自己的真实 `frp_scratch` 分区与无竞争 owner。本文数字属于独立样例，不能替代 Base 签名产品的 `app_check_size`。

## 软件合同与测试

- `efrp_idf_flash_store_bind` 核对固定 label `frp_scratch`、data/undefined、调用方给出的精确 offset、`0x10000` size、4 KiB erase size、可写且未加密；启动必须先 `recover`。小于等于 4 KiB 的控制记录不碰 scratch。
- `recover`、`begin`、`write`、`read` 每次短借调用方 owner；provider 要求 owner 回调恰好执行操作一次，且不能吞掉操作错误。写入分块回读。owner 在 64 KiB 大记录的 begin、写入或窗口复读中被 OTA 占用时安全失败，清零 reader 密钥和窗口。
- `clear` 只在 provider guard 下撤销 RAM lease，不做物理 I/O，也不争用 OTA owner；下一次 `begin` 或 boot `recover` 擦除密文。guard 争用使 clear 失败时保留隔离 lease，`session_destroy` 保留 handle 供重试。
- OpenSSL host 完整 CTest **13/13**；独立 TF-PSA-Crypto host **13/13**；完整 Mbed TLS 与官方 FRPS host **21/21**。新增真实 provider 假分区测试在三种后端各自通过：64 KiB 成功记录、17 次全长复读（`17 × 65536` 字节）、旧 lease 拒绝、OTA 在写入及两次明文窗口之间抢 owner、错误 tag/短写/读错、clear 失败重试、owner 回调漏调/重调/吞错。官方 FRPS fixture 另覆盖会话内 64 KiB、坏 tag、clear 失败后重复 destroy。

Host 复现命令（从本仓根执行，外部依赖目录须先准备）：

```bash
cmake -S . -B /private/tmp/frp-flash-openssl -DBUILD_TESTING=ON -DEFRP_TEST_UPSTREAM_CRYPTO=ON
cmake --build /private/tmp/frp-flash-openssl -j 8
ctest --test-dir /private/tmp/frp-flash-openssl --output-on-failure -j 4

cmake -S . -B /private/tmp/frp-flash-psa -DBUILD_TESTING=ON \
  -DEFRP_PSA_SOURCE_DIR=/private/tmp/mbedtls-4.1.0/tf-psa-crypto \
  -DGEN_FILES=OFF -DEFRP_TEST_UPSTREAM_CRYPTO=ON \
  -DCMAKE_C_FLAGS=-DMBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
cmake --build /private/tmp/frp-flash-psa -j 8
ctest --test-dir /private/tmp/frp-flash-psa --output-on-failure -j 4

cmake -S . -B /private/tmp/frp-flash-mbedtls -DBUILD_TESTING=ON \
  -DEFRP_MBEDTLS_SOURCE_DIR=/private/tmp/mbedtls-4.1.0 \
  -DEFRP_TEST_UPSTREAM_CRYPTO=ON
cmake --build /private/tmp/frp-flash-mbedtls -j 8
ctest --test-dir /private/tmp/frp-flash-mbedtls --output-on-failure -j 4
```

## 固定 SDK 双目标样例

ESP-IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c`、内嵌 lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`。两目标均用 ESP-IDF v6.1、`espressif/cjson 1.7.19~2`、组件摘要 `e788323270d90738662d66fffa910bfe1fba019bba087f01557e70c40485b469`；C3/ESP32 的 `dependencies.lock` 文件 SHA-256 分别为 `0fe4da669276a376c99bef4186a610edab82d2b860889b9117972b5224974309`、`59fdbc48687a0f17e1306426b5a23397246e3dccd985514ea4621069fbba943d`。样例分区表：NVS `0x9000/0x6000`、PHY `0xf000/0x1000`、factory `0x10000/0x100000`、独占 `frp_scratch` `0x110000/0x10000`；最终分区二进制 SHA-256 为 `5f900b9e9930afe0f5ad7742849f0835a1d7ccd02c392fe34ab2130c7ff249d6`。

构建命令（每个 target 用独立 build 与 SDKCONFIG，`IDF_PATH` 指向上述固定 SDK）：

```bash
source "$IDF_PATH/export.sh"
idf.py -C examples/tcp_proxy -B /private/tmp/frp-c3-build \
  -D SDKCONFIG=/private/tmp/frp-c3-sdkconfig \
  -D IDF_TARGET=esp32c3 build
idf.py -C examples/tcp_proxy -B /private/tmp/frp-esp32-build \
  -D SDKCONFIG=/private/tmp/frp-esp32-sdkconfig \
  -D IDF_TARGET=esp32 build
```

默认空输入编译结果：C3 `0x1eb00`（125696 B，factory 余 `0xe1500`，SHA-256 `7deb64d987cfc61ccb7566b7f1becd7759d9405e35b2e38d26989e0ef095bf5d`），ESP32 `0x1c8a0`（116896 B，余 `0xe3760`，SHA-256 `781bd612768c62a524968f40b52e7d897530a6fc22a016601fba087422728f76`）。二者是**普通未签名样例镜像**；空输入被常量折叠，不能据其大小推断 FRP client/provider 实际链接成本。完整非空输入实验仍只用于编译，假 SSID、无效 CA 与 Token 从不刷机。

为了使 FRP 真入口被链接，仓外从 `inputs.example.h` 复制一个公开合成头，再把五个空值分别设为 `public-test-ssid`、`public-test-password`、`time.example.invalid`、`public-invalid-ca`、`public-test-token`（依次为 Wi-Fi SSID、密码、NTP、CA、Token），其余原样；输入 SHA-256 `8cb2b80f3d22a6caad21650208e87974393a0b0728f5b1356f40918a55a0ad20`。对两个 target 分别增加 `-D EFRP_SAMPLE_INPUTS=/private/tmp/esp-frp-size-public-inputs-20260927.h` 构建；ad539 基线在仓外只复制相同 `partitions.csv` 和两项 custom-table sdkconfig defaults，用同一输入、SDK、target 和 factory 几何比较。

| 目标 | ad539 非空基线 | 本候选非空样例 | 差值 | 当前 factory 余量 |
| --- | ---: | ---: | ---: | ---: |
| C3 | `0xd3c30`（867376 B） | `0xd54a0`（873632 B） | +6256 B | `0x2ab60` |
| ESP32 | `0xc7640`（816704 B） | `0xc8f30`（823088 B） | +6384 B | `0x370d0` |

当前两个非空 ELF 都包含 `efrp_idf_flash_store_bind` 与 `efrp_idf_flash_store_callbacks` 符号，`src/idf_flash_store.c.obj` 分别在双目标组件目录生成。C3 会话结构的 DWARF size 从旧路径 11280 B 到 15392 B，增加独立 4096 B Flash 窗口；这不是运行峰值。Base 的安全启动签名尾、双槽分区和 MQTT/OTA 与原生业务链接集合不同，必须在其精确产品输入上重新量测。

## 尚未验收

没有刷写或修改设备、Base 正式分区与 pin。未测真实 Flash 的 16 扇区擦除/写回读耗时和磨损、PSA 芯片运行时间、单轮最多 17 次全长复读对 8 轮 `session_step`、心跳/WDT 的影响、OTA owner 长持时的业务并发活性、断电恢复、C3/ESP32 双板真实峰值与完整清理。Host 假分区只证明接口和故障路径；后续 Base 接线须以精确签名产品镜像、官方验签、双槽门与实板回归决定容量。
