# ESP32 32BIT-only AEAD 接收实验

本目录只在冻结五仓工程的仓外副本中装配实验。`prepare_qemu.py` 校验 Wi-Fi IRAM 两项关闭后的原 `sdkconfig`、已签名镜像和真实 AEAD fixture 摘要；复制工程，覆盖本分支 FRP 源码，加入 `word_capacity_probe.c`。输出目录须不存在。脚本不调用 `flash`，签名测试键只在构建机原仓外位置使用。

在有固定 ESP-IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c`、官方 Xtensa QEMU、已冻结 `/private/tmp/esp32-auth-wifi-iram-off-exact-20260927/probe` 及本分支独立副本的 mac-work-1：

```bash
python3 tests/esp32-iram-aead/prepare_qemu.py \
  /private/tmp/esp32-auth-wifi-iram-off-exact-20260927/probe \
  /private/tmp/esp-frp-iram-aead-source-20260927 \
  /private/tmp/esp32-frp-iram-aead-qemu-20260927/probe
export PATH="/opt/homebrew/bin:$PATH"
export IDF_PATH=/Users/darrenyou/.cache/darren-space/esp-idf-578cf89
source "$IDF_PATH/export.sh"
idf.py -C /private/tmp/esp32-frp-iram-aead-qemu-20260927/probe/firmware \
  -DIDF_TARGET=esp32 -DESP_BASE_CONTAINER_BINDING_PROBE=ON \
  -DEFRP_LAB_ESP32_IRAM_AEAD_RX=ON build
espsecure verify-signature --version 1 \
  --keyfile /private/tmp/esp32-auth-capacity-20260927/test-key.pem \
  /private/tmp/esp32-frp-iram-aead-qemu-20260927/probe/firmware/build/esp_base.bin
python3 /private/tmp/run_esp32_wifi_iram_qemu.py \
  /private/tmp/esp32-frp-iram-aead-qemu-20260927/probe/firmware \
  /private/tmp/esp32-frp-iram-aead-qemu-20260927/qemu.log 45
```

`run_esp32_wifi_iram_qemu.py` 是上一轮 [Container 五仓探针](https://github.com/esp-space/esp-container/blob/da1a69e63fa51721a8f6e3a7e5838df513c1e2b4/docs/operations/esp32-exec-pool-qemu-probe.md)使用的限时官方 QEMU 入口。需沿用原实验目录中的脚本；本仓不复制 QEMU 启动逻辑或签名键。QEMU 会生成仓外合成 Flash／eFuse 镜像，不写物理设备。

同一次 Base READY + 64 KiB ABI 2 guest 存活窗口，原分块 reader 先测 4 KiB、坏 tag 和 64 KiB；随后新 reader 对同一密文 fixture 测 4 KiB、4 KiB 坏 tag、64 KiB、64 KiB 坏 tag。每个块仅在密文到达时请求 4 字节对齐的 `MALLOC_CAP_EXEC | MALLOC_CAP_32BIT` 内存，拒绝共享 D/IRAM 或 byte-accessible 地址。日志逐块记录地址、`MALLOC_CAP_8BIT` 与 EXEC／32BIT 池读数，释放前用 32 位读取核对清零；认证后通过独立字节缓冲逐字节核对交付。

实验结果、收据与脱敏日志见 [运行记录](../../docs/operations/p6-frp-esp32-iram-aead.md)。直接 reader 探针不包含真实 FRP 会话、TLS 和网络；这些组合语义由实验模式 host 官方协议矩阵验证，实板仍未验收。
