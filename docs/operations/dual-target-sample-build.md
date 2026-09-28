# FRP 独立样例双目标软件检查点

2026-09-26 在 `master@72631be94ed0703d060be45fae58e7bbb012f8af` 加本轮未提交的 ESP32 样例改动上，使用 mac-work-1 的仓外私有副本完成两次空输入构建。副本 basename 固定为 `esp-frp`，使 IDF 按真实组件名装配；最初用其他 basename 的配置尝试在编译前因找不到 `esp-frp` 组件而失败，改正路径后两目标分别构建成功。编译没有连接串口、刷写设备、注入 Wi-Fi/Token 或启动 FRPS。

每轮先以 `python3 tools/sdk.py check --path "$IDF_PATH"` 核对公开 ESP-IDF `578cf89c343e388db43ba1f4ddcd602fedcb763c` 与 ESP lwIP `2758df4cd3666b3b2a5b53830148379326425c0d`，均通过。使用独立 build/sdkconfig 路径，实际命令形态为：

```bash
idf.py -C examples/tcp_proxy -B <私有build目录> \
  -D SDKCONFIG=<私有sdkconfig路径> \
  -D IDF_TARGET=<esp32c3或esp32> \
  -D EFRP_SAMPLE_INPUTS=<本仓>/examples/tcp_proxy/inputs.example.h build
```

| 目标 | 最终配置回读 | 镜像大小 | `esp_frp_sample.bin` SHA-256 | 生成锁 SHA-256 |
| --- | --- | ---: | --- | --- |
| ESP32-C3 | `esp32c3`、4 MiB、USB Serial/JTAG、单核 | 125696 字节（`0x1eb00`） | `98695446efd41d8e331470717a1cc18e4e71650b4b68471c8bd05275af3364a6` | `0fe4da669276a376c99bef4186a610edab82d2b860889b9117972b5224974309` |
| ESP32-D0WD-V3 | `esp32`、4 MiB、UART0 115200、单核 | 116896 字节（`0x1c8a0`） | `ba3a05fd6477aaee37323636849c438275367ae690d646b3d567471303b8aa24` | `59fdbc48687a0f17e1306426b5a23397246e3dccd985514ea4621069fbba943d` |

两份 `dependencies.lock` 均由固定 SDK 的 Component Manager 生成，解析 IDF 6.1.0 与 `espressif/cjson` 1.7.19~2、组件摘要 `e788323270d90738662d66fffa910bfe1fba019bba087f01557e70c40485b469`；锁文件分别精确声明 target。原 C3 锁与本次生成结果仅 `manifest_hash` 不同，已用原样生成文件更新。

本机另用 AppleClang/OpenSSL 3.6.3 执行 host ASan/UBSan CTest **7/7**，SDK 工具 Git fixture **8/8** 通过。空输入应用会在启动网络前拒绝，构建成功只证明双目标编译与链接。ESP32 真机的严格 TLS、官方 FRPS、双流/背压/FIN/RST/预备流、百次回收、资源峰值及 Base/MQTT/OTA 组合仍须按两台设备各自的身份、分区和完整 Flash 恢复基线逐项验收；ESP32 单核样例不能替代 Base 双核组合结果。
