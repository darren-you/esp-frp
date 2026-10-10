# SDK 准备与检查

`tools/sdk.py` 只消费本仓 [sdk-lock.json](../sdk-lock.json)、Python 标准库、Git 和锁定的公开来源。组件锁保存 IDF／lwIP 身份，以及 ESP Base 唯一 recipe 的来源提交与完整摘要；TLSF、两份修改与逐文件原文／派生摘要只存在于该 recipe。组件不保存第二套 patch 清单或脚本。

```mermaid
flowchart LR
    lock["组件 SDK 锁：官方身份 / recipe 提交与摘要"] --> prepare["sdk.py prepare：独立新目录"]
    recipe["Base 精确提交：唯一 sdk-lock.json / 两份修改"] --> prepare
    sdk["锁定 IDF / lwIP / TLSF 官方源码"] --> prepare
    prepare --> checkout["正式 SDK / 唯一 esp-sdk-derivation.json"]
    checkout --> check["本仓 sdk.py check：清单 / 源码 / Git 状态"]
    check --> component["CMake 组件守卫"]
```

```bash
python3 tools/sdk.py prepare --path "$HOME/.espressif/frameworks/esp-frp-idf"
bash "$HOME/.espressif/frameworks/esp-frp-idf/install.sh" esp32c3 esp32
source "$HOME/.espressif/frameworks/esp-frp-idf/export.sh"
python3 tools/sdk.py check --path "$IDF_PATH"
python3 -B -m unittest discover -s tools/tests -p test_sdk.py
```

`prepare` 只创建不存在的新路径，从冻结 Base 提交读取 recipe 和两份修改的数据，不执行 Base 构建或 SDK 内脚本。它核对清单与 patch 摘要、所有官方原文及完整修改集合，在全部 `git apply --check` 通过后才应用；最后独占创建 SDK 根普通文件 `esp-sdk-derivation.json`，其字节与冻结 recipe 完全相同。工具链安装与导出仍是独立的官方入口。

`check` 只读本地 SDK：先核该普通文件的完整摘要，再核官方 IDF／lwIP／TLSF 提交、逐文件原文与派生摘要、索引、精确工作树差异及所有子模块；不下载、不执行未知脚本，不调用相邻仓库。未装配旧 SDK、清单缺失／链接／漂移、部分修改、未声明修改及子模块漂移均拒绝。既有路径和失败现场保持，不提供自动修复、可选 allowlist 或旧门回退。`--quiet` 供构建调用，仅省略成功输出。

真实 Git fixture 覆盖独立准备、精确来源与逐文件校验，以及原始 lwIP、脏状态、索引、TLSF、清单、链接、部分修改和越界路径等拒绝；它不下载真实 SDK、不触达设备。软件守卫通过不授予 FRP／Base 组合容量、Broker 或实板资格。

## QUIC 精确源码

0.3.0 的完整 Mbed TLS host 模式和 ESP-IDF 组件都消费 [quic-lock.json](../quic-lock.json) 中同一组 ngtcp2/Picotls。使用两个不存在的仓外目录：

```bash
python3 tools/quic_sources.py prepare \
  --ngtcp2-path /absolute/path/to/esp-frp-ngtcp2 \
  --picotls-path /absolute/path/to/esp-frp-picotls
```

已有目录用 `check` 替代 `prepare`，不会覆盖或修改 checkout。host `cmake` 和 IDF `idf.py` 均添加 `-DEFRP_NGTCP2_SOURCE_DIR=/absolute/path/to/esp-frp-ngtcp2` 与 `-DEFRP_PICOTLS_SOURCE_DIR=/absolute/path/to/esp-frp-picotls`。构建检查独立 Git 根、完整 SHA 和未提交修改，不能用相邻工作区或改写依赖来绕过守卫。基础 OpenSSL／独立 PSA 协议矩阵不消费 QUIC。

原型和正式组件共用根锁、源守卫及第一方 crypto；正式装配由 `tools/quic_dependencies.cmake` 定义；原型仅作为独立测试入口。两个 target 并行构建需各自独立源码目录，不能共享 Component Manager 的 `managed_components` 目录。实际运行、资源与验收范围见[流传输合同](../docs/design/stream-transport.md)。
