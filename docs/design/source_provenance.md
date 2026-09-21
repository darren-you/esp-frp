# 来源与许可

| 上游 | 固定版本 / SHA | 参考路径 | 用途与本地实现 | 许可 |
| --- | --- | --- | --- | --- |
| [fatedier/frp](https://github.com/fatedier/frp) | v0.71.0 / 4a23aa181c1d7e28eecaa8216024ed753b9d27c8 | pkg/proto/wire/wire.go | magic、8 字节头、frame type/flags/length；本地 src/frame_reader.c 按增量与借用内存职责独立编写，未复制 Go 实现 | Apache-2.0，The frp Authors |
| 同上 | 同上 | pkg/msg/wire_v2.go | 协议消息编号与 JSON 装配的后续实现依据 | Apache-2.0 |

wire 常量必须与协议一致。当前没有 vendoring 或片段移植；测试也只依赖本仓 C API。两个 GPL 参考用于历史研究，不导入源码、机械翻译或换名副本。以后新增来源逐项登记原 URL、SHA、路径、保留范围、版权与修改。
