# 开发检查点

2026-09-21 开发基线：wire v2 帧 reader 的 ASan/UBSan host 回归通过；包括逐字节、拆帧/粘帧、64 KiB、非法头、EOF 与回调拒绝。完整客户端及实板未完成，不可作为可用 FRPC 宣传。

开发基线已保存至 `master` 的 `965d3e16bb644b907dcc3b4439959dd28a16bf9a`。已从 GitHub 重新 clone 到工作区之外的全新目录进行独立验证，不复用原 checkout 的源码或构建产物。 CMake 构建和 ASan/UBSan CTest 通过，输入覆盖不依赖 Token 或私有基础设施。

正式发布与硬件验收仍未完成。构建与 host 测试不替代实板。
