# 使用 Go 实现首版 Gateway

首版选择 Go 作为唯一运行时，以支持 Linux、Windows、macOS 的单二进制交付，并在同一进程中实现流式 HTTP、TLS/本地 CA、并发分片传输和 CLI。相比引入解释器或多运行时方案，这降低了自托管部署与跨平台维护成本。
