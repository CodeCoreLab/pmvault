# 变更日志 — 密码管理器（pmvault）

本文件记录本项目的变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增

- **引入版本权威源 `VERSION`**（仓库根，单行 `MAJOR.MINOR.PATCH`）：
  此前本仓没有任何版本常量，产物无从得知自身版本。本仓有两个独立 Go module
  （`vaultd` / `vaultgui`），若把版本号写进两处源码必漂移，故只在 `VERSION`
  存一份，由两个打包脚本在编译期经 `ldflags -X` 注入
- **两个程序新增 `--version`**：`vaultd --version` / `vaultgui --version`
  直接打印版本号后退出。该分支先于 `initConsole()`、建库、起服务与单实例
  互斥返回 —— 否则「查版本」会顺带创建数据目录并占用互斥量
- 启动日志打印版本号，便于从日志回溯运行的是哪个版本
- 17 项单元测试，覆盖会话并发、闲置上锁、错误码收敛、限流窗口、
  锁定时间解析、加密解密往返与密码强度校验

### 修复

- **`phase-a/脚本-打包.py` 的 `SRC` 路径错指**：原 `SRC = os.path.dirname(_HERE)`
  指向 `src/` 而非 `src/phase-a/`，导致 `go build ./cmd/vaultd`、图标与
  `README-桌面版.md` 三处路径全错，脚本从未真正跑通编译
- **`phase-a/脚本-打包.py` 的失效 ldflag**：原
  `-X main.buildInfo=desktop-1.0.0` 指向 `main` 包中不存在的变量。
  Go 链接器对不存在的 `-X` 目标**静默忽略**，编译成功但注入无效，
  是「看似有版本、实则产物无版本」的隐形漂移源。已删除，改为注入真实存在的
  `vaultd/internal/vault.Version`
- **`phase-edgeapp/脚本-打包.py` 缺构建步骤**：原先只打包、要求 exe 已预构建，
  版本号无处注入。现补齐 `go build` 并统一从 `VERSION` 取值注入
  `vaultgui/internal/vault.Version`
- **前端时间显示偏差**：`fmtTime` 原先把后端返回的本地时间一律当 UTC 解析，
  东八区用户看到的时间早 8 小时。改为按字符串内的时区标记精确换算，
  无偏移的旧数据按 UTC 兜底
- **登录限流绕过**：限流改用真实 `r.RemoteAddr`，不再采信可伪造的
  `X-Forwarded-For`；用户名归一化为小写去空白，防止大小写变体绕过

### 变更

- **统一错误出口**：原先有 30 处直接把 `err.Error()` 写进 HTTP 响应，
  会泄露 SQLite 表结构名与本机路径、操作系统细节。改为按稳定错误码收敛
  （`E_INTERNAL` / `E_NOT_FOUND` / `E_CONFLICT` / `E_VALIDATION` /
  `E_UNAUTHORIZED` / `E_LOCKED` / `E_RATE_LIMIT` / `E_NEED_UNLOCK` /
  `E_SESSION_GONE` / `E_DECRYPT_FAILED`），底层错误仅写入日志
- **会话并发安全**：session 字段访问改由互斥锁保护，消除数据竞争
- **滑动窗口闲置上锁**：每次成功的解锁态操作刷新闲置计时，取代原先
  「解锁后固定 15 分钟必锁」的行为
- **时间存储统一 UTC**：账户锁定时间改用 RFC3339 格式存取，
  修复非 UTC 时区下「被锁 15 分钟实际锁 23 小时」的问题；
  `nowStr()` 统一为 RFC3339，消除 Go 写本地时间与 SQLite 写 UTC 的混用
- **备份轮转失败留痕**：删除旧备份出错时写日志，不再静默吞错

## [1.0.0] - 2026-10-22

### 新增

- 首个发布版本：Windows 本地单机密码保险箱
- **加密**：AES-256-GCM 认证加密（防篡改），密文格式
  `版本号(1) ‖ IV(12) ‖ Tag(16) ‖ 密文`
- **密钥派生**：Argon2id（内存 64 MiB / 迭代 2 / 并行 1），抗 GPU / ASIC 暴力破解
- **主密钥不落盘**：库里只存派生参数（salt + KDF 参数），每次解锁时重新派生
- **仅监听 127.0.0.1 随机端口**：不对外开放，局域网内其他设备无法访问
- **闲置 15 分钟自动上锁**（滑动窗口：每次成功操作续期）
- **独立浏览器配置**：不影响日常浏览器的书签、密码、历史
- **备份轮转**：自动 / 手动备份，保留最近 30 份
- 双形态发布：原生窗口版（Edge / Chrome `--app` 模式承载）与浏览器版
- 数据格式与早期 PHP 版完全兼容，可双向读写

### 安全

- 账户锁定：连续 5 次失败锁定 15 分钟（锁定时间以 UTC 存储）
- 登录限流：按来源 IP 10 次/分，按用户名 5 次/5 分（用户名归一化为小写）
