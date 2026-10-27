# 变更日志 — pmvault（密码管理器）

本文件记录本项目的变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### pmvault

#### 变更

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

#### 修复

- **前端时间显示偏差**：`fmtTime` 原先把后端返回的本地时间一律当 UTC 解析，
  东八区用户看到的时间早 8 小时。改为按字符串内的时区标记精确换算，
  无偏移的旧数据按 UTC 兜底
- **登录限流绕过**：限流改用真实 `r.RemoteAddr`，不再采信可伪造的
  `X-Forwarded-For`；用户名归一化为小写去空白，防止大小写变体绕过

#### 新增

- 17 项单元测试，覆盖会话并发、闲置上锁、错误码收敛、限流窗口、
  锁定时间解析、加密解密往返与密码强度校验

## 版本说明

- **xmtool**：`Properties/AssemblyInfo.cs` 中的 `AssemblyInformationalVersion`
  为权威版本号。产物名带 `v1.0.5` 字样，但 AssemblyInfo 可能仍停留在旧值——
  发布前需同步。
- **team-planner**：版本以 `releases/v<版本>-<日期>/` 目录名为准；
  数据 schema 版本独立于应用版本，见 `src/js/data/db.js` 的 `DB_VERSION`。
- **pmvault** / **work-reminder**：版本分别定义在 `go.mod` / `Cargo.toml`
  的 `version` 字段。
