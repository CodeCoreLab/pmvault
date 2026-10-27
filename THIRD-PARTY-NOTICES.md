# 第三方组件与许可声明 — pmvault（密码管理器）

本文件列出本项目使用的第三方组件及其许可协议。

**本仓库不包含任何第三方二进制文件**——所有依赖一律通过语言原生的包管理机制
（`PackageReference` / `go.mod` / `Cargo.toml`）在构建时还原。
克隆本仓库后执行对应的构建命令，即可获得完整的依赖树。

## pmvault（密码管理器）

技术栈：Go 1.23+

| 组件 | 版本 | 许可 | 用途 |
|---|---|---|---|
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | v0.31.0 | BSD-3-Clause | Argon2id 密钥派生 |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | v1.34.5 | BSD-3-Clause | **纯 Go** 实现的 SQLite 驱动 |

`modernc.org/sqlite` 的选用理由：它不依赖 cgo，交叉编译时无需 C 工具链，
可产出单一静态可执行文件。间接依赖同样为 BSD 系列许可：

| 组件 | 版本 | 许可 |
|---|---|---|
| github.com/dustin/go-humanize | v1.0.1 | MIT |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| github.com/mattn/go-isatty | v0.0.20 | MIT |
| github.com/ncruces/go-strftime | v0.1.9 | MIT |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748 | MIT |
| golang.org/x/sys | v0.28.0 | BSD-3-Clause |
| modernc.org/libc | v1.55.3 | BSD-3-Clause |
| modernc.org/mathutil | v1.6.0 | BSD-3-Clause |
| modernc.org/memory | v1.8.0 | BSD-3-Clause |

> 完整、权威的依赖清单请以 `src/phase-a/go.mod` 与 `go.sum` 为准。

---
