package vault

// Version 是本程序的发布版本号。
//
// 唯一权威源 = 仓库根的 VERSION 文件（纯文本，一行一个版本号）。
// 构建时由打包脚本用 ldflags 注入到本变量：
//
//	go build -ldflags "-X vaultgui/internal/vault.Version=1.0.0"
//
// 未注入时为 "dev"，表示直接 go build 的本地开发构建（不作为发布版本）。
//
// 为什么不用 ldflags 之外的方式：
//
//	本仓有两个 Go module（vaultd / vaultgui），各自独立编译，
//	若把版本号写死进两处 Go 源码，二者迟早漂移；
//	而 ldflags 的值统一取自 VERSION 文件，注入路径由构建脚本保证一致。
var Version = "dev"
