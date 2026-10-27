//go:build !windows && !darwin

package main

// 非 Windows / 非 macOS 平台的空实现：单实例由外部保证（桌面单用户场景足够），
// 错误与提示直接写 stderr，代码页无需处理。
// macOS 单独走 platform_darwin.go（需要系统弹窗 + flock 单实例）。

import "fmt"

func acquireSingleInstance() (func(), bool) { return func() {}, true }

// runMessageBox 与 Windows 版保持一致的签名（无返回值），仅打印。
func runMessageBox(title, text string) {
	fmt.Printf("[%s] %s\n", title, text)
}

// notifyAlreadyRunningAsync 在非 Windows 平台直接打印后返回，调用方随即退出。
func notifyAlreadyRunningAsync(title, text string) {
	fmt.Printf("[%s] %s\n", title, text)
}

// showFatalPlatform 在无图形弹窗能力的平台上退化为 stderr 输出。
func showFatalPlatform(title, text string) {
	fmt.Printf("[%s] %s\n", title, text)
}

// initConsole 在 console_other.go 定义，此处不重复声明。
