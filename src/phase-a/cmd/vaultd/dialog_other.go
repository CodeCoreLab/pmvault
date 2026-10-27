//go:build !windows && !darwin

package main

import "fmt"

// showFatalDialog 在既非 Windows 也非 macOS 的平台上退化为 stderr 输出。
func showFatalDialog(title, text string) {
	fmt.Printf("[%s] %s\n", title, text)
}
