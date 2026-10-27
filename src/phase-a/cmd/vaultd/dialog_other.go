//go:build !windows

package main

import "fmt"

// showFatalDialog 在非 Windows 平台退化为 stderr 输出。
func showFatalDialog(title, text string) {
	fmt.Printf("[%s] %s\n", title, text)
}
