//go:build windows

package main

// Windows 平台：原生消息框。
// 无控制台模式下，弹窗是唯一可靠的错误呈现方式。

import (
	"syscall"
	"unsafe"
)

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

const (
	mbOK          = 0x00000000
	mbIconWarning = 0x00000030
)

// showFatalDialog 弹系统原生消息框（阻塞到用户点确定）。
// 仅用于致命错误路径，此时进程即将退出，阻塞是可接受的。
func showFatalDialog(title, text string) {
	t, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	c, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(c)),
		uintptr(unsafe.Pointer(t)),
		uintptr(mbOK|mbIconWarning))
}
