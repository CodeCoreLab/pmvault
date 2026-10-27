// Windows 控制台代码页处理。
//
// 问题：cmd.exe 默认代码页 936(GBK)，而 Go 程序输出 UTF-8 字节，
// 中文日志在窗口里会显示成乱码，用户看不懂错误提示。
// 解决：启动时调用 SetConsoleOutputCP(65001) 把输出代码页切到 UTF-8。
// 副作用：切换后老式 GBK 输入法可能受影响，但本程序不读标准输入，可接受。
//
// 单独成文件并加 build tag，使非 Windows 平台无需引入 syscall 相关代码。

//go:build windows

package main

import "syscall"

func initConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setOutputCP := kernel32.NewProc("SetConsoleOutputCP")
	// 65001 = CP_UTF8；失败（如被重定向到文件/管道）时无需处理，
	// 因为重定向场景下字节会直接落盘，不经过控制台解码。
	_, _, _ = setOutputCP.Call(uintptr(65001))
}
