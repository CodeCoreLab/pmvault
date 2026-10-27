//go:build darwin

package main

// macOS 平台：系统原生弹窗。
//
// 为什么需要：macOS 上从 Finder 双击 .app 启动时**没有终端窗口**，
// 纯 stderr 输出的致命错误（例如「数据库初始化失败」）
// 用户完全看不到，只会以为「双击了没反应」。
// osascript 的 `display alert` 是系统原生弹窗，与 Windows 的
// MessageBoxW 对位，且不依赖任何第三方库。
//
// 依赖：macOS 自带 /usr/bin/osascript，无需额外安装。

import "os/exec"

const darwinDialogScript = `on run argv
display alert (item 1 of argv) message (item 2 of argv) buttons {"好"} default button 1 with icon caution
end run`

// showFatalDialog 弹系统原生消息框（阻塞到用户点确定）。
// 仅用于致命错误路径，此时进程即将退出，阻塞是可接受的。
//
// 脚本通过 argv 传参（不经 shell），标题/正文里的引号与换行都不会破坏脚本。
// 弹窗失败时静默降级——弹窗本身失败不应再引发二次故障。
func showFatalDialog(title, text string) {
	cmd := exec.Command("/usr/bin/osascript", "-e", darwinDialogScript, title, text)
	_ = cmd.Run()
}
