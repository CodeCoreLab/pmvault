//go:build darwin

package main

// macOS 平台辅助：单实例互斥 + 系统原生弹窗。
//
// 为什么需要这一份（platform_other.go 已排除 darwin）：
//  1. macOS 上从 Finder 双击 .app 启动时**没有终端窗口**，
//     纯 stderr 输出的致命错误（例如「未找到可用的浏览器内核」）
//     用户完全看不到，只会以为「双击了没反应」。
//     osascript 的 `display alert` 是系统原生弹窗，与 Windows 的
//     MessageBoxW 对位。
//  2. Windows 用命名互斥量（CreateMutexW）做单实例；macOS 没有
//     等价 API，这里改用 flock 锁文件，效果等价：
//     第二个进程拿不到锁 → 弹「已在运行」提示后立即退出。
//
// 依赖：macOS 自带 /usr/bin/osascript，无需额外安装。

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const darwinDialogScript = `on run argv
display alert (item 1 of argv) message (item 2 of argv) buttons {"好"} default button 1 with icon caution
end run`

// showSystemDialog 弹出 macOS 系统弹窗。
// 脚本通过 argv 传参（不经 shell），标题/正文里的引号与换行都不会破坏脚本。
// 弹窗失败时静默降级——弹窗本身失败不应再引发二次故障。
func showSystemDialog(title, text string) {
	cmd := exec.Command("/usr/bin/osascript", "-e", darwinDialogScript, title, text)
	_ = cmd.Run()
}

// lockPath 单实例锁文件路径。
// 放在用户配置目录（macOS 上 os.UserConfigDir() = ~/Library/Application Support），
// 避开 .app bundle 内部——bundle 是只读签名容器，不能在里面写文件。
func lockPath() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "PasswordManager")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, ".instance.lock")
}

// acquireSingleInstance 用 flock 排他锁保证只有一个实例。
// 返回的 release 必须在退出时调用以释放锁。
func acquireSingleInstance() (func(), bool) {
	f, err := os.OpenFile(lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		// 创建失败不该阻断启动，宁可允许运行
		return func() {}, true
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return func() {}, false
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true
}

// runMessageBox 同步弹窗（阻塞到用户确认）。仅用于致命错误路径。
func runMessageBox(title, text string) {
	showSystemDialog(title, text)
}

// showFatalPlatform 致命错误的统一呈现入口。
// macOS 有原生弹窗，必须弹——从 Finder 启动时没有终端，stderr 用户看不到。
func showFatalPlatform(title, text string) {
	showSystemDialog(title, text)
}

// notifyAlreadyRunningAsync 提示「已在运行」后本进程立即退出。
//
// 与 Windows 版行为一致：弹窗必须可见但不能永久挂住进程。
// osascript 的 display alert 是阻塞式的，这里放到独立 goroutine，
// 主线程最多等 1.5 秒确保弹窗已出现即退出。
func notifyAlreadyRunningAsync(title, text string) {
	done := make(chan struct{})
	go func() {
		showSystemDialog(title, text)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
	}
}
