//go:build windows

package main

// Windows 平台辅助：单实例互斥 + 系统弹窗。
// 桌面程序无控制台（PE Subsystem=2），系统弹窗是唯一可靠的错误呈现方式。

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW = kernel32.NewProc("CreateMutexW")
	procCloseHandle  = kernel32.NewProc("CloseHandle")
	user32           = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW  = user32.NewProc("MessageBoxW")
)

const (
	errorAlreadyExists = 183
	mbIconWarning      = 0x00000030
	mbIconInfo         = 0x00000040
	mbOK               = 0x00000000
	mbSetForeground    = 0x00010000
	mbTopMost          = 0x00040000
)

// acquireSingleInstance 用命名互斥量保证只有一个实例。
// 返回的 release 必须在退出时调用以释放句柄。
func acquireSingleInstance() (func(), bool) {
	name, err := syscall.UTF16PtrFromString(`Global\PasswordManagerGUI_SingleInstance_v1`)
	if err != nil {
		return func() {}, true
	}
	h, _, errno := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if h == 0 {
		// 创建失败不该阻断启动，宁可允许运行
		return func() {}, true
	}
	handle := syscall.Handle(h)
	if errno == syscall.Errno(errorAlreadyExists) {
		procCloseHandle.Call(uintptr(handle))
		return func() {}, false
	}
	return func() { procCloseHandle.Call(uintptr(handle)) }, true
}

// messageBox 弹出系统消息框。
//
// 注意：MB_OK 型 MessageBox **会阻塞调用线程直到用户点确定**。
// 因此调用方必须区分场景：
//   - 致命错误（进程即将退出）：可以阻塞，让用户看清原因
//   - 「已在运行」提示（属于正常路径）：不能阻塞，否则第二个进程会
//     一直挂在任务管理器里，用户以为程序坏了
func messageBox(title, text string, flags uintptr) {
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
		flags)
}

// runMessageBox 同步弹窗（阻塞到用户确认）。仅用于致命错误路径。
func runMessageBox(title, text string) {
	messageBox(title, text, mbOK|mbIconWarning)
}

// notifyAlreadyRunningAsync 在后台线程弹「已在运行」提示，本进程立即退出。
//
// 为什么异步：第二个实例属于正常场景（用户手滑双击两次），不该把
// 进程永久挂住等用户点确定；但它确实需要一个可见反馈，不能静默退出。
// 弹窗放到独立 goroutine 里，主线程稍等片刻确保窗口已出现即退出。
func notifyAlreadyRunningAsync(title, text string) {
	done := make(chan struct{})
	go func() {
		// 置顶 + 抢焦点，确保用户能看见
		messageBox(title, text, mbOK|mbIconInfo|mbSetForeground|mbTopMost)
		close(done)
	}()

	// 等到弹窗真正出现（或最多 1.5 秒）就退出进程。
	// 不直接 return：那样进程会立刻消失，用户什么都看不到。
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
	}
}
