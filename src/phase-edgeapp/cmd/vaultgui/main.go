// Command vaultgui 是密码管理器的桌面版（Edge --app 模式）。
//
// 设计取舍（为什么不用 WebView2 绑定库）：
//
//	实测 github.com/jchv/go-webview2 在本机 WebView2 150.0.4078 运行时上完全不可用 ——
//	该库内嵌旧版 WebView2Loader.dll，而新版运行时已不再随附 loader，
//	表现为窗口能创建但 JS 绑定与 Eval 全部静默失效、页面停在空白。
//
// 本实现改用「系统已装的 Edge/Chrome 以 --app 模式承载本地页面」：
//   - 无第三方 GUI 依赖，只用标准库 + os/exec
//   - --app 模式没有地址栏、书签栏、标签栏，外观与原生应用窗口一致
//   - 独立 --user-data-dir，不影响用户日常浏览器配置，也保证单实例干净
//   - 后端仍是同一套 Go 服务，主密钥只在进程内，绝不下发前端
//
// 代价：依赖系统存在 Edge 或 Chrome。Windows 10/11 自带 Edge，实际风险很低；
// 启动时依次探测 Edge → Chrome，全部缺失则给出明确提示。
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vaultgui/internal/vault"
)

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("[vaultgui] ")
	initConsole()

	// 单实例互斥：避免两个进程同时写同一 SQLite
	release, ok := acquireSingleInstance()
	if !ok {
		// 用非阻塞提示：这是正常场景（用户手滑双击两次），
		// 弹窗要可见但进程不能挂住等用户点确定。
		notifyAlreadyRunningAsync("密码管理器",
			"程序已在运行中。\n\n请在任务栏查看已打开的窗口。")
		return
	}
	defer release()

	root, err := resolveDataDir()
	if err != nil {
		showFatal("无法确定数据目录", err)
		return
	}
	for _, d := range []string{root, filepath.Join(root, "backups")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			showFatal("无法创建数据目录 "+d, err)
			return
		}
	}

	// 桌面版用 -H windowsgui 编译（无控制台），因此必须把日志落到文件，
	// 否则出问题时用户与支持者都拿不到任何线索。
	// 只保留最近一次运行，避免日志无限增长。
	if lf, err := openRunLog(root); err == nil {
		defer lf.Close()
		log.SetOutput(io.MultiWriter(lf, os.Stderr))
		log.Printf("=== 启动 ===")
	} else {
		log.Printf("无法创建日志文件（继续运行）: %v", err)
	}

	log.Printf("数据目录: %s", root)

	store, err := vault.OpenStore(filepath.Join(root, "passwords.db"), filepath.Join(root, "backups"))
	if err != nil {
		showFatal("数据库初始化失败", err)
		return
	}
	defer store.Close()

	app := vault.NewApp(store)

	// 只监听回环地址：这是本地应用，不应暴露给局域网
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		showFatal("端口监听失败", err)
		return
	}
	port := ln.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	log.Printf("服务端口: %d", port)

	srv := &http.Server{
		Handler:           app.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("服务异常退出: %v", err)
		}
	}()

	browser, err := findBrowser()
	if err != nil {
		showFatal("未找到可用的浏览器内核",
			fmt.Errorf("本程序需要 Microsoft Edge 或 Google Chrome。\n"+
				"Windows 10/11 通常自带 Edge；若被移除，请安装 Edge 后重试。"))
		closeServer(srv)
		return
	}
	log.Printf("使用浏览器: %s", browser)

	// 独立配置目录放在数据目录下，随程序一起搬走/删除，不留系统残留
	profileDir := filepath.Join(root, "browser-profile")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		log.Printf("创建浏览器配置目录失败（回退到浏览器默认路径）: %v", err)
		profileDir = ""
	}

	cmd, err := launchAppWindow(browser, url, profileDir, root)
	if err != nil {
		showFatal("无法启动应用窗口", err)
		closeServer(srv)
		return
	}
	log.Printf("应用窗口已启动")

	// 三条退出路径：用户关窗口 / 网页内点「退出程序」/ 进程被中断
	winClosed := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(winClosed)
	}()

	select {
	case <-winClosed:
		log.Println("浏览器窗口已关闭，正在退出...")
	case <-app.Quit():
		log.Println("收到网页端退出请求，正在关闭窗口...")
		killBrowser(cmd)
	case <-waitSignal():
		log.Println("收到中断信号，正在关闭...")
		killBrowser(cmd)
	}

	closeServer(srv)
	app.Close()
	log.Println("已退出")
}

// findBrowser 依次探测 Edge、Chrome 与常见安装位置。
// 顺序刻意把 Edge 放前面：Windows 10/11 默认预装，覆盖率最高。
func findBrowser() (string, error) {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		local := os.Getenv("LOCALAPPDATA")
		candidates = []string{
			filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(local, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(local, `Google\Chrome\Application\chrome.exe`),
		}
	case "darwin":
		candidates = []string{
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		}
	default:
		// PATH 中的命令名由 exec.LookPath 解析
		candidates = []string{"microsoft-edge", "google-chrome", "chromium", "chromium-browser"}
	}

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if strings.ContainsAny(c, `/\`) {
			if fileExists(c) {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", errors.New("未找到 Edge 或 Chrome")
}

// launchAppWindow 以 --app 模式打开独立窗口。
//
// 关键参数：
//
//	--app=URL                   无地址栏/标签栏/书签栏，外观等同原生应用窗口
//	--user-data-dir=DIR         独立配置目录，避免污染日常浏览数据；
//	                            也避免复用已有浏览器进程（那样会失去窗口尺寸控制）
//	--no-first-run              跳过首次体验引导
//	--no-default-browser-check  不弹「设为默认浏览器」
//	--disable-background-mode   关窗即真正退出，不在后台驻留
func launchAppWindow(browser, url, profileDir, dataRoot string) (*exec.Cmd, error) {
	args := []string{
		"--app=" + url,
		"--window-size=1120,760",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-mode",
		"--disable-features=Translate,TranslateUI,MediaRouter",
	}
	if profileDir != "" {
		args = append(args, "--user-data-dir="+profileDir)
	}
	cmd := exec.Command(browser, args...)
	cmd.Dir = dataRoot
	// 浏览器自身输出与应用无关，丢弃以免污染日志
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// killBrowser 只结束本次启动的那个浏览器实例，不影响用户其它窗口
func killBrowser(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}

func closeServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func waitSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}

// resolveDataDir 便携优先：可执行文件同级存在 data/ 就用它；
// 否则退到用户配置目录，避免装进 Program Files 后无写权限。
func resolveDataDir() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		portable := filepath.Join(exeDir, "data")
		if st, e := os.Stat(portable); e == nil && st.IsDir() {
			return portable, nil
		}
		if _, e := os.Stat(filepath.Join(exeDir, "passwords.db")); e == nil {
			return exeDir, nil
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "PasswordManager"), nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// openRunLog 打开 data/run.log（截断写入，只保留最近一次运行）。
// 桌面版无控制台，日志文件是排障的唯一入口。
func openRunLog(dataRoot string) (*os.File, error) {
	return os.OpenFile(filepath.Join(dataRoot, "run.log"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

func showFatal(msg string, err error) {
	full := fmt.Sprintf("%s: %v", msg, err)
	log.Print(full)
	if runtime.GOOS == "windows" {
		// 致命错误：可以阻塞，让用户看清原因再关窗
		runMessageBox("密码管理器启动失败", full)
	} else {
		fmt.Fprintln(os.Stderr, full)
	}
}
