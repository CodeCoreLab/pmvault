// Command vaultd 是密码管理系统的 Windows 原生版本（Phase A）。
//
// 设计要点：
//  1. 单一可执行文件：内嵌 HTTP 服务 + 静态资源 + SQLite 驱动，无需 PHP / Web 服务器
//  2. 数据完全兼容：直接读写既有 data/passwords.db，密文格式与 PHP 版逐字节一致
//  3. 零 CGO：使用 modernc.org/sqlite，交叉编译无需 C 工具链
//  4. 密钥只在服务端内存：主密钥不返回给浏览器，解密由后端完成（修正原版把主密钥
//     交给前端并随请求回传的设计）
package main

import (
	"context"
	"errors"
	"flag"
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
	"syscall"
	"time"

	"vaultd/internal/vault"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "监听地址（默认 127.0.0.1 随机端口）")
	dataDir := flag.String("data", "", "数据目录（默认：可执行文件同级的 data/）")
	openBrowser := flag.Bool("open", true, "启动后自动打开浏览器")
	flag.Parse()

	// Windows 控制台默认代码页是 GBK(936)，而 Go 输出的是 UTF-8 字节，
	// 直接打印会变成乱码（用户无法看懂日志与错误信息）。
	// 启动时把控制台切到 UTF-8，即可让中文正常显示。
	initConsole()

	log.SetFlags(log.Ltime)
	log.SetPrefix("[vaultd] ")

	// 解析数据目录
	root, err := resolveRoot(*dataDir)
	if err != nil {
		fatal("无法定位数据目录", err)
	}
	dbPath := filepath.Join(root, "passwords.db")
	backupDir := filepath.Join(root, "backups")
	for _, d := range []string{root, backupDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			fatal("无法创建目录 "+d, err)
		}
	}
	log.Printf("数据目录: %s", root)

	// 同时写 data/run.log：用户双击 bat 时控制台可能一闪而过或根本没看，
	// 出问题时没有控制台就无从查起。文件日志是唯一的可观测入口。
	// O_TRUNC 只保留最近一次运行，避免无限增长。
	if lf, err := os.OpenFile(filepath.Join(root, "run.log"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
		defer lf.Close()
	}

	// 初始化存储层（自动建表，兼容 PHP 版已有库）
	store, err := vault.OpenStore(dbPath, backupDir)
	if err != nil {
		fatal("数据库初始化失败", err)
	}
	defer store.Close()

	app := vault.NewApp(store)

	// 只监听回环地址：这是本地应用而非网络服务，不应暴露给局域网
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fatal("端口监听失败", err)
	}
	url := "http://" + ln.Addr().String() + "/"

	srv := &http.Server{
		Handler:           app.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		// 本地单用户场景不需要长连接超时，但保留写超时防止挂死
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		log.Printf("已启动: %s", url)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("服务异常退出: %v", err)
		}
	}()

	if *openBrowser {
		go openURL(url)
	}

	// 等待中断信号或网页端「退出程序」请求，优雅关闭
	select {
	case <-app.Quit():
		log.Println("收到退出请求，正在关闭...")
	case <-sigChan():
		log.Println("收到中断信号，正在关闭...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("关闭超时: %v", err)
	}
	app.Close()
	log.Println("已退出")
}

func sigChan() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}

// resolveRoot 决定数据目录位置。
// 便携优先：若可执行文件同级存在 data/ 或 passwords.db，则用它；
// 否则用系统用户数据目录，避免把库塞进 Program Files（无写权限）。
func resolveRoot(explicit string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		return abs, err
	}

	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		portableData := filepath.Join(exeDir, "data")
		// 便携模式判据：data 目录已存在，或同级直接放着 passwords.db
		if st, err := os.Stat(portableData); err == nil && st.IsDir() {
			return portableData, nil
		}
		if _, err := os.Stat(filepath.Join(exeDir, "passwords.db")); err == nil {
			return exeDir, nil
		}
	}

	// 退回用户数据目录
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "PasswordManager"), nil
}

func openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("自动打开浏览器失败，请手动访问 %s: %v", url, err)
	}
}

func fatal(msg string, err error) {
	log.Printf("%s: %v", msg, err)
	identity := fmt.Sprintf("%s: %v", msg, err)
	fatalBox(identity)
	os.Exit(1)
}

// fatalBox 用系统原生弹窗告知启动失败（Windows / macOS）/ 写 stderr（其他平台）。
//
// 早先用 mshta 拼 JS 弹窗，有两个问题：会额外起一个子进程，
// 且企业环境常禁用 mshta。改用 user32!MessageBoxW，无额外进程。
//
// macOS 走 osascript 的 display alert：从 Finder 双击 .app 启动时没有终端，
// stderr 用户看不到，必须弹原生框。
func fatalBox(detail string) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		fmt.Fprintf(os.Stderr, "%s\n", detail)
		return
	}
	showFatalDialog("密码管理器启动失败", detail)
}
