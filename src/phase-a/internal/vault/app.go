// HTTP 层：会话、API 路由、内嵌前端。
//
// 与 PHP 版的关键差异（也是本实现刻意改进点）：
//  1. 主密钥只保存在服务端会话内，绝不下发浏览器；
//     解密接口不需要前端传密钥 —— 消除了原版「XSS 即可窃取主密钥」的攻击面。
//  2. CSP 不再需要 unsafe-inline/unsafe-eval，脚本全部走外部文件。
//  3. 监听 127.0.0.1，不对外网暴露；会话 Cookie 加 SameSite=Strict。
package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

//go:embed web/*
var webFS embed.FS

const (
	sessionTTL    = 30 * time.Minute
	autoLockAfter = 15 * time.Minute // 会话内主密钥的闲置失效时间
)

// session 保存单个已登录会话。
//
// 并发约定：App.mu 保护 sessions/csrf 两张 map；session.mu 保护本结构体的字段。
// 两者**不得嵌套持有**（先取 map 指针并释放 App.mu，再操作 session 字段），
// 否则容易形成 A→B / B→A 的锁顺序反转死锁。
type session struct {
	mu sync.Mutex

	UserID    int64
	Username  string
	MasterKey string // base64，仅存服务端
	Created   time.Time

	// lastActiveAt 是「最近一次成功的解锁态操作」时间，用来实现滑动窗口的闲置自动上锁。
	// 原实现用解锁时刻做绝对超时：用户一直在用也会在 15 分钟后被踢出去解锁。
	lastActiveAt time.Time
}

// masterKey 返回主密钥副本（加锁读取，避免与解锁/上锁并发写产生数据竞争）。
func (s *session) masterKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.MasterKey
}

// unlock 设置主密钥并重置闲置计时。
func (s *session) unlock(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MasterKey = key
	s.lastActiveAt = time.Now()
}

// lockNow 立即上锁（清空主密钥）。
func (s *session) lockNow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MasterKey = ""
}

// lockState 返回主密钥与是否仍处于解锁态。
// idle 为 true 表示已闲置超时（调用方需在置空后返回 423）。
func (s *session) lockState(idleTimeout time.Duration) (key string, unlocked bool, idle bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MasterKey == "" {
		return "", false, false
	}
	if idleTimeout > 0 && time.Since(s.lastActiveAt) > idleTimeout {
		s.MasterKey = "" // 闲置自动上锁
		return "", false, true
	}
	return s.MasterKey, true, false
}

// touch 刷新闲置计时（滑动窗口：每次成功的解锁态操作都续期）。
func (s *session) touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActiveAt = time.Now()
}

type App struct {
	store *Store

	mu       sync.Mutex
	sessions map[string]*session
	csrf     map[string]string // sessionID -> csrf token
	limiter  *Limiter

	quitOnce sync.Once
	quitCh   chan struct{}
}

func NewApp(store *Store) *App {
	return &App{
		store:    store,
		sessions: make(map[string]*session),
		csrf:     make(map[string]string),
		limiter:  NewLimiter(),
		quitCh:   make(chan struct{}),
	}
}

// Quit 返回一个在网页端请求退出时关闭的通道
func (a *App) Quit() <-chan struct{} { return a.quitCh }

// requestQuit 触发优雅关闭（供「退出程序」按钮使用）
func (a *App) requestQuit() {
	a.quitOnce.Do(func() { close(a.quitCh) })
}

// Close 释放资源
func (a *App) Close() {
	a.mu.Lock()
	a.sessions = make(map[string]*session)
	a.csrf = make(map[string]string)
	a.mu.Unlock()
	_ = a.store.Close()
}

func (a *App) Router() http.Handler {
	mux := http.NewServeMux()

	// 静态资源
	sub, err := fs.Sub(webFS, "web")
	if err == nil {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	}

	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("GET /api/status", a.handleStatus)
	mux.HandleFunc("POST /api/register", a.handleRegister)
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	mux.HandleFunc("POST /api/unlock", a.handleUnlock)
	mux.HandleFunc("POST /api/lock", a.handleLock)
	mux.HandleFunc("GET /api/session", a.handleSessionInfo)
	mux.HandleFunc("GET /api/entries", a.handleListEntries)
	mux.HandleFunc("POST /api/entries", a.handleCreateEntry)
	mux.HandleFunc("PUT /api/entries/{id}", a.handleUpdateEntry)
	mux.HandleFunc("DELETE /api/entries/{id}", a.handleDeleteEntry)
	mux.HandleFunc("POST /api/entries/{id}/restore", a.handleRestoreEntry)
	mux.HandleFunc("POST /api/entries/{id}/reveal", a.handleRevealEntry)
	mux.HandleFunc("GET /api/categories", a.handleListCategories)
	mux.HandleFunc("POST /api/categories", a.handleCreateCategory)
	mux.HandleFunc("PUT /api/categories/{id}", a.handleUpdateCategory)
	mux.HandleFunc("DELETE /api/categories/{id}", a.handleDeleteCategory)
	mux.HandleFunc("GET /api/stats", a.handleStats)
	mux.HandleFunc("POST /api/generator", a.handleGenerator)
	mux.HandleFunc("POST /api/change-password", a.handleChangeLoginPassword)
	mux.HandleFunc("POST /api/change-master", a.handleChangeMasterPassword)
	mux.HandleFunc("GET /api/backups", a.handleListBackups)
	mux.HandleFunc("POST /api/backups", a.handleCreateBackup)
	mux.HandleFunc("POST /api/shutdown", a.handleShutdown)

	return a.recoverPanic(a.securityHeaders(a.csrfGuard(mux)))
}

// recoverPanic 兜住 handler 内的 panic。
//
// net/http 默认会 recover 并直接断开连接（客户端看到 Connection Reset），
// 对桌面单进程应用来说这等于「界面突然白屏且无任何提示」。
// 此处改为返回 500 + 可读错误，并把堆栈写进日志。
func (a *App) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				buf := make([]byte, 8192)
				n := runtime.Stack(buf, false)
				logf("PANIC %s %s: %v\n%s", r.Method, r.URL.Path, rec, buf[:n])
				writeErr(w, 500, CodeInternal,
					"内部错误，请重试；若持续出现请回看程序窗口日志", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ---------- 中间件 ----------

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// 本地应用不需要 eval，脚本全部走外部文件，因此不给 unsafe-*
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; "+
				"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// csrfGuard 对写操作校验 CSRF token（双提交：Cookie + 请求头）
//
// 例外：/api/register 与 /api/login 必须放行 —— 它们的作用就是建立会话并下发首个 token。
// 若对它们也强制校验，全新安装将永远无法创建第一个账户（没有会话就没有 token），
// 形成鸡生蛋死锁。这两个端点改由其内部逻辑自我约束：
//   - register 仅在零用户时可用，且要求主密钥密码
//   - login 有 IP + 用户名双维度限流
//
// 其余所有写操作一律强制校验。
func (a *App) csrfGuard(next http.Handler) http.Handler {
	exempt := map[string]bool{
		"/api/register": true,
		"/api/login":    true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if exempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		sid := a.sessionID(r)
		token := r.Header.Get("X-CSRF-Token")
		a.mu.Lock()
		expect := a.csrf[sid]
		a.mu.Unlock()
		if sid == "" || expect == "" || subtle.ConstantTimeCompare([]byte(expect), []byte(token)) != 1 {
			writeErr(w, 403, CodeValidation, "CSRF 校验失败，请刷新页面", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- 会话 ----------

func (a *App) sessionID(r *http.Request) string {
	c, err := r.Cookie("sid")
	if err != nil {
		return ""
	}
	return c.Value
}

func (a *App) currentSession(r *http.Request) *session {
	sid := a.sessionID(r)
	if sid == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[sid]
	if s == nil {
		return nil
	}
	if time.Since(s.Created) > sessionTTL {
		delete(a.sessions, sid)
		delete(a.csrf, sid)
		return nil
	}
	return s
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) *session {
	s := a.currentSession(r)
	if s == nil {
		writeErr(w, 401, CodeSessionGone, "未登录或会话已过期", nil)
		return nil
	}
	return s
}

// requireUnlocked 检查会话内主密钥仍有效（闲置超时则要求重新解锁）
//
// 闲置判定采用**滑动窗口**：每次成功的解锁态操作都会续期，
// 只有真正「一段时间没人动」才上锁。原实现是解锁后固定 15 分钟必锁，
// 用户一直在用也会被反复要求解锁，体验很差。
func (a *App) requireUnlocked(w http.ResponseWriter, r *http.Request) (*session, bool) {
	s := a.requireSession(w, r)
	if s == nil {
		return nil, false
	}
	key, unlocked, idle := s.lockState(autoLockAfter)
	if !unlocked {
		if idle {
			writeNeedUnlock(w, "已闲置自动锁定，请重新输入主密钥密码")
		} else {
			writeNeedUnlock(w, "需要解锁：请输入主密钥密码")
		}
		return nil, false
	}
	// 滑动窗口续期
	s.touch()
	_ = key
	return s, true
}

func (a *App) newSession(w http.ResponseWriter, userID int64, username string) (string, string) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	sid := hex.EncodeToString(buf)
	buf2 := make([]byte, 32)
	_, _ = rand.Read(buf2)
	token := hex.EncodeToString(buf2)

	a.mu.Lock()
	a.sessions[sid] = &session{UserID: userID, Username: username, Created: time.Now()}
	a.csrf[sid] = token
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return sid, token
}

// ---------- 处理器 ----------

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "前端资源缺失", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	n, err := a.store.UserCount()
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":           true,
		"initialized":  n > 0,
		"app_name":     "密码管理器",
		"argon2_ready": true,
	})
}

type registerReq struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	MasterPassword string `json:"master_password"`
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	n, err := a.store.UserCount()
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	if n > 0 {
		writeErr(w, 400, CodeConflict, "系统已初始化，请直接登录", nil)
		return
	}

	var req registerReq
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 3 || len(req.Username) > 20 {
		writeErr(w, 400, CodeValidation, "用户名长度必须在 3-20 个字符之间", nil)
		return
	}
	if st := CheckStrength(req.Password); st.Score < 3 {
		writeErr(w, 400, CodeValidation, "登录密码强度不足："+strings.Join(st.Feedback, "、"), nil)
		return
	}
	if st := CheckStrength(req.MasterPassword); st.Score < 3 {
		writeErr(w, 400, CodeValidation, "主密钥密码强度不足："+strings.Join(st.Feedback, "、"), nil)
		return
	}
	if req.Password == req.MasterPassword {
		// 双密码分离的意义在于两把钥匙互不牵连，相同则等于单密码
		writeErr(w, 400, CodeValidation, "主密钥密码不能与登录密码相同", nil)
		return
	}

	loginHash, err := hashPassword(req.Password)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	masterHash, err := hashPassword(req.MasterPassword)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	saltB64, keyB64, kdfType, paramsJSON, err := NewKey(req.MasterPassword)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}

	u := &User{
		Username:              req.Username,
		PasswordHash:          loginHash,
		MasterKeyPasswordHash: masterHash,
		MasterKeySalt:         saltB64,
		KDFType:               kdfType,
		KDFParams:             paramsJSON,
		Settings:              `{"theme":"light"}`,
	}
	id, err := a.store.CreateUser(u)
	if err != nil {
		writeErr(w, 400, CodeConflict, "注册失败：用户名可能已存在", nil)
		return
	}

	// 注册后主密钥即时可用（用户刚刚输入过主密钥密码）。
	// newSession 返回 sessionID 与 csrf，需在会话上直接设置主密钥。
	sid, token := a.newSession(w, id, u.Username)
	a.mu.Lock()
	sess := a.sessions[sid]
	a.mu.Unlock()
	if sess != nil {
		sess.unlock(keyB64)
	}
	a.store.Log(id, "register", "系统初始化")
	writeJSON(w, 200, map[string]any{"ok": true, "csrf": token, "unlocked": true})
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeErr(w, 400, CodeValidation, "请输入用户名", nil)
		return
	}
	// 限流键必须归一化：
	//   - IP 取真实来源（原先硬编码 127.0.0.1，等于所有客户端共用一个桶，
	//     一台机器上的多用户会把彼此挤掉；而经反向代理时又完全失去意义）
	//   - 用户名统一小写并去空白，否则 "Admin" / "admin " / "Admin" 各算一个桶，
	//     攻击者靠大小写变体即可绕过 5 次/5 分钟 的限制
	ip := clientIP(r)
	userKey := strings.ToLower(username)
	if !a.limiter.Allow("login_ip_"+ip, 10, time.Minute) ||
		!a.limiter.Allow("login_user_"+userKey, 5, 5*time.Minute) {
		writeErr(w, 429, CodeRateLimit, "尝试过于频繁，请稍后再试", nil)
		return
	}

	u, err := a.store.UserByName(username)
	if err != nil {
		// 用户不存在时也执行一次等价哈希，避免响应时间泄露「用户名是否存在」
		_, _ = bcrypt.GenerateFromPassword([]byte(req.Password), 12)
		writeErr(w, 401, CodeUnauthorized, "用户名或密码错误", nil)
		return
	}

	if locked, until := a.store.IsLocked(u); locked {
		secs := int(time.Until(until).Seconds())
		if secs < 1 {
			secs = 1
		}
		writeErr(w, 429, CodeLocked,
			fmt.Sprintf("账户已锁定，请在 %d 秒后重试", secs), nil)
		return
	}

	if !verifyPassword(req.Password, u.PasswordHash) {
		if err := a.store.RecordLoginFailure(u.ID, 5, 900); err != nil {
			// 记失败次数失败不影响本次登录结论，但必须留痕
			logf("记录登录失败次数出错 user=%d: %v", u.ID, err)
		}
		writeErr(w, 401, CodeUnauthorized, "用户名或密码错误", nil)
		return
	}

	if err := a.store.UpdateLoginSuccess(u.ID); err != nil {
		logf("重置登录失败计数出错 user=%d: %v", u.ID, err)
	}
	_, token := a.newSession(w, u.ID, u.Username)
	a.store.Log(u.ID, "login", "用户登录")

	// 登录时自动备份并轮转（备份含全部密文，必须限制数量）
	if name, size, err := a.store.Backup("backup"); err == nil {
		a.store.RotateBackups("backup", 30)
		a.store.Log(u.ID, "auto_backup", fmt.Sprintf("登录时自动备份: %s (%s)", name, humanSize(size)))
	}

	writeJSON(w, 200, map[string]any{"ok": true, "csrf": token, "unlocked": false, "username": u.Username})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	sid := a.sessionID(r)
	a.mu.Lock()
	delete(a.sessions, sid)
	delete(a.csrf, sid)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, 200, map[string]any{"ok": true})
}

type unlockReq struct {
	Password string `json:"password"`
}

func (a *App) handleUnlock(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	var req unlockReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !a.limiter.Allow(fmt.Sprintf("unlock_%d", s.UserID), 10, 5*time.Minute) {
		writeErr(w, 429, CodeRateLimit, "尝试过于频繁，请稍后再试", nil)
		return
	}

	u, err := a.store.UserByID(s.UserID)
	if err != nil {
		writeErr(w, 500, CodeInternal, "读取账户信息失败", err)
		return
	}

	verifyHash := u.MasterKeyPasswordHash
	if verifyHash == "" {
		// 旧账户没有独立的主密钥口令哈希，回退验证登录口令（与 PHP 版一致）
		verifyHash = u.PasswordHash
	}
	if !verifyPassword(req.Password, verifyHash) {
		writeErr(w, 401, CodeUnauthorized, "主密钥密码错误", nil)
		return
	}

	salt, err := base64.StdEncoding.DecodeString(u.MasterKeySalt)
	if err != nil || len(salt) == 0 {
		writeErr(w, 500, CodeInternal, "账户密钥参数损坏", err)
		return
	}
	keyB64, err := DeriveKey(req.Password, salt, u.KDFType, u.KDFParams)
	if err != nil {
		writeErr(w, 500, CodeInternal, "主密钥派生失败", err)
		return
	}

	s.unlock(keyB64)

	writeJSON(w, 200, map[string]any{"ok": true, "unlocked": true})
}

func (a *App) handleLock(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	s.lockNow()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	_, unlocked, _ := s.lockState(autoLockAfter)
	writeJSON(w, 200, map[string]any{
		"ok":       true,
		"username": s.Username,
		"unlocked": unlocked,
	})
}

type entryView struct {
	ID           int64  `json:"id"`
	CategoryID   int64  `json:"category_id"`
	Title        string `json:"title"`
	URL          string `json:"url"`
	Username     string `json:"username"`
	Notes        string `json:"notes"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	PasswordHint string `json:"password_hint"` // 固定掩码，绝不返回密文或明文
}

func toView(e Entry) entryView {
	return entryView{
		ID: e.ID, CategoryID: e.CategoryID, Title: e.Title, URL: e.URL,
		Username: e.Username, Notes: e.Notes, CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt, PasswordHint: "••••••••",
	}
}

func (a *App) handleListEntries(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	catID, _ := strconv.ParseInt(q.Get("category_id"), 10, 64)
	trash := q.Get("trash") == "1"

	items, total, err := a.store.ListEntries(s.UserID, ListOptions{
		CategoryID: catID, Search: q.Get("search"), Page: page, Limit: limit, ShowTrash: trash,
	})
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	views := make([]entryView, 0, len(items))
	for _, e := range items {
		views = append(views, toView(e))
	}
	if limit <= 0 {
		limit = 20
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "entries": views, "total": total,
		"page": max(page, 1), "limit": limit,
	})
}

type entryReq struct {
	CategoryID int64  `json:"category_id"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Notes      string `json:"notes"`
}

func (a *App) handleCreateEntry(w http.ResponseWriter, r *http.Request) {
	s, ok := a.requireUnlocked(w, r)
	if !ok {
		return
	}
	var req entryReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Title) == "" || req.Password == "" {
		writeErr(w, 400, CodeValidation, "标题和密码不能为空", nil)
		return
	}
	cipher, err := Encrypt(req.Password, s.masterKey())
	if err != nil {
		writeErr(w, 500, CodeInternal, "加密失败", err)
		return
	}
	id, err := a.store.InsertEntry(s.UserID, &Entry{
		CategoryID: req.CategoryID, Title: req.Title, URL: req.URL,
		Username: req.Username, Cipher: cipher, Notes: req.Notes,
	}, "")
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	a.store.Log(s.UserID, "add_entry", "新增记录: "+req.Title)
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

func (a *App) handleUpdateEntry(w http.ResponseWriter, r *http.Request) {
	s, ok := a.requireUnlocked(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, CodeValidation, "无效的 ID", nil)
		return
	}
	var req entryReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		writeErr(w, 400, CodeValidation, "标题不能为空", nil)
		return
	}
	if _, err := a.store.GetEntry(s.UserID, id, true); err != nil {
		writeErr(w, 404, CodeNotFound, "记录不存在", nil)
		return
	}

	newCipher := ""
	if req.Password != "" {
		newCipher, err = Encrypt(req.Password, s.masterKey())
		if err != nil {
			writeErr(w, 500, CodeInternal, "加密失败", err)
			return
		}
	}
	if err := a.store.UpdateEntry(s.UserID, &Entry{
		ID: id, CategoryID: req.CategoryID, Title: req.Title,
		URL: req.URL, Username: req.Username, Notes: req.Notes,
	}, newCipher); err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	a.store.Log(s.UserID, "update_entry", fmt.Sprintf("更新记录: %s (ID: %d)", req.Title, id))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, CodeValidation, "无效的 ID", nil)
		return
	}
	if r.URL.Query().Get("purge") == "1" {
		// 永久删除不影响解密，无需解锁；但仍需确认归属
		if _, err := a.store.GetEntry(s.UserID, id, true); err != nil {
			writeErr(w, 404, CodeNotFound, "记录不存在", nil)
			return
		}
		if err := a.store.Purge(s.UserID, id); err != nil {
			writeInternalErr(w, 500, err)
			return
		}
		a.store.Log(s.UserID, "purge_entry", fmt.Sprintf("永久删除 ID: %d", id))
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if err := a.store.SoftDelete(s.UserID, id); err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	a.store.Log(s.UserID, "delete_entry", fmt.Sprintf("移入回收站 ID: %d", id))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleRestoreEntry(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, CodeValidation, "无效的 ID", nil)
		return
	}
	if err := a.store.Restore(s.UserID, id); err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleRevealEntry 解密单条密码。
// 主密钥取自服务端会话，前端不传也不接触密钥 —— 这是相对 PHP 版的核心改进。
func (a *App) handleRevealEntry(w http.ResponseWriter, r *http.Request) {
	s, ok := a.requireUnlocked(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, CodeValidation, "无效的 ID", nil)
		return
	}
	e, err := a.store.GetEntry(s.UserID, id, false)
	if err != nil {
		writeErr(w, 404, CodeNotFound, "记录不存在或已删除", nil)
		return
	}
	plain, err := Decrypt(e.Cipher, s.masterKey())
	if err != nil {
		writeErr(w, 400, CodeDecryptFailed, "解密失败：主密钥不匹配或数据已损坏", err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "password": plain})
}

func (a *App) handleListCategories(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	list, err := a.store.ListCategories(s.UserID)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "categories": list})
}

type categoryReq struct {
	Name     string `json:"name"`
	ParentID int64  `json:"parent_id"`
	Icon     string `json:"icon"`
}

func (a *App) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	var req categoryReq
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, 400, CodeValidation, "分类名称不能为空", nil)
		return
	}
	if req.ParentID == 0 && name == "未分类" {
		writeErr(w, 400, CodeValidation, "「未分类」为系统内置分类，请使用其他名称", nil)
		return
	}
	if req.Icon == "" {
		req.Icon = "folder"
	}
	id, err := a.store.AddCategory(s.UserID, name, req.ParentID, req.Icon)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

func (a *App) handleUpdateCategory(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, CodeValidation, "无效的 ID", nil)
		return
	}
	var req categoryReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, 400, CodeValidation, "分类名称不能为空", nil)
		return
	}
	if err := a.store.RenameCategory(s.UserID, id, strings.TrimSpace(req.Name), req.Icon); err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleDeleteCategory(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, CodeValidation, "无效的 ID", nil)
		return
	}
	if err := a.store.DeleteCategory(s.UserID, id); err != nil {
		// 该错误是业务提示（分类下仍有记录），可直接展示；细节同时记日志
		writeErr(w, 400, CodeConflict, err.Error(), err)
		return
	}
	a.store.Log(s.UserID, "delete_category", fmt.Sprintf("删除分类 ID: %d", id))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	stats, err := a.store.Stats(s.UserID)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "stats": stats})
}

type genReq struct {
	Length   int  `json:"length"`
	Upper    bool `json:"upper"`
	Lower    bool `json:"lower"`
	Digits   bool `json:"digits"`
	Symbols  bool `json:"symbols"`
	AvoidAmb bool `json:"avoid_amb"`
}

func (a *App) handleGenerator(w http.ResponseWriter, r *http.Request) {
	if a.requireSession(w, r) == nil {
		return
	}
	var req genReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Length < 6 || req.Length > 64 {
		writeErr(w, 400, CodeValidation, "长度必须在 6-64 之间", nil)
		return
	}
	pw, err := generatePassword(req)
	if err != nil {
		writeErr(w, 400, CodeValidation, err.Error(), nil)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "password": pw, "strength": CheckStrength(pw)})
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (a *App) handleChangeLoginPassword(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	var req changePasswordReq
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := a.store.UserByID(s.UserID)
	if err != nil {
		writeErr(w, 500, CodeInternal, "用户不存在", nil)
		return
	}
	if !verifyPassword(req.OldPassword, u.PasswordHash) {
		writeErr(w, 401, CodeUnauthorized, "原登录密码错误", nil)
		return
	}
	if st := CheckStrength(req.NewPassword); st.Score < 3 {
		writeErr(w, 400, CodeValidation, "新密码强度不足："+strings.Join(st.Feedback, "、"), nil)
		return
	}
	h, err := hashPassword(req.NewPassword)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	if err := a.store.UpdateLoginPassword(s.UserID, h); err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	a.store.Log(s.UserID, "change_password", "修改登录密码")
	writeJSON(w, 200, map[string]any{"ok": true})
}

type changeMasterReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// handleChangeMasterPassword 轮换主密钥：备份 → 事务内全量重加密 → 提交。
//
// 注意：恢复密钥存储的是「用恢复密钥加密的主密钥」，轮换后旧备份解出的仍是旧主密钥，
// 必然解不开新密文。重新包装需要恢复密钥明文（轮换流程拿不到），因此必须作废旧备份
// 并明确告知用户重新生成 —— 而不是留下一个验证通过却找回失败的假有效状态。
func (a *App) handleChangeMasterPassword(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	var req changeMasterReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !a.limiter.Allow(fmt.Sprintf("mkchange_%d", s.UserID), 5, 5*time.Minute) {
		writeErr(w, 429, CodeRateLimit, "尝试过于频繁，请稍后再试", nil)
		return
	}
	u, err := a.store.UserByID(s.UserID)
	if err != nil {
		writeErr(w, 500, CodeInternal, "用户不存在", nil)
		return
	}
	verifyHash := u.MasterKeyPasswordHash
	if verifyHash == "" {
		verifyHash = u.PasswordHash
	}
	if !verifyPassword(req.OldPassword, verifyHash) {
		writeErr(w, 401, CodeUnauthorized, "原主密钥密码错误", nil)
		return
	}
	if st := CheckStrength(req.NewPassword); st.Score < 3 {
		writeErr(w, 400, CodeValidation, "新主密钥密码强度不足："+strings.Join(st.Feedback, "、"), nil)
		return
	}

	oldSalt, err := base64.StdEncoding.DecodeString(u.MasterKeySalt)
	if err != nil {
		writeErr(w, 500, CodeInternal, "账户密钥参数损坏", nil)
		return
	}
	oldKey, err := DeriveKey(req.OldPassword, oldSalt, u.KDFType, u.KDFParams)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}

	// 强制备份，失败即中止（备份是前置条件，不是尽力而为）
	if _, _, err := a.store.Backup("backup"); err != nil {
		writeErr(w, 500, CodeInternal, "修改前自动备份失败，已取消本次操作", nil)
		return
	}
	a.store.RotateBackups("backup", 30)

	newSalt, newKey, newKDF, newParams, err := NewKey(req.NewPassword)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	newMasterHash, err := hashPassword(req.NewPassword)
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}

	reencrypted, hadRecovery, err := a.store.ReencryptAll(s.UserID, oldKey, newKey,
		newSalt, newKDF, newParams, newMasterHash)
	if err != nil {
		writeErr(w, 500, CodeInternal, "修改失败，数据已回滚保持原样", err)
		return
	}

	s.unlock(newKey)

	msg := fmt.Sprintf("主密钥密码修改成功，已重新加密 %d 条记录", reencrypted)
	if hadRecovery {
		msg += "。原恢复密钥已失效，请重新生成"
	}
	a.store.Log(s.UserID, "change_master_key", msg)
	writeJSON(w, 200, map[string]any{
		"ok": true, "message": msg, "reencrypted": reencrypted,
		"recovery_invalidated": hadRecovery,
	})
}

func (a *App) handleListBackups(w http.ResponseWriter, r *http.Request) {
	if a.requireSession(w, r) == nil {
		return
	}
	list, err := a.store.ListBackups()
	if err != nil {
		writeInternalErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "backups": list})
}

func (a *App) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	s := a.requireSession(w, r)
	if s == nil {
		return
	}
	name, size, err := a.store.Backup("backup")
	if err != nil {
		writeErr(w, 500, CodeInternal, "备份失败，请查看日志", err)
		return
	}
	a.store.RotateBackups("backup", 30)
	a.store.Log(s.UserID, "backup_database", "手动备份: "+name)
	writeJSON(w, 200, map[string]any{"ok": true, "filename": name, "size": size, "size_formatted": humanSize(size)})
}

// handleShutdown 网页端「退出程序」：停掉本地服务，用户无需去任务管理器杀进程。
// 这是桌面版特有的需求 —— 浏览器版没有「进程」概念。
func (a *App) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if a.requireSession(w, r) == nil {
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "程序即将退出"})
	go func() {
		time.Sleep(300 * time.Millisecond) // 留出响应写回时间
		a.requestQuit()
	}()
}

// ---------- 辅助 ----------

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, 400, CodeValidation, "请求格式错误（JSON 解析失败）", err)
		return false
	}
	return true
}

// hashPassword 使用 Argon2id（m=64MB, t=4, p=1），与 PHP 的 password_hash 参数一致
func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, 4, 65536, 1, 32)
	// 输出 PHC 字符串，便于将来与 PHP 的 password_hash 互通校验
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=4,p=1$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword 解析 PHC 字符串校验，兼容 PHP 生成的 $argon2id$ / $2y$ 格式
func verifyPassword(pw, encoded string) bool {
	if strings.HasPrefix(encoded, "$argon2id$") {
		var mMB, t, p int
		parts := strings.Split(encoded, "$")
		// ["", "argon2id", "v=19", "m=65536,t=4,p=1", salt, hash]
		if len(parts) != 6 {
			return false
		}
		for _, kv := range strings.Split(parts[3], ",") {
			var k string
			var v int
			if _, err := fmt.Sscanf(kv, "%1s=%d", &k, &v); err != nil {
				continue
			}
			switch k {
			case "m":
				mMB = v
			case "t":
				t = v
			case "p":
				p = v
			}
		}
		salt, err := base64.RawStdEncoding.DecodeString(parts[4])
		if err != nil {
			return false
		}
		want, err := base64.RawStdEncoding.DecodeString(parts[5])
		if err != nil {
			return false
		}
		got := argon2.IDKey([]byte(pw), salt, uint32(t), uint32(mMB), uint8(p), uint32(len(want)))
		return subtle.ConstantTimeCompare(got, want) == 1
	}
	if strings.HasPrefix(encoded, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(encoded), []byte(pw)) == nil
	}
	return false
}

func generatePassword(req genReq) (string, error) {
	lower := "abcdefghijklmnopqrstuvwxyz"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	symbols := ".,:;?!@#$%^&*_-+=[]{}<>"
	amb := "0oOIlL1i"

	sets := []string{}
	if req.Lower {
		sets = append(sets, lower)
	}
	if req.Upper {
		sets = append(sets, upper)
	}
	if req.Digits {
		sets = append(sets, digits)
	}
	if req.Symbols {
		sets = append(sets, symbols)
	}
	if len(sets) == 0 {
		return "", errors.New("至少需要选择一种字符类型")
	}

	clean := func(s string) string {
		if !req.AvoidAmb {
			return s
		}
		out := make([]rune, 0, len(s))
		for _, r := range s {
			if !strings.ContainsRune(amb, r) {
				out = append(out, r)
			}
		}
		return string(out)
	}

	all := ""
	for i := range sets {
		sets[i] = clean(sets[i])
		all += sets[i]
	}
	if all == "" {
		return "", errors.New("字符集不能为空")
	}

	pw := make([]byte, req.Length)
	for i := range pw {
		pw[i] = all[randInt(len(all))]
	}
	// 保证每类至少出现一次，再打乱
	for _, s := range sets {
		if s == "" {
			continue
		}
		found := false
		for _, c := range pw {
			if strings.IndexByte(s, c) >= 0 {
				found = true
				break
			}
		}
		if !found {
			pw[randInt(req.Length)] = s[randInt(len(s))]
		}
	}
	for i := len(pw) - 1; i > 0; i-- {
		j := randInt(i + 1)
		pw[i], pw[j] = pw[j], pw[i]
	}
	return string(pw), nil
}
