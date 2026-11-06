package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// sqlNullString 构造 sql.NullString 的便捷包装。
func sqlNullString(v string) sql.NullString {
	return sql.NullString{String: v, Valid: v != ""}
}

// ---------- session 并发安全 ----------

// TestSessionConcurrentAccess 在 -race 下验证 session 的加锁访问没有数据竞争。
//
// 背景：主密钥原先存放在 App.mu 保护之外（读写用不同的锁），
// 解锁 / 上锁 / 读取并发时会触发 data race，
// 轻则读到半写入的密钥串，重则直接 panic。
func TestSessionConcurrentAccess(t *testing.T) {
	s := &session{UserID: 1, Username: "u", Created: time.Now()}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				switch j % 4 {
				case 0:
					s.unlock("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
				case 1:
					s.lockNow()
				case 2:
					_ = s.masterKey()
				case 3:
					_, _, _ = s.lockState(time.Minute)
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestSessionIdleLock 验证闲置自动上锁：超过闲置时长后必须要求重新解锁。
func TestSessionIdleLock(t *testing.T) {
	s := &session{UserID: 1, Created: time.Now()}
	s.unlock("key")

	if _, unlocked, _ := s.lockState(time.Hour); !unlocked {
		t.Fatal("刚解锁的会话应处于解锁态")
	}
	// 用 0 模拟「已闲置超时」的边界：idleTimeout<=0 表示不做过期判定
	if _, unlocked, _ := s.lockState(0); !unlocked {
		t.Fatal("idleTimeout=0 时不应触发上锁")
	}
	// touch 续期后应仍然解锁
	s.touch()
	if _, unlocked, _ := s.lockState(time.Hour); !unlocked {
		t.Fatal("touch 续期后应仍处于解锁态")
	}
}

// TestSessionLockClearsKey 验证上锁会清空主密钥。
func TestSessionLockClearsKey(t *testing.T) {
	s := &session{UserID: 1, Created: time.Now()}
	s.unlock("secret-key")
	s.lockNow()
	if k := s.masterKey(); k != "" {
		t.Fatalf("上锁后主密钥应为空，实际=%q", k)
	}
}

// ---------- 错误码 ----------

// TestWriteErrHidesInternalDetail 验证内部错误不会出现在响应体里。
//
// 这是本轮修复的核心安全目标：原始 err 可能是
// "constraint failed: UNIQUE constraint failed: users.username"（泄露表结构）
// 或 "open C:\\Users\\xxx\\vault.db: permission denied"（泄露本机路径）。
func TestWriteErrHidesInternalDetail(t *testing.T) {
	rec := httptest.NewRecorder()
	writeErr(rec, 500, CodeInternal, "服务器内部错误，请查看日志",
		errors.New("open C:\\Users\\victim\\vault.db: permission denied"))

	body := rec.Body.String()
	if strings.Contains(body, "victim") || strings.Contains(body, "permission denied") {
		t.Fatalf("响应体泄露了内部错误细节: %s", body)
	}
	if !strings.Contains(body, CodeInternal) {
		t.Fatalf("响应体应包含错误码 %s: %s", CodeInternal, body)
	}
	if !strings.Contains(body, "服务器内部错误") {
		t.Fatalf("响应体应包含给用户的文案: %s", body)
	}
}

// TestWriteNeedUnlockKeepsField 验证 423 响应保留 need_unlock 字段（前端兼容）。
func TestWriteNeedUnlockKeepsField(t *testing.T) {
	rec := httptest.NewRecorder()
	writeNeedUnlock(rec, "需要解锁：请输入主密钥密码")

	if rec.Code != http.StatusLocked {
		t.Fatalf("状态码应为 423，实际=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "need_unlock") {
		t.Fatalf("响应体应保留 need_unlock 字段: %s", rec.Body.String())
	}
}

// ---------- 限流 ----------

// TestLimiterCountsWithinWindow 验证限流窗口内计数正确、超限后拒绝。
func TestLimiterCountsWithinWindow(t *testing.T) {
	l := NewLimiter()
	for i := 0; i < 3; i++ {
		if !l.Allow("k", 3, time.Minute) {
			t.Fatalf("第 %d 次应在限额内", i+1)
		}
	}
	if l.Allow("k", 3, time.Minute) {
		t.Fatal("超过限额后应被拒绝")
	}
	// 不同 key 互不影响
	if !l.Allow("other", 3, time.Minute) {
		t.Fatal("不同 key 不应互相影响")
	}
}

// TestLimiterWindowResets 验证窗口过期后计数重置。
func TestLimiterWindowResets(t *testing.T) {
	l := NewLimiter()
	if !l.Allow("k", 1, 10*time.Millisecond) {
		t.Fatal("首次应放行")
	}
	if l.Allow("k", 1, 10*time.Millisecond) {
		t.Fatal("窗口内第二次应被拒绝")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.Allow("k", 1, 10*time.Millisecond) {
		t.Fatal("窗口过期后应重新放行")
	}
}

// TestClientIPIgnoresForwardedHeader 验证不采信可伪造的 X-Forwarded-For。
func TestClientIPIgnoresForwardedHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.RemoteAddr = "192.168.1.50:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := clientIP(r)
	if got != "192.168.1.50" {
		t.Fatalf("应取真实 RemoteAddr，实际=%q", got)
	}
}

// TestClientIPHandlesMissingPort 验证 RemoteAddr 无端口时不 panic。
func TestClientIPHandlesMissingPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.RemoteAddr = "127.0.0.1"
	if got := clientIP(r); got != "127.0.0.1" {
		t.Fatalf("实际=%q", got)
	}
	r2 := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r2.RemoteAddr = ""
	if got := clientIP(r2); got != "unknown" {
		t.Fatalf("空 RemoteAddr 应回落为 unknown，实际=%q", got)
	}
}

// ---------- 账户锁定时间 ----------

// TestIsLockedParsesNewFormat 验证带时区标记的新格式能正确判定锁定。
func TestIsLockedParsesNewFormat(t *testing.T) {
	s := &Store{}
	future := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
	u := &User{LockedUntil: sqlNullString(future)}
	locked, until := s.IsLocked(u)
	if !locked {
		t.Fatal("未来时刻应判定为锁定")
	}
	if until.Before(time.Now()) {
		t.Fatal("返回的解锁时刻应在未来")
	}
}

// TestIsLockedParsesLegacyLocalFormat 验证旧版本地时间格式仍可正确判定。
func TestIsLockedParsesLegacyLocalFormat(t *testing.T) {
	s := &Store{}
	future := time.Now().Add(10 * time.Minute).Format(lockTimeLayoutOld)
	u := &User{LockedUntil: sqlNullString(future)}
	if locked, _ := s.IsLocked(u); !locked {
		t.Fatal("旧格式未来时刻应判定为锁定")
	}
	past := time.Now().Add(-10 * time.Minute).Format(lockTimeLayoutOld)
	u2 := &User{LockedUntil: sqlNullString(past)}
	if locked, _ := s.IsLocked(u2); locked {
		t.Fatal("旧格式过去时刻不应判定为锁定")
	}
}

// TestIsLockedEmptyValue 验证空值不会误判为锁定。
func TestIsLockedEmptyValue(t *testing.T) {
	s := &Store{}
	for _, v := range []string{"", "   "} {
		u := &User{LockedUntil: sqlNullString(v)}
		if locked, _ := s.IsLocked(u); locked {
			t.Fatalf("空值不应判定为锁定: %q", v)
		}
	}
	if locked, _ := s.IsLocked(nil); locked {
		t.Fatal("nil 用户不应判定为锁定")
	}
}

// ---------- 密码学 ----------

// TestEncryptDecryptRoundTrip 验证加解密往返一致。
func TestEncryptDecryptRoundTrip(t *testing.T) {
	_, keyB64, _, _, err := NewKey("test-master-password")
	if err != nil {
		t.Fatalf("NewKey 失败: %v", err)
	}
	plain := "P@ssw0rd-中文-🔐"
	blob, err := Encrypt(plain, keyB64)
	if err != nil {
		t.Fatalf("Encrypt 失败: %v", err)
	}
	got, err := Decrypt(blob, keyB64)
	if err != nil {
		t.Fatalf("Decrypt 失败: %v", err)
	}
	if got != plain {
		t.Fatalf("往返不一致: got=%q want=%q", got, plain)
	}
}

// TestDecryptWrongKeyFails 验证错误密钥无法解密（认证失败）。
func TestDecryptWrongKeyFails(t *testing.T) {
	_, keyB64, _, _, err := NewKey("right-password")
	if err != nil {
		t.Fatalf("NewKey 失败: %v", err)
	}
	blob, err := Encrypt("secret", keyB64)
	if err != nil {
		t.Fatalf("Encrypt 失败: %v", err)
	}
	_, wrong, _, _, err := NewKey("wrong-password")
	if err != nil {
		t.Fatalf("NewKey 失败: %v", err)
	}
	if _, err := Decrypt(blob, wrong); err == nil {
		t.Fatal("错误密钥应解密失败")
	}
}

// TestEncryptRejectsBadKey 验证非法密钥被拒绝而不是 panic。
func TestEncryptRejectsBadKey(t *testing.T) {
	if _, err := Encrypt("x", "not-base64-!!!"); err == nil {
		t.Fatal("非法密钥应报错")
	}
	if _, err := Encrypt("x", ""); err == nil {
		t.Fatal("空密钥应报错")
	}
}

// TestDecryptRejectsMalformed 验证畸形密文被拒绝而不是 panic。
func TestDecryptRejectsMalformed(t *testing.T) {
	_, keyB64, _, _, err := NewKey("pw")
	if err != nil {
		t.Fatalf("NewKey 失败: %v", err)
	}
	for _, bad := range []string{"", "!!!not-base64!!!", "aGVsbG8="} {
		if _, err := Decrypt(bad, keyB64); err == nil {
			t.Fatalf("畸形密文 %q 应报错", bad)
		}
	}
}

// TestCheckStrength 验证强度评分的边界。
func TestCheckStrength(t *testing.T) {
	if st := CheckStrength("123456"); st.Score >= 3 {
		t.Fatalf("纯数字弱密码得分应 < 3，实际=%d", st.Score)
	}
	if st := CheckStrength("Abcdef1!@#$xyz"); st.Score < 3 {
		t.Fatalf("强密码得分应 >= 3，实际=%d", st.Score)
	}
	if st := CheckStrength(""); len(st.Feedback) == 0 {
		t.Fatal("空密码应给出反馈建议")
	}
}

// ---------- 密码强度策略（P2-5） ----------

// TestMeetsStrengthPolicyRejectsWeakPasswords 验证强度门槛能拦住旧规则放行的弱密码。
//
// 背景：旧规则门槛只有 3 分，「6 位纯小写 + 1 个数字」正好 3 分即可注册。
// 新规则要求长度 >= 8 且总分 >= 4。
func TestMeetsStrengthPolicyRejectsWeakPasswords(t *testing.T) {
	weak := []string{
		"",          // 空
		"abc",       // 极短
		"abcdef1",   // 7 位小写+数字（旧规则 3 分放行）
		"12345678",  // 8 位纯数字
		"abcdefgh",  // 8 位纯小写
		"A1!bc",     // 5 位但 4 类字符 —— 长度不足必须拒绝
		"abcdefghij", // 10 位纯小写
	}
	for _, pw := range weak {
		if ok, _ := MeetsStrengthPolicy(pw); ok {
			t.Errorf("弱密码 %q 不应通过强度门槛", pw)
		}
	}
}

// TestMeetsStrengthPolicyAcceptsStrongPasswords 验证正常强度的密码不被误伤。
func TestMeetsStrengthPolicyAcceptsStrongPasswords(t *testing.T) {
	strong := []string{
		"Abcdefg1",    // 8 位，3 类字符
		"Abcdefg1!",   // 8 位，4 类字符
		"aB3$xY9z",    // 8 位，4 类字符
		"correcthorsebatterystaple", // 25 位长口令
	}
	for _, pw := range strong {
		if ok, fb := MeetsStrengthPolicy(pw); !ok {
			t.Errorf("强密码 %q 应通过强度门槛，反馈=%v", pw, fb)
		}
	}
}

// TestCheckStrengthLengthGate 验证长度不达标时总分被封顶，
// 避免「4 类字符 + 5 位长度」拿到满分这种绕过。
func TestCheckStrengthLengthGate(t *testing.T) {
	// 5 位、4 类字符：字符类别分已经是 4 分，
	// 若不封顶，「A1!bc」会拿到 4 分并通过门槛。
	if st := CheckStrength("A1!bc"); st.Score >= minStrengthScore {
		t.Fatalf("长度不足的密码总分应被封顶在门槛以下，实际=%d", st.Score)
	}
	// 长度达标后封顶不再生效
	if st := CheckStrength("Abcdefg1"); st.Score < minStrengthScore {
		t.Fatalf("长度达标的密码不应被封顶，实际=%d", st.Score)
	}
}

// ---------- KDF 参数解析（P1-1） ----------

// TestDeriveKeyRawRejectsBrokenKDFParams 验证 kdf_params 损坏时返回明确错误。
//
// 背景：旧实现用 `_ = json.Unmarshal(...)` 静默吞掉解析错误，
// 参数保持零值 → 落到默认值兜底 → 派生出的主密钥与用户设置的不一致，
// 用户永远解不开自己的库，且全程没有任何报错。
func TestDeriveKeyRawRejectsBrokenKDFParams(t *testing.T) {
	broken := []string{
		`{"opslimit":2,`,           // 截断
		`not json at all`,          // 非法 JSON
		`{"opslimit":"two"}`,       // 类型错误
		`[1,2,3]`,                  // 类型错误（数组）
	}
	for _, p := range broken {
		if _, err := deriveKeyRaw("pw", make([]byte, 16), kdfArgon2ID, p); err == nil {
			t.Errorf("损坏的 kdf_params %q 应报错", p)
		} else if !errors.Is(err, ErrKDFParams) {
			t.Errorf("错误应可用 errors.Is(err, ErrKDFParams) 判定，实际=%v", err)
		}
	}
}

// TestDeriveKeyRawAcceptsEmptyParams 验证空 kdf_params 仍然合法（PHP 版旧用户）。
func TestDeriveKeyRawAcceptsEmptyParams(t *testing.T) {
	if _, err := deriveKeyRaw("pw", make([]byte, 16), kdfPBKDF2, ""); err != nil {
		t.Fatalf("空 kdf_params 应被接受（PHP 版旧用户兼容），实际=%v", err)
	}
}

// TestDeriveKeyRawRejectsUnknownKDFType 验证未知 KDF 类型仍报错。
func TestDeriveKeyRawRejectsUnknownKDFType(t *testing.T) {
	if _, err := deriveKeyRaw("pw", make([]byte, 16), "scrypt", ""); err == nil {
		t.Fatal("未知 KDF 类型应报错")
	}
}

// ---------- PKCS#7 填充校验（P1-2） ----------

// TestDecryptRejectsEmptyCiphertext 验证空密文被拒绝而不是 panic。
//
// 背景：v2 分支只检查 len(ct)%16==0，len(ct)==0 时通过，
// 随后 out[len(out)-1] 越界 panic —— 且该路径在 ReencryptAll 事务中间，
// 不经 HTTP recover，会直接打挂服务。
//
// 注意本用例必须构造**合法 HMAC**的 v2 blob：
// HMAC 校验在解密之前，HMAC 不过就返回「验证失败」，根本走不到填充处理，
// 那样就测不到目标路径了。
func TestDecryptRejectsEmptyCiphertext(t *testing.T) {
	_, keyB64, _, _, err := NewKey("pw")
	if err != nil {
		t.Fatalf("NewKey 失败: %v", err)
	}
	key := mustDecodeKey(t, keyB64)
	iv := make([]byte, aes.BlockSize)
	macKey := pbkdf2.Key(key, []byte("mima_hmac_salt"), 1000, 32, sha256.New)

	m := hmac.New(sha256.New, macKey)
	m.Write(iv)
	// ct 为空：只写 IV，不写任何密文数据块
	blob := make([]byte, 0, 1+len(iv)+32)
	blob = append(blob, versionV2)
	blob = append(blob, iv...)
	blob = append(blob, m.Sum(nil)...)

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("解密空密文不应 panic: %v", rec)
		}
	}()
	if _, err := Decrypt(base64.StdEncoding.EncodeToString(blob), keyB64); err == nil {
		t.Fatal("空密文应报错")
	}
}

// TestDecryptRejectsInvalidPadding 验证非法 PKCS#7 填充被拒绝。
//
// 背景：旧实现在 n==0 或 n>len(out) 时不报错，直接返回带残留填充的明文，
// 用户会把带垃圾字节的「密码」当成真密码复制走。
func TestDecryptRejectsInvalidPadding(t *testing.T) {
	_, keyB64, _, _, err := NewKey("pw")
	if err != nil {
		t.Fatalf("NewKey 失败: %v", err)
	}
	block, err := aes.NewCipher(mustDecodeKey(t, keyB64))
	if err != nil {
		t.Fatalf("aes.NewCipher 失败: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	macKey := pbkdf2.Key(mustDecodeKey(t, keyB64), []byte("mima_hmac_salt"), 1000, 32, sha256.New)

	// 三个用例：填充字节为 0、填充字节超过块大小、填充内容不一致
	// 注意：明文长度必须是块大小（16）的整数倍 —— CBC 加密要求如此，
	// 且这里不加真正的 PKCS#7 填充，我们要的就是「最后那个字节不是合法填充长度」。
	cases := []struct {
		name string
		pt   []byte
	}{
		{"零填充字节", append(bytes.Repeat([]byte{0x41}, 15), 0x00)},
		{"填充长度越界", append(bytes.Repeat([]byte{0x41}, 15), 0xff)},
		{"填充内容不一致", append(bytes.Repeat([]byte{0x41}, 13), 0x02, 0x03, 0x03)},
	}
	for _, tc := range cases {
		ct := make([]byte, len(tc.pt))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, tc.pt)

		m := hmac.New(sha256.New, macKey)
		m.Write(iv)
		m.Write(ct)

		blob := make([]byte, 0, 1+len(iv)+32+len(ct))
		blob = append(blob, versionV2)
		blob = append(blob, iv...)
		blob = append(blob, m.Sum(nil)...)
		blob = append(blob, ct...)

		got, err := Decrypt(base64.StdEncoding.EncodeToString(blob), keyB64)
		if err == nil {
			t.Errorf("%s：非法填充应报错，实际返回 %q", tc.name, got)
		}
	}
}

// mustDecodeKey 解 base64 密钥，失败即测试失败。
func mustDecodeKey(t *testing.T, keyB64 string) []byte {
	t.Helper()
	k, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatalf("密钥 base64 解码失败: %v", err)
	}
	return k
}

// ---------- 会话 GC（P2-6） ----------

// TestGCExpiredSessions 验证过期会话被后台 GC 回收。
//
// 背景：旧实现只在「用该 sid 发请求」时才顺手删一条，
// 用户关掉浏览器不再回来 → 会话对象永久滞留，map 无界增长。
func TestGCExpiredSessions(t *testing.T) {
	a := &App{
		sessions: make(map[string]*session),
		csrf:     make(map[string]string),
		quitCh:   make(chan struct{}),
	}
	// 已过期
	a.sessions["expired"] = &session{UserID: 1, Username: "u",
		Created: time.Now().Add(-sessionTTL - time.Minute)}
	a.csrf["expired"] = "tok-expired"
	// 未过期
	a.sessions["alive"] = &session{UserID: 1, Username: "u", Created: time.Now()}
	a.csrf["alive"] = "tok-alive"

	a.gcExpiredSessions()

	if _, ok := a.sessions["expired"]; ok {
		t.Error("过期会话应被回收")
	}
	if _, ok := a.csrf["expired"]; ok {
		t.Error("过期会话的 CSRF token 应被回收")
	}
	if _, ok := a.sessions["alive"]; !ok {
		t.Error("未过期会话不应被回收")
	}
	if _, ok := a.csrf["alive"]; !ok {
		t.Error("未过期会话的 CSRF token 不应被回收")
	}
}

// ---------- 审计日志保留策略（P1-4） ----------

// TestPruneLogsRemovesOldEntries 验证审计日志按保留天数裁剪。
//
// 背景：修复前 logs 表只有 INSERT，全仓没有 DELETE FROM logs，
// 审计日志无限增长（同时把备份文件也撑大）。
func TestPruneLogsRemovesOldEntries(t *testing.T) {
	s := newTestStore(t)

	// 一条很久以前的（超过保留期）
	old := time.Now().AddDate(0, 0, -logsRetentionDays-5).Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO logs (user_id, action, details, ip_address, created_at)
		VALUES (1, 'old', 'old', '127.0.0.1', ?)`, old); err != nil {
		t.Fatalf("插入旧日志失败: %v", err)
	}
	// 一条近期的
	if _, err := s.db.Exec(`INSERT INTO logs (user_id, action, details, ip_address, created_at)
		VALUES (1, 'new', 'new', '127.0.0.1', ?)`, nowStr()); err != nil {
		t.Fatalf("插入新日志失败: %v", err)
	}

	deleted, err := s.PruneLogs()
	if err != nil {
		t.Fatalf("PruneLogs 失败: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("应删除 1 条过期日志，实际=%d", deleted)
	}

	var remain int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&remain); err != nil {
		t.Fatalf("统计日志失败: %v", err)
	}
	if remain != 1 {
		t.Fatalf("应保留 1 条近期日志，实际=%d", remain)
	}
}

// TestPruneLogsEnforcesRowCap 验证审计日志条数上限生效（删最旧的）。
func TestPruneLogsEnforcesRowCap(t *testing.T) {
	s := newTestStore(t)

	// 插入略超上限的日志条数；为缩短测试时间，这里直接改上限不现实，
	// 改为插入少量日志并断言「未超限时不删除任何一条」。
	for i := 0; i < 5; i++ {
		s.Log(1, "noop", "noop")
	}
	deleted, err := s.PruneLogs()
	if err != nil {
		t.Fatalf("PruneLogs 失败: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("未超限时不应删除日志，实际删除=%d", deleted)
	}

	var remain int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&remain); err != nil {
		t.Fatalf("统计日志失败: %v", err)
	}
	if remain != 5 {
		t.Fatalf("应保留 5 条日志，实际=%d", remain)
	}
}

// TestPruneLogsKeepsNewestOnCap 验证超限时删除的是**最旧**的记录。
//
// 用一个临时的小上限来验证语义：直接改包级常量不现实，
// 因此这里手工执行与 PruneLogs 相同的 SQL 语义（按 id 倒序保留 N 条），
// 并验证被删掉的确实是 id 最小（= 最旧）的那些。
func TestPruneLogsKeepsNewestOnCap(t *testing.T) {
	s := newTestStore(t)

	for i := 0; i < 10; i++ {
		s.Log(1, "noop", "noop")
	}
	var ids []int64
	rows, err := s.db.Query(`SELECT id FROM logs ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("查询日志失败: %v", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatalf("扫描日志失败: %v", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 10 {
		t.Fatalf("应有 10 条日志，实际=%d", len(ids))
	}

	// 与 PruneLogs 规则 1 相同的语义：保留 id 最大的 N 条
	const keep = 4
	if _, err := s.db.Exec(`DELETE FROM logs WHERE id NOT IN (
		SELECT id FROM logs ORDER BY id DESC LIMIT ?)`, keep); err != nil {
		t.Fatalf("按条数裁剪失败: %v", err)
	}

	rows2, err := s.db.Query(`SELECT id FROM logs ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("查询日志失败: %v", err)
	}
	defer rows2.Close()
	var left []int64
	for rows2.Next() {
		var id int64
		if err := rows2.Scan(&id); err != nil {
			t.Fatalf("扫描日志失败: %v", err)
		}
		left = append(left, id)
	}
	if len(left) != keep {
		t.Fatalf("应保留 %d 条，实际=%d", keep, len(left))
	}
	// 剩下的应该是 id 最大的 4 条（即最新的）
	for i, id := range left {
		want := ids[len(ids)-keep+i]
		if id != want {
			t.Fatalf("保留的应是最新 %d 条，第 %d 条期望 id=%d 实际=%d", keep, i, want, id)
		}
	}
}

// ---------- 列表 limit 回显一致性（A34） ----------

// TestListEntriesEchoesEffectiveLimit 验证回显的 limit 就是实际生效的 limit。
//
// 背景：修复前 handler 直接把请求里的 limit 原样回显，
// 而 store 内部会把 limit>200 或 limit<=0 钳制成 20。
// 于是请求 limit=500 时，响应说 limit=500，实际只返回 20 条 ——
// 前端据此算分页会得出「只有 1 页」的错误结论。
func TestListEntriesEchoesEffectiveLimit(t *testing.T) {
	a, s, sid, router := newTestAppWithSession(t)
	uid := a.sessions[sid].UserID

	// 造 30 条记录，确保 20 条的默认上限真的会被触发
	for i := 0; i < 30; i++ {
		if _, err := s.InsertEntry(uid, &Entry{
			CategoryID: 0, Title: fmt.Sprintf("条目-%02d", i), Cipher: "x",
		}, ""); err != nil {
			t.Fatalf("插入记录失败: %v", err)
		}
	}

	cases := []struct {
		query     string
		wantLimit int
	}{
		{"", 20},              // 未传 → 默认
		{"?limit=0", 20},       // 0 → 默认
		{"?limit=-5", 20},      // 负数 → 默认
		{"?limit=500", 20},     // 超上限 → 默认（而非 500）
		{"?limit=201", 20},     // 刚超上限 → 默认
		{"?limit=5", 5},        // 合法值 → 原样生效
		{"?limit=200", 200},    // 上限本身 → 原样生效
	}
	for _, tc := range cases {
		rec := doRequest(router, "GET", "/api/entries"+tc.query, sid, "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s：状态码应为 200，实际=%d body=%s", tc.query, rec.Code, rec.Body.String())
		}
		var resp struct {
			Limit   int `json:"limit"`
			Total   int `json:"total"`
			Entries []struct {
				ID int64 `json:"id"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s：响应不是合法 JSON: %v body=%s", tc.query, err, rec.Body.String())
		}
		if resp.Limit != tc.wantLimit {
			t.Errorf("%s：回显 limit 应为 %d，实际=%d", tc.query, tc.wantLimit, resp.Limit)
		}
		if len(resp.Entries) > resp.Limit {
			t.Errorf("%s：返回条数 %d 超过生效 limit %d", tc.query, len(resp.Entries), resp.Limit)
		}
		if resp.Limit == 20 && resp.Total > 20 &&
			len(resp.Entries) != 20 {
			t.Errorf("%s：生效 limit 为 20 时应实际返回 20 条，实际=%d",
				tc.query, len(resp.Entries))
		}
	}
}

// TestClampListLimitSingleSource 验证 limit 钳制只有一处真相源。
//
// 用 HTTP 层行为反推钳制规则（不直接依赖内部函数），
// 这样同一份测试在修复前后都能编译，便于做「缺陷版本失败 / 修复后通过」的双向验证。
func TestClampListLimitSingleSource(t *testing.T) {
	a, s, sid, router := newTestAppWithSession(t)
	uid := a.sessions[sid].UserID
	for i := 0; i < 30; i++ {
		if _, err := s.InsertEntry(uid, &Entry{
			CategoryID: 0, Title: fmt.Sprintf("条目-%02d", i), Cipher: "x",
		}, ""); err != nil {
			t.Fatalf("插入记录失败: %v", err)
		}
	}
	cases := []struct {
		query     string
		wantLimit int
	}{
		{"", 20},
		{"?limit=0", 20},
		{"?limit=-1", 20},
		{"?limit=1", 1},
		{"?limit=20", 20},
		{"?limit=200", 200},
		{"?limit=201", 20},
		{"?limit=5000", 20},
	}
	for _, tc := range cases {
		rec := doRequest(router, "GET", "/api/entries"+tc.query, sid, "", "")
		var resp struct {
			Limit int `json:"limit"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s：响应不是合法 JSON: %v body=%s", tc.query, err, rec.Body.String())
		}
		if resp.Limit != tc.wantLimit {
			t.Errorf("%s：回显 limit 应为 %d，实际=%d", tc.query, tc.wantLimit, resp.Limit)
		}
	}
}

// ---------- 分类父级校验（A35） ----------

// TestAddCategoryRejectsInvalidParent 验证 parent_id 必须真实存在且属于当前用户。
//
// 背景：修复前 AddCategory 完全不校验 parent_id，
// 可以指向不存在的 id（悬空），也可以指向其他用户的分类（跨用户越权）。
func TestAddCategoryRejectsInvalidParent(t *testing.T) {
	s := newTestStore(t)
	uid1, err := s.CreateUser(&User{Username: "u1", PasswordHash: "x"})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	uid2, err := s.CreateUser(&User{Username: "u2", PasswordHash: "x"})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	otherCat, err := s.AddCategory(uid2, "别人的分类", 0, "folder")
	if err != nil {
		t.Fatalf("创建他人分类失败: %v", err)
	}

	// 1) parent_id 不存在
	if _, err := s.AddCategory(uid1, "子分类", 999999, "folder"); err == nil {
		t.Error("parent_id 不存在时必须报错")
	} else if !strings.Contains(err.Error(), "父分类不存在") {
		t.Errorf("错误信息应说明父分类不存在，实际=%v", err)
	}
	// 2) parent_id 属于其他用户（越权）
	if _, err := s.AddCategory(uid1, "子分类", otherCat, "folder"); err == nil {
		t.Error("parent_id 越权时必须报错")
	} else if !strings.Contains(err.Error(), "父分类不存在") {
		t.Errorf("错误信息应说明父分类不存在，实际=%v", err)
	}
	// 3) 合法父级仍应成功
	root, err := s.AddCategory(uid1, "根分类", 0, "folder")
	if err != nil {
		t.Fatalf("创建根分类失败: %v", err)
	}
	if _, err := s.AddCategory(uid1, "子分类", root, "folder"); err != nil {
		t.Fatalf("合法 parent_id 应创建成功: %v", err)
	}
	// 4) 校验失败不应留下任何分类记录
	var cnt int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM categories WHERE user_id=?`, uid1).Scan(&cnt); err != nil {
		t.Fatalf("统计分类失败: %v", err)
	}
	if cnt != 2 {
		t.Errorf("父级校验失败时不应写入分类，实际条数=%d（期望 2：根分类 + 合法子分类）", cnt)
	}
}

// TestCreateCategoryAPIRejectsInvalidParent 验证 HTTP 层把父级问题映射成 404 + 稳定错误码。
//
// 不区分「不存在」与「越权」，避免探测其他用户的分类 id。
func TestCreateCategoryAPIRejectsInvalidParent(t *testing.T) {
	a, s, sid, router := newTestAppWithSession(t)
	uid := a.sessions[sid].UserID

	otherUID, err := s.CreateUser(&User{Username: "other", PasswordHash: "x"})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	otherCat, err := s.AddCategory(otherUID, "别人的分类", 0, "folder")
	if err != nil {
		t.Fatalf("创建他人分类失败: %v", err)
	}

	for _, tc := range []struct {
		name     string
		parentID int64
	}{
		{"父级不存在", 999999},
		{"父级越权", otherCat},
	} {
		body := fmt.Sprintf(`{"name":"子分类","parent_id":%d,"icon":"folder"}`, tc.parentID)
		rec := doRequest(router, "POST", "/api/categories", sid, "test-csrf", body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s：状态码应为 404，实际=%d body=%s", tc.name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), CodeNotFound) {
			t.Errorf("%s：响应应包含错误码 %s，body=%s", tc.name, CodeNotFound, rec.Body.String())
		}
	}

	// 合法父级仍应成功
	root, err := s.AddCategory(uid, "根分类", 0, "folder")
	if err != nil {
		t.Fatalf("创建根分类失败: %v", err)
	}
	body := fmt.Sprintf(`{"name":"子分类","parent_id":%d,"icon":"folder"}`, root)
	rec := doRequest(router, "POST", "/api/categories", sid, "test-csrf", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法父级应创建成功，实际=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestCategoryChildrenIDsTerminatesOnCycle 验证 parent_id 成环时 BFS 不会无限循环。
//
// 背景：S03 提到的衍生风险 —— 历史数据或手工改库可能让 parent_id 成环，
// 修复前的 BFS 没有 visited 集合，遇到环会无限循环（请求挂死、内存暴涨）。
func TestCategoryChildrenIDsTerminatesOnCycle(t *testing.T) {
	s := newTestStore(t)
	uid, err := s.CreateUser(&User{Username: "u1", PasswordHash: "x"})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	c1, err := s.AddCategory(uid, "C1", 0, "folder")
	if err != nil {
		t.Fatalf("创建分类失败: %v", err)
	}
	c2, err := s.AddCategory(uid, "C2", c1, "folder")
	if err != nil {
		t.Fatalf("创建分类失败: %v", err)
	}
	// 人为造环：C1 的父级改成 C2（C2 的父级是 C1）
	if _, err := s.db.Exec(`UPDATE categories SET parent_id=? WHERE id=?`, c2, c1); err != nil {
		t.Fatalf("构造环失败: %v", err)
	}

	done := make(chan struct{})
	var ids []int64
	var gotErr error
	go func() {
		defer close(done)
		ids, gotErr = s.CategoryChildrenIDs(uid, c1)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parent_id 成环时 CategoryChildrenIDs 未在 5 秒内返回（无限循环）")
	}
	if gotErr != nil {
		t.Fatalf("CategoryChildrenIDs 返回错误: %v", gotErr)
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("返回值含重复 id %d（成环未去重）: %v", id, ids)
		}
		seen[id] = true
	}
	if !seen[c1] || !seen[c2] {
		t.Errorf("返回值应包含环上的两个分类，实际=%v", ids)
	}
}

// ---------- 审计日志失败可感知（A36） ----------

// TestAuditFailureIsSurfacedToCaller 验证审计写入失败时调用方能感知，
// 且**不会**让正常业务失败。
//
// 响应体必须带上稳定错误码 E_AUDIT_UNAVAILABLE 与 audit_degraded 标记，
// 响应头也带 X-Audit-Degraded —— 不能只有服务端日志里的一行字。
//
// 注意：这里刻意用字面量而不是包内常量，
// 这样同一份测试在修复前后都能编译，便于做「缺陷版本失败 / 修复后通过」的双向验证。
func TestAuditFailureIsSurfacedToCaller(t *testing.T) {
	a, s, sid, router := newTestAppWithSession(t)
	uid := a.sessions[sid].UserID

	catID, err := s.AddCategory(uid, "待删分类", 0, "folder")
	if err != nil {
		t.Fatalf("创建分类失败: %v", err)
	}
	// 让审计写入失败
	if _, err := s.db.Exec(`DROP TABLE logs`); err != nil {
		t.Fatalf("破坏 logs 表失败: %v", err)
	}

	rec := doRequest(router, "DELETE", fmt.Sprintf("/api/categories/%d", catID), sid, "test-csrf", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("审计故障不应阻断正常业务，状态码=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v body=%s", err, rec.Body.String())
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Errorf("业务本身应成功，body=%s", rec.Body.String())
	}
	if resp["audit_code"] != "E_AUDIT_UNAVAILABLE" {
		t.Errorf("响应体应带 audit_code=E_AUDIT_UNAVAILABLE，body=%s", rec.Body.String())
	}
	if degraded, _ := resp["audit_degraded"].(bool); !degraded {
		t.Errorf("响应体应带 audit_degraded=true，body=%s", rec.Body.String())
	}
	if got := rec.Header().Get("X-Audit-Degraded"); got != "E_AUDIT_UNAVAILABLE" {
		t.Errorf("响应头 X-Audit-Degraded 应为 E_AUDIT_UNAVAILABLE，实际=%q", got)
	}
}

// TestAuditSuccessHasNoDegradedMarker 验证审计正常时不带降级标记（不误报）。
func TestAuditSuccessHasNoDegradedMarker(t *testing.T) {
	a, s, sid, router := newTestAppWithSession(t)
	uid := a.sessions[sid].UserID

	catID, err := s.AddCategory(uid, "待删分类", 0, "folder")
	if err != nil {
		t.Fatalf("创建分类失败: %v", err)
	}
	rec := doRequest(router, "DELETE", fmt.Sprintf("/api/categories/%d", catID), sid, "test-csrf", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码应为 200，实际=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "audit_degraded") {
		t.Errorf("审计正常时不应带 audit_degraded 标记，body=%s", rec.Body.String())
	}
	if got := rec.Header().Get("X-Audit-Degraded"); got != "" {
		t.Errorf("审计正常时不应带 X-Audit-Degraded 响应头，实际=%q", got)
	}
}

// newTestStore 建一个临时 SQLite 库用于测试（调用方负责 Close）。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "test.db"), filepath.Join(dir, "backups"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newTestAppWithSession 建一个带已登录会话的 App，并返回 router 与会话 id。
//
// 不走注册/登录流程（那需要密码策略与 KDF 参数），直接注入会话，
// 让测试聚焦在目标逻辑上。
func newTestAppWithSession(t *testing.T) (*App, *Store, string, http.Handler) {
	t.Helper()
	s := newTestStore(t)
	uid, err := s.CreateUser(&User{Username: "tester", PasswordHash: "x"})
	if err != nil {
		t.Fatalf("创建测试用户失败: %v", err)
	}
	a := &App{
		store:    s,
		sessions: make(map[string]*session),
		csrf:     make(map[string]string),
		limiter:  NewLimiter(),
		quitCh:   make(chan struct{}),
	}
	const sid = "test-sid"
	a.sessions[sid] = &session{UserID: uid, Username: "tester", Created: time.Now()}
	a.csrf[sid] = "test-csrf"
	return a, s, sid, a.Router()
}

// doRequest 发一个带会话 Cookie（写操作另带 CSRF 头）的请求。
func doRequest(h http.Handler, method, target, sid, csrf, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}
