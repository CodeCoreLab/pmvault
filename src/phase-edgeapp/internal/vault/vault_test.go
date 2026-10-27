package vault

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
