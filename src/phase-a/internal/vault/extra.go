package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"sync"
	"time"
)

// Limiter 数据库级限流：不依赖 Cookie，攻击者丢弃 Cookie 也绕不过
// （PHP 版从会话级改为 DB 级是同一个理由；本地应用用内存即可，
// 因为进程生命周期内有效，重启后归零对本地单用户场景无影响）
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

func NewLimiter() *Limiter {
	l := &Limiter{buckets: make(map[string]*bucket)}
	go l.gc()
	return l
}

func (l *Limiter) Allow(name string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[name]
	if b == nil || now.After(b.resetAt) {
		l.buckets[name] = &bucket{count: 1, resetAt: now.Add(window)}
		return true
	}
	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

func (l *Limiter) gc() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		l.mu.Lock()
		now := time.Now()
		for k, b := range l.buckets {
			if now.After(b.resetAt) {
				delete(l.buckets, k)
			}
		}
		l.mu.Unlock()
	}
}

// randInt 返回 [0,n) 的密码学安全随机数（等同于 PHP 的 random_int）
func randInt(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// ReencryptAll 轮换主密钥：备份已在调用方完成，此处只做事务内全量重加密。
//
// 必须覆盖 passwords（含回收站）与 password_history —— 历史版本同样用旧密钥加密，
// 漏掉会导致「主密码改了，但历史版本再也打不开」。
//
// 返回：重加密记录数、是否作废了恢复密钥、错误。
func (s *Store) ReencryptAll(userID int64, oldKey, newKey, newSalt, newKDF, newParams, newMasterHash string) (int, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()

	// 1. 密码条目（含回收站）
	type row struct {
		id  int64
		enc string
	}
	rows, err := tx.Query(`SELECT id, cipher FROM passwords WHERE user_id = ?`, userID)
	if err != nil {
		return 0, false, err
	}
	var entries []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.enc); err != nil {
			rows.Close()
			return 0, false, err
		}
		entries = append(entries, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, false, err
	}

	for _, r := range entries {
		plain, err := Decrypt(r.enc, oldKey)
		if err != nil {
			// 任何一条解不开就整批回滚：宁可失败也不产生半新半旧的中间态
			return 0, false, err
		}
		nc, err := Encrypt(plain, newKey)
		if err != nil {
			return 0, false, err
		}
		if _, err := tx.Exec(`UPDATE passwords SET cipher=? WHERE id=? AND user_id=?`, nc, r.id, userID); err != nil {
			return 0, false, err
		}
	}

	// 2. 历史版本
	hrows, err := tx.Query(`SELECT h.id, h.cipher FROM password_history h
		INNER JOIN passwords p ON h.password_id = p.id WHERE p.user_id = ?`, userID)
	if err != nil {
		return 0, false, err
	}
	var hist []row
	for hrows.Next() {
		var r row
		if err := hrows.Scan(&r.id, &r.enc); err != nil {
			hrows.Close()
			return 0, false, err
		}
		hist = append(hist, r)
	}
	hrows.Close()
	if err := hrows.Err(); err != nil {
		return 0, false, err
	}
	for _, r := range hist {
		plain, err := Decrypt(r.enc, oldKey)
		if err != nil {
			return 0, false, err
		}
		nc, err := Encrypt(plain, newKey)
		if err != nil {
			return 0, false, err
		}
		if _, err := tx.Exec(`UPDATE password_history SET cipher=? WHERE id=?`, nc, r.id); err != nil {
			return 0, false, err
		}
	}

	// 3. 账户参数；同时作废旧恢复密钥
	var hadRecovery int
	if err := tx.QueryRow(`SELECT CASE WHEN COALESCE(recovery_backup,'')<>'' THEN 1 ELSE 0 END
		FROM users WHERE id=?`, userID).Scan(&hadRecovery); err != nil {
		return 0, false, err
	}
	if hadRecovery == 1 {
		if _, err := tx.Exec(`UPDATE users SET recovery_key_salt=NULL, recovery_backup=NULL WHERE id=?`, userID); err != nil {
			return 0, false, err
		}
	}
	if _, err := tx.Exec(`UPDATE users SET master_key_password_hash=?, master_key_salt=?,
		kdf_type=?, kdf_params=? WHERE id=?`,
		newMasterHash, newSalt, newKDF, newParams, userID); err != nil {
		return 0, false, err
	}

	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return len(entries), hadRecovery == 1, nil
}

// TrustedKDFParams 供测试与迁移校验使用：把 kdf_params 规范化为语义化 JSON
func TrustedKDFParams(kdfType string, saltB64, keyB64 string) string {
	p := KDFParams{}
	if kdfType == kdfArgon2ID {
		p = KDFParams{OpsLimit: defaultArgon2Ops, MemLimit: defaultArgon2MemB}
	} else {
		p = KDFParams{Iters: defaultPBKDF2Iters}
	}
	b, _ := json.Marshal(p)
	return string(b)
}

// DecodeSalt 辅助：把 base64 salt 解成字节
func DecodeSalt(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}

func logf(format string, args ...any) { log.Printf(format, args...) }
