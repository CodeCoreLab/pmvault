// 存储层：SQLite 读写，schema 与 PHP 版完全一致。
//
// 兼容性要求（来自实测）：
//   - users 表的 kdf_type / kdf_params / master_key_salt 必须原样保留并可解析
//   - passwords.cipher 为 base64(0x03 || IV12 || Tag16 || CT)
//   - category_id = 0 表示内置「未分类」，因此库中不声明、也不启用外键
package vault

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db        *sql.DB
	dbPath    string
	backupDir string
}

func OpenStore(dbPath, backupDir string) (*Store, error) {
	// _pragma 参数在每个连接建立时生效。WAL 让读写不互相阻塞，
	// busy_timeout 避免并发下立刻报 database is locked。
	dsn := fmt.Sprintf(
		"file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(0)",
		filepath.ToSlash(dbPath),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite 单写者模型：限制连接数避免写锁竞争
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{db: db, dbPath: dbPath, backupDir: backupDir}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrate 幂等建表，schema 与 PHP 版 database.php 保持一致。
// 已存在的库不会被改动，因此 PHP 版与 Go 版可以共用同一份文件。
func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			master_key_salt TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_login DATETIME,
			login_attempts INTEGER DEFAULT 0,
			locked_until DATETIME,
			settings TEXT,
			master_key_password_hash TEXT,
			kdf_type TEXT,
			kdf_params TEXT,
			recovery_key_salt TEXT,
			recovery_backup TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS categories (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			parent_id INTEGER DEFAULT 0,
			name TEXT NOT NULL,
			icon TEXT,
			sort_order INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS passwords (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			category_id INTEGER DEFAULT 0,
			title TEXT NOT NULL,
			url TEXT,
			username TEXT,
			cipher TEXT NOT NULL,
			notes TEXT,
			is_deleted INTEGER DEFAULT 0,
			deleted_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS password_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			password_id INTEGER NOT NULL,
			cipher TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			session_id TEXT UNIQUE NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			action TEXT NOT NULL,
			details TEXT,
			ip_address TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS system_settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			setting_key TEXT UNIQUE NOT NULL,
			setting_value TEXT,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS rate_limits (
			name TEXT PRIMARY KEY,
			count INTEGER NOT NULL DEFAULT 0,
			reset_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_passwords_user ON passwords(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_passwords_category ON passwords(category_id)`,
		`CREATE INDEX IF NOT EXISTS idx_passwords_deleted ON passwords(is_deleted)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("建表失败: %w (%s)", err, firstLine(q))
		}
	}
	// 默认系统设置
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('app_name','密码管理器')`)
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('app_logo','shield')`)
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	if len(s) > 90 {
		return s[:90]
	}
	return s
}

// ---------- 用户 ----------

type User struct {
	ID                    int64
	Username              string
	PasswordHash          string
	MasterKeyPasswordHash string
	MasterKeySalt         string
	KDFType               string
	KDFParams             string
	RecoveryKeySalt       string
	RecoveryBackup        string
	Settings              string
	LoginAttempts         int
	LockedUntil           sql.NullString
}

func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) UserByName(name string) (*User, error) {
	row := s.db.QueryRow(`SELECT id, username, password_hash,
		COALESCE(master_key_password_hash,''), COALESCE(master_key_salt,''),
		COALESCE(kdf_type,''), COALESCE(kdf_params,''),
		COALESCE(recovery_key_salt,''), COALESCE(recovery_backup,''),
		COALESCE(settings,''), COALESCE(login_attempts,0), locked_until
		FROM users WHERE username = ?`, name)
	return scanUser(row)
}

func (s *Store) UserByID(id int64) (*User, error) {
	row := s.db.QueryRow(`SELECT id, username, password_hash,
		COALESCE(master_key_password_hash,''), COALESCE(master_key_salt,''),
		COALESCE(kdf_type,''), COALESCE(kdf_params,''),
		COALESCE(recovery_key_salt,''), COALESCE(recovery_backup,''),
		COALESCE(settings,''), COALESCE(login_attempts,0), locked_until
		FROM users WHERE id = ?`, id)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.MasterKeyPasswordHash,
		&u.MasterKeySalt, &u.KDFType, &u.KDFParams, &u.RecoveryKeySalt,
		&u.RecoveryBackup, &u.Settings, &u.LoginAttempts, &u.LockedUntil)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) CreateUser(u *User) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO users
		(username, password_hash, master_key_password_hash, master_key_salt,
		 kdf_type, kdf_params, settings, created_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		u.Username, u.PasswordHash, u.MasterKeyPasswordHash, u.MasterKeySalt,
		u.KDFType, u.KDFParams, u.Settings, nowStr())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateLoginSuccess(id int64) error {
	_, err := s.db.Exec(`UPDATE users SET login_attempts=0, locked_until=NULL, last_login=? WHERE id=?`,
		nowStr(), id)
	return err
}

// 账户锁定时间统一使用带时区标记的 UTC 存储。
//
// 原实现写的是本地时间（time.Now().Add(...)），读的时候却用
// time.Parse("2006-01-02 15:04:05", ...) —— 注意 time.Parse 在没有时区信息时
// 按 UTC 解释，于是「写本地、读 UTC」在非 UTC 时区下会偏差一个时区：
// 东八区用户被锁 15 分钟，实际可能被锁 23 小时（或反过来完全锁不住）。
//
// 新版本统一写入 RFC3339（含 'Z' 或 ±hh:mm 偏移），可无歧义地还原为 UTC；
// 旧版本写入的是无时区信息的本地时间字符串，按本地时间解析以兼容存量数据。
const (
	lockTimeLayoutNew = time.RFC3339
	lockTimeLayoutOld = "2006-01-02 15:04:05"
)

// IsLocked 判断账户当前是否处于锁定期，并返回解锁截止时刻。
//
// 解析顺序：
//  1. 先试 RFC3339（新版本写入的带时区格式）→ 唯一确定，不存在歧义；
//  2. 再试旧的无时区格式 → 按本地时间解释（兼容历史数据）。
//
// 之所以不能对同一字符串同时按 UTC 和本地两种方式「取较晚的那个」：
// 新格式按本地方式再解一次会凭空多出时区偏移，让已过期的锁定又变回未过期。
func (s *Store) IsLocked(u *User) (bool, time.Time) {
	if u == nil || !u.LockedUntil.Valid || u.LockedUntil.String == "" {
		return false, time.Time{}
	}
	raw := strings.TrimSpace(u.LockedUntil.String)
	if raw == "" {
		return false, time.Time{}
	}
	if t, err := time.Parse(lockTimeLayoutNew, raw); err == nil {
		if t.After(time.Now()) {
			return true, t
		}
		return false, time.Time{}
	}
	if t, err := time.ParseInLocation(lockTimeLayoutOld, raw, time.Local); err == nil {
		if t.After(time.Now()) {
			return true, t
		}
	}
	return false, time.Time{}
}

func (s *Store) RecordLoginFailure(id int64, maxAttempts int, lockSeconds int) error {
	var attempts int
	if err := s.db.QueryRow(`SELECT COALESCE(login_attempts,0) FROM users WHERE id=?`, id).Scan(&attempts); err != nil {
		return err
	}
	attempts++
	var locked any
	if attempts >= maxAttempts {
		// 统一写 UTC（带时区标记），由 IsLocked 负责解析
		locked = time.Now().UTC().Add(time.Duration(lockSeconds) * time.Second).Format(lockTimeLayoutNew)
	}
	_, err := s.db.Exec(`UPDATE users SET login_attempts=?, locked_until=? WHERE id=?`, attempts, locked, id)
	return err
}

func (s *Store) UpdateLoginPassword(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	return err
}

// ---------- 分类 ----------

type Category struct {
	ID        int64  `json:"id"`
	ParentID  int64  `json:"parent_id"`
	Name      string `json:"name"`
	Icon      string `json:"icon"`
	SortOrder int    `json:"sort_order"`
}

func (s *Store) ListCategories(userID int64) ([]Category, error) {
	rows, err := s.db.Query(`SELECT id, COALESCE(parent_id,0), name, COALESCE(icon,'folder'),
		COALESCE(sort_order,0) FROM categories WHERE user_id=? ORDER BY sort_order, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Category{}
	for rows.Next() {
		var c Category
		if err := rows.Scan(&c.ID, &c.ParentID, &c.Name, &c.Icon, &c.SortOrder); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) AddCategory(userID int64, name string, parentID int64, icon string) (int64, error) {
	var maxOrder int
	_ = s.db.QueryRow(`SELECT COALESCE(MAX(sort_order),0) FROM categories WHERE user_id=? AND parent_id=?`,
		userID, parentID).Scan(&maxOrder)
	res, err := s.db.Exec(`INSERT INTO categories (user_id, parent_id, name, icon, sort_order, created_at)
		VALUES (?,?,?,?,?,?)`, userID, parentID, name, icon, maxOrder+1, nowStr())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) RenameCategory(userID, id int64, name, icon string) error {
	_, err := s.db.Exec(`UPDATE categories SET name=?, icon=? WHERE id=? AND user_id=?`,
		name, icon, id, userID)
	return err
}

// DeleteCategory 显式完成级联：外键在本库刻意关闭，关系一致性由此处维护。
// 仍有未删除记录时拒绝删除；回收站内记录归入「未分类」（category_id=0）。
func (s *Store) DeleteCategory(userID, id int64) error {
	var cnt int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM passwords
		WHERE category_id=? AND user_id=? AND is_deleted=0`, id, userID).Scan(&cnt); err != nil {
		return err
	}
	if cnt > 0 {
		return fmt.Errorf("该分类下还有 %d 条密码记录，请先删除或移动", cnt)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE passwords SET category_id=0 WHERE category_id=? AND user_id=?`, id, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM categories WHERE id=? AND user_id=?`, id, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CategoryChildrenIDs(userID, id int64) ([]int64, error) {
	ids := []int64{id}
	queue := []int64{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		rows, err := s.db.Query(`SELECT id FROM categories WHERE parent_id=? AND user_id=?`, cur, userID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var cid int64
			if err := rows.Scan(&cid); err != nil {
				rows.Close()
				return nil, err
			}
			ids = append(ids, cid)
			queue = append(queue, cid)
		}
		rows.Close()
	}
	return ids, nil
}

// ---------- 密码条目 ----------

type Entry struct {
	ID         int64  `json:"id"`
	CategoryID int64  `json:"category_id"`
	Title      string `json:"title"`
	URL        string `json:"url"`
	Username   string `json:"username"`
	Cipher     string `json:"-"`
	Notes      string `json:"notes"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type ListOptions struct {
	CategoryID int64
	Search     string
	Page       int
	Limit      int
	ShowTrash  bool
}

func (s *Store) ListEntries(userID int64, o ListOptions) ([]Entry, int, error) {
	where := `user_id = ? AND is_deleted = ?`
	args := []any{userID, boolToInt(o.ShowTrash)}

	if o.CategoryID > 0 {
		ids, err := s.CategoryChildrenIDs(userID, o.CategoryID)
		if err != nil {
			return nil, 0, err
		}
		ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		where += ` AND category_id IN (` + ph + `)`
		for _, id := range ids {
			args = append(args, id)
		}
	}
	if o.Search != "" {
		where += ` AND (title LIKE ? OR username LIKE ? OR url LIKE ? OR notes LIKE ?)`
		like := "%" + o.Search + "%"
		args = append(args, like, like, like, like)
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM passwords WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := `SELECT id, COALESCE(category_id,0), title, COALESCE(url,''), COALESCE(username,''),
		cipher, COALESCE(notes,''), created_at, updated_at
		FROM passwords WHERE ` + where + ` ORDER BY updated_at DESC LIMIT ? OFFSET ?`
	page, limit := o.Page, o.Limit
	if page < 1 {
		page = 1
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	args = append(args, limit, (page-1)*limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.CategoryID, &e.Title, &e.URL, &e.Username,
			&e.Cipher, &e.Notes, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func (s *Store) GetEntry(userID, id int64, includeTrash bool) (*Entry, error) {
	q := `SELECT id, COALESCE(category_id,0), title, COALESCE(url,''), COALESCE(username,''),
		cipher, COALESCE(notes,''), created_at, updated_at
		FROM passwords WHERE id=? AND user_id=?`
	if !includeTrash {
		q += ` AND is_deleted=0`
	}
	var e Entry
	err := s.db.QueryRow(q, id, userID).Scan(&e.ID, &e.CategoryID, &e.Title, &e.URL,
		&e.Username, &e.Cipher, &e.Notes, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) InsertEntry(userID int64, e *Entry, historyCipher string) (int64, error) {
	now := nowStr()
	res, err := s.db.Exec(`INSERT INTO passwords
		(user_id, category_id, title, url, username, cipher, notes, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		userID, e.CategoryID, e.Title, e.URL, e.Username, e.Cipher, e.Notes, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateEntry 在替换密文前把旧密文写入 history，与 PHP 版行为一致
func (s *Store) UpdateEntry(userID int64, e *Entry, newCipher string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if newCipher != "" {
		var old string
		err := tx.QueryRow(`SELECT cipher FROM passwords WHERE id=? AND user_id=?`, e.ID, userID).Scan(&old)
		if err == nil && old != "" && old != newCipher {
			if _, err := tx.Exec(`INSERT INTO password_history (password_id, cipher, created_at) VALUES (?,?,?)`,
				e.ID, old, nowStr()); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(`UPDATE passwords SET category_id=?, title=?, url=?, username=?,
			cipher=?, notes=?, updated_at=? WHERE id=? AND user_id=?`,
			e.CategoryID, e.Title, e.URL, e.Username, newCipher, e.Notes, nowStr(), e.ID, userID); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`UPDATE passwords SET category_id=?, title=?, url=?, username=?,
			notes=?, updated_at=? WHERE id=? AND user_id=?`,
			e.CategoryID, e.Title, e.URL, e.Username, e.Notes, nowStr(), e.ID, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SoftDelete 软删除：进回收站，不物理删除
func (s *Store) SoftDelete(userID, id int64) error {
	_, err := s.db.Exec(`UPDATE passwords SET is_deleted=1, deleted_at=? WHERE id=? AND user_id=? AND is_deleted=0`,
		nowStr(), id, userID)
	return err
}

func (s *Store) Restore(userID, id int64) error {
	_, err := s.db.Exec(`UPDATE passwords SET is_deleted=0, deleted_at=NULL WHERE id=? AND user_id=?`, id, userID)
	return err
}

// Purge 物理删除，同时清理历史版本（外键关闭，必须显式清理）
func (s *Store) Purge(userID, id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM password_history WHERE password_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM passwords WHERE id=? AND user_id=?`, id, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Stats(userID int64) (map[string]any, error) {
	var total, deleted, categories int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM passwords WHERE user_id=? AND is_deleted=0`, userID).Scan(&total); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM passwords WHERE user_id=? AND is_deleted=1`, userID).Scan(&deleted); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM categories WHERE user_id=?`, userID).Scan(&categories); err != nil {
		return nil, err
	}
	var size int64
	if st, err := os.Stat(s.dbPath); err == nil {
		size = st.Size()
	}
	return map[string]any{
		"total_passwords":   total,
		"deleted_passwords": deleted,
		"total_categories":  categories,
		"database_size":     humanSize(size),
	}, nil
}

// ---------- ��作日志 ----------

func (s *Store) Log(userID int64, action, details string) {
	_, err := s.db.Exec(`INSERT INTO logs (user_id, action, details, ip_address, created_at) VALUES (?,?,?,?,?)`,
		userID, action, details, "127.0.0.1", nowStr())
	if err != nil {
		logf("写入操作日志失败: %v", err)
	}
}

// ---------- 备份 ----------

type BackupInfo struct {
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	SizeText    string `json:"size_formatted"`
	CreatedAt   string `json:"created_at"`
	Timestamp   int64  `json:"timestamp"`
	IsEmergency bool   `json:"is_emergency"`
}

// Backup 用 VACUUM INTO 生成事务一致的快照（而非直接 copy 文件）。
// SQLite 直接把「同时有主文件与 WAL」的目录拷走可能得到半成品快照。
func (s *Store) Backup(prefix string) (string, int64, error) {
	if err := os.MkdirAll(s.backupDir, 0o700); err != nil {
		return "", 0, err
	}
	path := s.uniquePath(prefix)
	esc := strings.ReplaceAll(filepath.ToSlash(path), "'", "''")
	if _, err := s.db.Exec("VACUUM INTO '" + esc + "'"); err != nil {
		return "", 0, err
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		return "", 0, fmt.Errorf("备份文件创建失败或为空")
	}
	return filepath.Base(path), st.Size(), nil
}

func (s *Store) uniquePath(prefix string) string {
	ts := time.Now().Format("2006-01-02_15-04-05")
	p := filepath.Join(s.backupDir, fmt.Sprintf("%s_%s.db", prefix, ts))
	for i := 1; fileExists(p); i++ {
		p = filepath.Join(s.backupDir, fmt.Sprintf("%s_%s_%d.db", prefix, ts, i))
	}
	return p
}

func (s *Store) ListBackups() ([]BackupInfo, error) {
	entries, err := os.ReadDir(s.backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []BackupInfo{}, nil
		}
		return nil, err
	}
	out := []BackupInfo{}
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".db") {
			continue
		}
		if !strings.HasPrefix(name, "backup_") && !strings.HasPrefix(name, "emergency_backup_") {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupInfo{
			Filename:    name,
			Size:        info.Size(),
			SizeText:    humanSize(info.Size()),
			CreatedAt:   info.ModTime().Format(time.RFC3339),
			Timestamp:   info.ModTime().Unix(),
			IsEmergency: strings.HasPrefix(name, "emergency_backup_"),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp > out[j].Timestamp })
	return out, nil
}

// RotateBackups 只保留最近 keep 份，避免备份无限增长（备份是不加密的完整库副本）
//
// 删除失败必须留痕：备份文件里是完整的密文库，删不掉就意味着
// 「以为已清理、实际一直躺在磁盘上」，运维排查时完全看不见。
func (s *Store) RotateBackups(prefix string, keep int) {
	list, err := s.ListBackups()
	if err != nil {
		logf("轮转备份失败：读取备份列表出错 prefix=%s: %v", prefix, err)
		return
	}
	var matched []BackupInfo
	for _, b := range list {
		if strings.HasPrefix(b.Filename, prefix+"_") && !strings.HasPrefix(b.Filename, "emergency_backup_") {
			matched = append(matched, b)
		} else if prefix == "emergency_backup" && b.IsEmergency {
			matched = append(matched, b)
		}
	}
	// 已按时间倒序
	for i := keep; i < len(matched); i++ {
		path := filepath.Join(s.backupDir, matched[i].Filename)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logf("轮转备份失败：删除旧备份出错 %s: %v", path, err)
		}
	}
}

// ---------- 工具 ----------

// nowStr 返回带时区偏移的时间戳（RFC3339）。
//
// 为什么不用 "2006-01-02 15:04:05"：
//   - 该格式没有时区信息，而 SQLite 的 DEFAULT CURRENT_TIMESTAMP 写的是 UTC，
//     同一列里就会混入「本地时间」和「UTC」两种语义，前端无法区分，
//     结果是东八区用户看到的时间差 8 小时。
//   - 带偏移量的写法可以被前端精确换算到本地显示，跨时区、跨机器都不串。
//
// 旧数据仍是无偏移量的字符串，前端按 UTC 兜底解析（见 web/app.js 的 fmtTime）。
func nowStr() string { return time.Now().Format(time.RFC3339) }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	units := []string{"KB", "MB", "GB"}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit && exp < len(units)-1; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}
