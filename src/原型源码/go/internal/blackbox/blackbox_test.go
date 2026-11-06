// Package blackbox 是原型的黑盒回归测试。
//
// 放在独立包（而不是 cmd/vault 包内）是有意的：
// 本测试只用「编译出二进制 → 跑一次 → 检查 stdout」的方式验证，
// 不引用 cmd/vault 包内的任何符号，因此**同一份测试代码**
// 在「缺陷版本」（直接打印 base64 主密钥）与「修复版本」下都能编译运行，
// 可以直接用于「缺陷版本失败 / 修复后通过」的双向验证。
package blackbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	testSaltB64 = "R8wK0u9p6uwNKIqNc370hQ=="
	testPassword = "Master5678!xyz"
	testIter     = "1000"
)

// TestBinaryStdoutHasNoDerivedMasterKey 验证原型运行时 stdout 不含派生主密钥明文。
//
// 背景：修复前原型直接 `fmt.Printf("主密钥(base64) : %s", ...)`，
// 派生主密钥会落进终端回滚缓冲 / CI 日志 / 截图 / 输出重定向文件。
func TestBinaryStdoutHasNoDerivedMasterKey(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("环境里没有 go 工具链，跳过黑盒测试")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "vaultproto")
	if runtime.GOOS == "windows" {
		// Windows 下没有扩展名的文件不能直接执行
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "../../cmd/vault")
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("编译原型失败: %v\n%s", err, out)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("编译产物不存在: %v", err)
	}

	cmd := exec.Command(bin, "-salt", testSaltB64, "-pw", testPassword, "-iter", testIter)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// 忽略退出码：不同版本的参数校验行为可能不同，这里只关心 stdout。
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		t.Fatalf("运行原型失败: %v\nstderr=%s", err, stderr.String())
	}
	out := stdout.String()

	salt, err := base64.StdEncoding.DecodeString(testSaltB64)
	if err != nil {
		t.Fatalf("salt 解码失败: %v", err)
	}
	keyB64 := deriveKeyB64(t, testPassword, salt)
	if strings.Contains(out, keyB64) {
		t.Errorf("stdout 含派生主密钥明文:\n%s", out)
	}
	if strings.Contains(out, strings.TrimRight(keyB64, "=")) {
		t.Errorf("stdout 含派生主密钥明文（无 padding 变体）:\n%s", out)
	}
	if strings.Contains(out, argon2PrefixB64(t, testPassword, salt)) {
		t.Errorf("stdout 含 Argon2id 派生值明文前缀:\n%s", out)
	}
}

// deriveKeyB64 在测试内独立复算一遍 PBKDF2 派生结果（不复用 cmd/vault 的代码，
// 以免测试与被测代码共享同一个 bug）。
func deriveKeyB64(t *testing.T, password string, salt []byte) string {
	t.Helper()
	key := pbkdf2Key(password, salt, 1000)
	return base64.StdEncoding.EncodeToString(key)
}

// pbkdf2Key 复现 PHP hash_pbkdf2('sha256', pw, salt, iterations, 32, true)。
func pbkdf2Key(password string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

// argon2PrefixB64 返回 Argon2id 派生值的 base64 前 16 字符（修复前原型打印的就是它）。
func argon2PrefixB64(t *testing.T, password string, salt []byte) string {
	t.Helper()
	a2 := argon2.IDKey([]byte(password), salt, 2, 64*1024, 1, 32)
	return base64.StdEncoding.EncodeToString(a2)[:16]
}
