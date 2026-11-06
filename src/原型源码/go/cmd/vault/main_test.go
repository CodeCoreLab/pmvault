package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// TestRunDoesNotPrintDerivedMasterKey 验证运行原型时不会把派生主密钥打印到 stdout。
//
// 背景：修复前 main 里直接 `fmt.Printf("主密钥(base64) : %s", ...)`，
// 派生主密钥会落进终端回滚缓冲、CI 日志、截图、输出重定向文件。
// 修复后只输出指纹（sha256 前 8 位），足够人工核对一致性，又不泄漏密钥。
func TestRunDoesNotPrintDerivedMasterKey(t *testing.T) {
	const saltB64 = "R8wK0u9p6uwNKIqNc370hQ=="
	const password = "Master5678!xyz"

	var buf bytes.Buffer
	// iter 取小值只为让测试跑得快；派生逻辑与生产路径完全一致。
	if code := run(&buf, []string{"-salt", saltB64, "-pw", password, "-iter", "1000"}); code != 0 {
		t.Fatalf("run 退出码应为 0，实际=%d 输出=%s", code, buf.String())
	}
	out := buf.String()

	// 1) 输出里不得出现派生主密钥的 base64 明文
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatalf("salt 解码失败: %v", err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(derivePBKDF2(password, salt, 1000))
	if strings.Contains(out, keyB64) {
		t.Errorf("输出包含派生主密钥明文: %s", out)
	}
	// base64 的其它等价写法（带 padding 变体）同样不得出现
	if strings.Contains(out, strings.TrimRight(keyB64, "=")) {
		t.Errorf("输出包含派生主密钥明文（无 padding 变体）: %s", out)
	}

	// 2) 输出里不得出现 Argon2id 派生值的前缀明文
	a2B64 := base64.StdEncoding.EncodeToString(deriveArgon2id(password, salt, 2, 64*1024))
	if strings.Contains(out, a2B64[:16]) {
		t.Errorf("输出包含 Argon2id 派生值明文前缀: %s", out)
	}

	// 3) 必须给出指纹，且指纹是 sha256 前 8 位十六进制
	fp := keyFingerprint(derivePBKDF2(password, salt, 1000))
	if len(fp) != 8 {
		t.Fatalf("指纹长度应为 8，实际=%d (%q)", len(fp), fp)
	}
	if !strings.Contains(out, fp) {
		t.Errorf("输出应包含主密钥指纹 %s，实际输出=%s", fp, out)
	}
	if !strings.Contains(out, "指纹") {
		t.Errorf("输出应明确标注这是指纹，实际输出=%s", out)
	}
}

// TestKeySummaryContainsNoKeyMaterial 验证摘要行不含密钥材料本身。
func TestKeySummaryContainsNoKeyMaterial(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	line := keySummary("主密钥指纹(sha256前8位)", key)

	if strings.Contains(line, base64.StdEncoding.EncodeToString(key)) {
		t.Errorf("摘要行含 base64 密钥: %s", line)
	}
	if strings.Contains(line, string(key)) {
		t.Errorf("摘要行含密钥原始字节: %s", line)
	}
	if !strings.Contains(line, keyFingerprint(key)) {
		t.Errorf("摘要行应含指纹 %s，实际=%s", keyFingerprint(key), line)
	}
}

// TestKeyFingerprintIsStableAndDistinguishing 验证指纹稳定且能区分不同密钥。
func TestKeyFingerprintIsStableAndDistinguishing(t *testing.T) {
	k1 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	k2 := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	if keyFingerprint(k1) != keyFingerprint(k1) {
		t.Error("同一密钥的指纹应稳定")
	}
	if keyFingerprint(k1) == keyFingerprint(k2) {
		t.Error("不同密钥的指纹不应相同")
	}
	for _, k := range [][]byte{k1, k2} {
		fp := keyFingerprint(k)
		if len(fp) != 8 {
			t.Fatalf("指纹长度应为 8，实际=%d", len(fp))
		}
		for _, c := range fp {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Errorf("指纹应是小写十六进制，实际=%q", fp)
			}
		}
	}
}
