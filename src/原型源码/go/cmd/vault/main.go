// Go 迁移可行性验证原型
//
// 目标：证明 Go 可等价复现 PHP 版密码管理器 2.0 的加密体系，
// 从而支持「换语言实现但保留历史数据」的平滑迁移。
//
// 覆盖：
//  1. PBKDF2-HMAC-SHA256 600k 派生（PHP 当前实际使用的 KDF）
//  2. AES-256-GCM v3 格式解析      base64(0x03 || IV12 || Tag16 || CT)
//  3. 双向互通（Go 加密 → Go 解密自校验）
//  4. Argon2id 路径（PHP 因常量名写错未启用，Go 侧现成可用）
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	versionV3 byte = 0x03
	versionV2 byte = 0x02
)

// keyFingerprint 返回派生密钥的指纹（sha256 前 8 位十六进制）。
//
// 【为什么不能打印密钥本身】主密钥是解密一切历史数据的关键材料，
// 把它打到 stdout 会：落进终端回滚缓冲 / CI 日志 / 截图 / 进程输出重定向文件。
// 人工核对「两侧派生出的是不是同一个密钥」只需要一个指纹就够了：
// 指纹相同即等价，指纹不同即不等价，无需看到密钥本身。
func keyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:8]
}

// keySummary 返回展示用的派生密钥摘要行：只含指纹，绝不含密钥本身。
//
// 单独抽出来是为了能直接对「输出内容」做断言（见 main_test.go），
// 避免测试只能靠 grep 源码这种脆弱手段。
func keySummary(label string, key []byte) string {
	return fmt.Sprintf("%s: %s", label, keyFingerprint(key))
}

// derivePBKDF2 复现 PHP hash_pbkdf2('sha256', pw, salt, 600000, 32, true)
func derivePBKDF2(password string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

// deriveArgon2id 对应 sodium_crypto_pwhash(32, pw, salt, ops=2, mem=64MB, ALG_ARGON2ID13)
// 注：sodium 的 opslimit/memlimit 与 argon2 的 time/memory 不是同名同义，
// 此处给出可直接用于等价性验证的参数映射。
func deriveArgon2id(password string, salt []byte, time uint32, memoryKiB uint32) []byte {
	return argon2.IDKey([]byte(password), salt, time, memoryKiB, 1, 32)
}

// decryptV3 解析 PHP v3 格式并解密
func decryptV3(blobB64 string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil {
		return "", fmt.Errorf("base64 解码失败: %w", err)
	}
	if len(data) < 29 {
		return "", fmt.Errorf("数据过短: %d 字节", len(data))
	}
	if data[0] != versionV3 {
		return "", fmt.Errorf("版本字节不符: 期望 0x03 实际 0x%02x", data[0])
	}
	iv := data[1:13]
	tag := data[13:29]
	ct := data[29:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("建 cipher 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM 初始化失败: %w", err)
	}
	// Go 的 GCM 期望 ciphertext||tag 拼接
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)

	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("GCM 认证失败（密钥错误或数据被篡改）: %w", err)
	}
	return string(plain), nil
}

// encryptV3 生成与 PHP 完全一致的 v3 格式（用于反向互通验证）
func encryptV3(plain string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, []byte(plain), nil) // ciphertext || tag
	split := len(sealed) - 16
	ct, tag := sealed[:split], sealed[split:]

	blob := make([]byte, 0, 1+12+16+len(ct))
	blob = append(blob, versionV3)
	blob = append(blob, iv...)
	blob = append(blob, tag...)
	blob = append(blob, ct...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// sniff 模拟 PHP 的三格式识别（按版本字节给候选）
func sniff(blobB64 string) string {
	data, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil || len(data) == 0 {
		return "非法 base64"
	}
	switch {
	case data[0] == versionV3 && len(data) >= 29:
		return "v3 (AES-256-GCM + 版本前缀)"
	case data[0] == versionV2 && len(data) >= 49:
		return "v2 (AES-256-CBC + HMAC-SHA256)"
	default:
		return "legacy (无前缀 GCM) 或需回退尝试"
	}
}

func main() {
	os.Exit(run(os.Stdout, os.Args[1:]))
}

// run 是真正的主体；main 只负责把退出码交给操作系统。
//
// 拆开是为了让测试能捕获输出内容并断言「输出里没有派生主密钥明文」。
func run(out io.Writer, args []string) int {
	fs := flag.NewFlagSet("vault", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	saltB64 := fs.String("salt", "", "master_key_salt（base64，取自 users 表）")
	password := fs.String("pw", "", "主密钥密码")
	cipherB64 := fs.String("cipher", "", "待解密的 v3 密文（base64，取自 passwords.cipher）")
	iter := fs.Int("iter", 600000, "PBKDF2 迭代次数")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *saltB64 == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "用法: vault -salt <b64> -pw <password> [-cipher <b64>]")
		return 2
	}

	salt, err := base64.StdEncoding.DecodeString(*saltB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "salt 解码失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "salt 长度        : %d 字节\n", len(salt))

	// --- PBKDF2 派生（与 PHP 交互的必需路径）---
	t0 := time.Now()
	key := derivePBKDF2(*password, salt, *iter)
	dur := time.Since(t0)
	// 只打印指纹，不打印派生主密钥本身（见 keyFingerprint 的说明）。
	fmt.Fprintln(out, keySummary("主密钥指纹(sha256前8位)", key))
	fmt.Fprintf(out, "PBKDF2-%d 耗时  : %.0f ms\n", *iter, float64(dur.Microseconds())/1000.0)

	// --- Argon2id 对比（PHP 侧未能启用）---
	t0 = time.Now()
	a2 := deriveArgon2id(*password, salt, 2, 64*1024)
	fmt.Fprintf(out, "Argon2id 耗时    : %.0f ms  (m=64MiB, t=2, p=1)\n", float64(time.Since(t0).Microseconds())/1000.0)
	fmt.Fprintln(out, keySummary("Argon2id 指纹", a2))

	if *cipherB64 == "" {
		return 0
	}

	fmt.Fprintf(out, "\n格式嗅探         : %s\n", sniff(*cipherB64))
	plain, err := decryptV3(*cipherB64, key)
	if err != nil {
		fmt.Fprintf(out, "解密结果         : 失败 -> %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "解密结果         : %q   <== 与 PHP 明文一致即证明互通\n", plain)

	// --- 反向：Go 加密，再自解（同时可交 PHP 验证）---
	round, err := encryptV3(plain, key)
	if err != nil {
		fmt.Fprintf(out, "加密回写失败     : %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "GO_CIPHER=%s\n", round)
	back, err := decryptV3(round, key)
	if err != nil {
		fmt.Fprintf(out, "回环失败         : %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "回环校验         : %q -> %s\n", back, map[bool]string{true: "OK", false: "FAIL"}[back == plain])
	return 0
}
