// 密码学层：与 PHP 版逐字节兼容。
//
// 必须同时支持三种历史格式（顺序与 PHP 的 Security::decrypt 一致）：
//
//	v3    base64(0x03 || IV(12) || Tag(16) || CT)   AES-256-GCM
//	v2    base64(0x02 || IV(16) || HMAC(32) || CT)  AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
//	legacy base64(IV(12) || Tag(16) || CT)          AES-256-GCM，无版本前缀
//
// legacy 无前缀，其首字节就是随机 IV 的第 0 字节，有 1/256 概率恰好为 0x02/0x03，
// 因此必须「按可能性顺序全部试一遍」，靠认证失败自证格式 —— 这正是 PHP 版的做法，
// 移植时若只实现 v3，老用户数据会静默打不开。
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	versionV3          byte = 0x03
	versionV2          byte = 0x02
	kdfArgon2ID             = "argon2id"
	kdfPBKDF2               = "pbkdf2"
	legacyPBKDF2Iters       = 10000 // 旧版用户存量参数
	defaultPBKDF2Iters      = 600000
	defaultArgon2Ops        = 2                // sodium opslimit = Argon2 t_cost
	defaultArgon2MemB       = 64 * 1024 * 1024 // sodium memlimit（字节）= Argon2 m_cost
)

// KDFParams 是 users.kdf_params 的语义化表示。
//
// ⚠ 参数名必须保留 PHP/sodium 的原始语义（opslimit / memlimit），不要改成 t/m：
//
//	sodium opslimit  == Argon2 t_cost
//	sodium memlimit  == Argon2 m_cost（字节，转 KiB 需 /1024）
//	并行度固定 p = 1
//
// 该映射经实测校准：ops=1..4、mem=32/64MB 共 5 组，Go 与 sodium 输出逐字节一致。
type KDFParams struct {
	OpsLimit int `json:"opslimit,omitempty"`   // Argon2 t_cost
	MemLimit int `json:"memlimit,omitempty"`   // Argon2 m_cost（字节）
	Iters    int `json:"iterations,omitempty"` // PBKDF2 迭代次数
}

// DeriveKey 按库中记录的 kdf_type / kdf_params / salt 派生主密钥。
// 返回 base64 编码的 32 字节密钥，可直接与 PHP 版互换。
func DeriveKey(password string, saltRaw []byte, kdfType string, paramsJSON string) (string, error) {
	key, err := deriveKeyRaw(password, saltRaw, kdfType, paramsJSON)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func deriveKeyRaw(password string, saltRaw []byte, kdfType, paramsJSON string) ([]byte, error) {
	params := KDFParams{}
	if paramsJSON != "" {
		_ = json.Unmarshal([]byte(paramsJSON), &params)
	}

	switch kdfType {
	case kdfArgon2ID:
		ops := params.OpsLimit
		if ops <= 0 {
			ops = defaultArgon2Ops
		}
		memBytes := params.MemLimit
		if memBytes <= 0 {
			memBytes = defaultArgon2MemB
		}
		memKiB := uint32(memBytes / 1024)
		if len(saltRaw) != 16 {
			// sodium 要求 16 字节 salt；与 PHP 的兜底保持一致（sha256 截断）
			sum := sha256.Sum256(saltRaw)
			saltRaw = sum[:16]
		}
		return argon2.IDKey([]byte(password), saltRaw, uint32(ops), memKiB, 1, 32), nil

	case kdfPBKDF2, "":
		iters := params.Iters
		if iters <= 0 {
			// 空 kdf_type = 旧版用户，沿用存量 10000 次
			if kdfType == "" {
				iters = legacyPBKDF2Iters
			} else {
				iters = defaultPBKDF2Iters
			}
		}
		return pbkdf2.Key([]byte(password), saltRaw, iters, 32, sha256.New), nil

	default:
		return nil, fmt.Errorf("未知的 KDF 类型: %s", kdfType)
	}
}

// NewKey 为新账户派生主密钥，返回 salt(base64)、key(base64) 与应落库的参数
func NewKey(password string) (saltB64, keyB64, kdfType, paramsJSON string, err error) {
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	// 本实现始终可用 argon2id（纯 Go，无外部依赖），故新账户一律用 Argon2id
	kdfType = kdfArgon2ID
	p := KDFParams{OpsLimit: defaultArgon2Ops, MemLimit: defaultArgon2MemB}
	pj, _ := json.Marshal(p)
	paramsJSON = string(pj)
	raw, derr := deriveKeyRaw(password, salt, kdfType, paramsJSON)
	if derr != nil {
		err = derr
		return
	}
	saltB64 = base64.StdEncoding.EncodeToString(salt)
	keyB64 = base64.StdEncoding.EncodeToString(raw)
	return
}

// Encrypt 生成 v3 格式密文：base64(0x03 || IV12 || Tag16 || CT)
func Encrypt(plain, keyB64 string) (string, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return "", err
	}
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
	sealed := gcm.Seal(nil, iv, []byte(plain), nil) // CT || Tag
	split := len(sealed) - 16
	ct, tag := sealed[:split], sealed[split:]

	blob := make([]byte, 0, 1+12+16+len(ct))
	blob = append(blob, versionV3)
	blob = append(blob, iv...)
	blob = append(blob, tag...)
	blob = append(blob, ct...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt 自动识别三种历史格式。顺序与 PHP 一致：先按版本字节构造候选，最后兜底 legacy。
func Decrypt(blobB64, keyB64 string) (string, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(trimSpace(blobB64))
	if err != nil {
		return "", fmt.Errorf("密文格式错误：base64 解码失败")
	}
	if len(data) < 28 {
		return "", fmt.Errorf("密文长度错误：数据太短")
	}

	var candidates []string
	v := data[0]
	if v == versionV3 && len(data) >= 29 {
		candidates = append(candidates, "v3")
	}
	if v == versionV2 && len(data) >= 49 {
		candidates = append(candidates, "v2")
	}
	candidates = append(candidates, "legacy")

	var lastErr error
	for _, f := range candidates {
		plain, err := decryptAs(data, key, f)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("无法识别的加密数据格式")
	}
	return "", lastErr
}

func decryptAs(data, key []byte, format string) (string, error) {
	switch format {
	case "v3":
		iv, tag, ct := data[1:13], data[13:29], data[29:]
		return gcmOpen(key, iv, ct, tag)
	case "v2":
		iv, mac, ct := data[1:17], data[17:49], data[49:]
		macKey := pbkdf2.Key(key, []byte("mima_hmac_salt"), 1000, 32, sha256.New)
		m := hmac.New(sha256.New, macKey)
		m.Write(iv)
		m.Write(ct)
		if !hmac.Equal(mac, m.Sum(nil)) {
			return "", errors.New("解密失败：HMAC 验证失败，数据可能被篡改或密钥错误")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		if len(ct)%aes.BlockSize != 0 {
			return "", errors.New("解密失败：密文长度不是块大小的整数倍")
		}
		out := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
		// 去除 PKCS#7 填充
		if n := int(out[len(out)-1]); n > 0 && n <= aes.BlockSize && n <= len(out) {
			out = out[:len(out)-n]
		}
		return string(out), nil
	default: // legacy：无前缀 GCM
		iv, tag, ct := data[0:12], data[12:28], data[28:]
		return gcmOpen(key, iv, ct, tag)
	}
}

func gcmOpen(key, iv, ct, tag []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(iv) != 12 || len(tag) != 16 {
		return "", errors.New("密文格式错误：IV 或 Tag 长度不正确")
	}
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", errors.New("解密失败：GCM 认证失败，密钥错误或数据被篡改")
	}
	return string(plain), nil
}

func decodeKey(keyB64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(trimSpace(keyB64))
	if err != nil || len(key) != 32 {
		return nil, errors.New("密钥格式错误：必须是 32 字节的 base64 编码")
	}
	return key, nil
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\r' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 {
		c := s[len(s)-1]
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return s
}

// PasswordStrength 密码强度评估（与 PHP 版规则一致，便于跨实现对齐）
type Strength struct {
	Score    int      `json:"score"`
	Level    string   `json:"level"`
	Feedback []string `json:"feedback"`
}

func CheckStrength(pw string) Strength {
	score := 0
	feedback := []string{}
	if len(pw) >= 6 {
		score++
	} else {
		feedback = append(feedback, "密码长度至少6位")
	}
	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if hasLower {
		score++
	} else {
		feedback = append(feedback, "包含小写字母")
	}
	if hasUpper {
		score++
	} else {
		feedback = append(feedback, "包含大写字母")
	}
	if hasDigit {
		score++
	} else {
		feedback = append(feedback, "包含数字")
	}
	if hasSymbol {
		score++
	} else {
		feedback = append(feedback, "包含特殊字符")
	}
	if len(pw) >= 12 {
		score++
	}
	levels := []string{"很弱", "弱", "一般", "强", "很强", "极强"}
	if score > 5 {
		score = 5
	}
	return Strength{Score: score, Level: levels[score], Feedback: feedback}
}
