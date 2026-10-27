// 统一错误出口与错误码。
//
// 为什么需要这一层（开源版新增）：
// 原实现里有 30 处直接把 err.Error() 写进 HTTP 响应。err 可能是 SQLite 的
// "constraint failed: UNIQUE constraint failed: users.username"，也可能是
// "open C:\Users\xxx\vault.db: permission denied" —— 前者泄露表结构，
// 后者泄露本机路径与操作系统细节。对一个本地密码管理器来说这些信息
// 没有必要出浏览器。
//
// 约定：
//   - 对外只返回「稳定错误码 + 给用户看的中文文案」；
//   - 内部原始错误只写服务端日志，不进响应体；
//   - 前端只需要读 error 字段即可正常提示，code 字段供后续做分支处理。
package vault

import (
	"log"
	"net"
	"net/http"
	"strings"
)

// 稳定错误码。语义化命名，一经发布不再改含义（前端可依赖它做分支）。
const (
	CodeInternal      = "E_INTERNAL"       // 未预期的服务端错误，细节只进日志
	CodeNotFound      = "E_NOT_FOUND"      // 目标不存在或不属于当前用户
	CodeConflict      = "E_CONFLICT"       // 唯一性冲突（用户名重复等）
	CodeValidation    = "E_VALIDATION"     // 输入不合法
	CodeUnauthorized  = "E_UNAUTHORIZED"   // 凭据错误
	CodeLocked        = "E_LOCKED"         // 账户被锁定
	CodeRateLimit     = "E_RATE_LIMIT"     // 触发限流
	CodeNeedUnlock    = "E_NEED_UNLOCK"    // 需要重新解锁主密钥
	CodeSessionGone   = "E_SESSION_GONE"   // 会话不存在或已过期
	CodeDecryptFailed = "E_DECRYPT_FAILED" // 解密失败（密钥不匹配或数据损坏）
)

// writeErr 是所有错误响应的唯一出口。
//
// publicMsg 必须是可以直接展示给用户的文案，不要拼接原始 err。
// internalErr 传 nil 表示这不是服务端内部错误（例如参数校验失败）。
func writeErr(w http.ResponseWriter, status int, code, publicMsg string, internalErr error) {
	if internalErr != nil {
		// 原始错误只进日志：响应体里不放表名、路径、驱动名
		log.Printf("[%s] %s", code, internalErr)
	}
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": publicMsg,
		"code":  code,
	})
}

// writeInternalErr 是最常用的快捷方式：内部错误 → 通用文案 + 记日志。
func writeInternalErr(w http.ResponseWriter, status int, internalErr error) {
	writeErr(w, status, CodeInternal, "服务器内部错误，请查看日志", internalErr)
}

// writeNeedUnlock 统一「需要解锁」响应（HTTP 423）。
//
// 保留 need_unlock 字段是为了兼容既有前端逻辑：
// 部分客户端（如打包脚本的冒烟用例）依赖该字段判断是否要弹解锁框。
func writeNeedUnlock(w http.ResponseWriter, msg string) {
	writeJSON(w, 423, map[string]any{
		"ok":          false,
		"error":       msg,
		"code":        CodeNeedUnlock,
		"need_unlock": true,
	})
}

// clientIP 取请求来源 IP，用于登录限流。
//
// 不信任 X-Forwarded-For：本程序默认只监听 127.0.0.1，没有可信反向代理，
// 一旦采信客户端可伪造的头，限流就形同虚设。
// 若将来确实部署在受控反向代理后，应改为「只信任来自已知代理网段的请求头」。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr 没有端口（或被改写），整体作为标识
		ip := strings.TrimSpace(r.RemoteAddr)
		if ip == "" {
			return "unknown"
		}
		return ip
	}
	if host == "" {
		return "unknown"
	}
	return host
}
