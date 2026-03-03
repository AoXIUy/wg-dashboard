package main

import (
	"net"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ================= SEC-5: 登录频率限制 =================
//
// 基于 IP 的 Sliding Window 计数器，防止暴力破解。
// 规则：5 分钟内同一 IP 失败次数超过 10 次，封禁该 IP 15 分钟。

const (
	rateLimitWindow   = 5 * time.Minute  // 统计窗口
	rateLimitMaxFails = 10               // 窗口内最大失败次数
	rateLimitBanDur   = 15 * time.Minute // 封禁时长
)

type loginAttempt struct {
	// 记录窗口内每次失败的时间戳
	failures []time.Time
	// 封禁解除时间，零值表示未封禁
	bannedUntil time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

var loginRateLimiter = &rateLimiter{
	attempts: make(map[string]*loginAttempt),
}

// getClientIP 从请求中提取真实客户端 IP（支持 X-Forwarded-For）
func getClientIP(c *gin.Context) string {
	// 优先读取 X-Real-IP（Nginx 代理时设置）
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		if parsed := net.ParseIP(ip); parsed != nil {
			return parsed.String()
		}
	}
	// 使用 Gin 内置方法（自动处理 X-Forwarded-For）
	return c.ClientIP()
}

// isRateLimited 检查该 IP 是否已被封禁或达到频率上限。
// 若被限制返回 true；对于合法请求，此函数不做任何记录
func (r *rateLimiter) isRateLimited(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	attempt, ok := r.attempts[ip]
	if !ok {
		return false
	}

	// 检查是否处于封禁期
	if !attempt.bannedUntil.IsZero() && time.Now().Before(attempt.bannedUntil) {
		return true
	}

	// 清理超出窗口的旧记录，检查当前失败次数
	now := time.Now()
	cutoff := now.Add(-rateLimitWindow)
	valid := attempt.failures[:0]
	for _, t := range attempt.failures {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	attempt.failures = valid

	// 内存泄漏修复：封禁已到期且失败记录为空时删除 map 条目
	if len(valid) == 0 {
		delete(r.attempts, ip)
		return false
	}

	return len(attempt.failures) >= rateLimitMaxFails
}

// recordFailure 记录一次登录失败
func (r *rateLimiter) recordFailure(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	attempt, ok := r.attempts[ip]
	if !ok {
		attempt = &loginAttempt{}
		r.attempts[ip] = attempt
	}

	attempt.failures = append(attempt.failures, time.Now())

	// 超过阈值则封禁
	if len(attempt.failures) >= rateLimitMaxFails {
		attempt.bannedUntil = time.Now().Add(rateLimitBanDur)
		logger.Printf("[RateLimit] IP %s 登录失败次数过多，已封禁至 %s",
			ip, attempt.bannedUntil.Format("15:04:05"))
	}
}

// recordSuccess 登录成功后清除该 IP 的失败记录
func (r *rateLimiter) recordSuccess(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, ip)
}
// 注意： rateLimitMiddleware 已删除（死代码）。
// 登录频率限制由 loginHandler 直接调用 loginRateLimiter.isRateLimited() 实现，无需中间件。
