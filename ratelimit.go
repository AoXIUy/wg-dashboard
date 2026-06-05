package main

import (
	"context"
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

// getClientIP 获取客户端真实 IP。
// SEC-5：不再手动信任 X-Real-IP Header，完全依赖 gin 的 TrustedProxies 配置
// （在 startHTTPServer 中设置），防止未经代理的客户端伪造 IP 绕过限流。
func getClientIP(c *gin.Context) string {
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

// startCleaner SEC-4：定期扫描并删除过期的限流条目，防止 attempts map 无限增长。
// 满足以下条件将被删除：封禁已解除 且 失败记录均超出统计窗口。
func (r *rateLimiter) startCleaner(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			cutoff := now.Add(-rateLimitWindow)
			r.mu.Lock()
			for ip, a := range r.attempts {
				// 封禁已过期 且 所有失败记录均超出统计窗口时，删除该条目
				banExpired := a.bannedUntil.IsZero() || a.bannedUntil.Before(now)
				failuresExpired := len(a.failures) == 0 || a.failures[len(a.failures)-1].Before(cutoff)
				if banExpired && failuresExpired {
					delete(r.attempts, ip)
				}
			}
			r.mu.Unlock()
		}
	}
}
