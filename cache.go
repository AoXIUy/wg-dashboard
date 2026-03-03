package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ================= AliasCache：Peer 别名与启用状态缓存 =================

// AliasCache 带 TTL 的内存缓存，存储 Peer 的别名和启用状态。
// 采用 stale-while-revalidate 策略：Get 始终返回已有数据，
// 过期刷新由后台 startCacheRefresher 异步完成。
type AliasCache struct {
	mu         sync.RWMutex
	data       map[string]string
	enabled    map[string]bool // peer 启用状态缓存
	lastUpdate time.Time
	ttl        time.Duration
}

// NewAliasCache 创建指定 TTL 的别名缓存
func NewAliasCache(ttl time.Duration) *AliasCache {
	return &AliasCache{
		data:    make(map[string]string),
		enabled: make(map[string]bool),
		ttl:     ttl,
	}
}

// Get 获取 Peer 别名，始终返回已有数据（过期由后台刷新）
func (ac *AliasCache) Get(pk string) (string, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	alias, ok := ac.data[pk]
	return alias, ok
}

// Set 更新单条别名
func (ac *AliasCache) Set(pk, alias string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.data[pk] = alias
}

// GetEnabled 返回 Peer 的启用状态，缓存中无记录时默认返回 true
func (ac *AliasCache) GetEnabled(pk string) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if v, ok := ac.enabled[pk]; ok {
		return v
	}
	return true // 默认启用
}

// SetEnabled 更新 Peer 的启用状态缓存
func (ac *AliasCache) SetEnabled(pk string, v bool) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.enabled[pk] = v
}

// Refresh 从数据库全量刷新别名与启用状态缓存
func (ac *AliasCache) Refresh(ctx context.Context) error {
	rows, err := db.QueryContext(ctx, "SELECT public_key, alias, enabled FROM peer_aliases")
	if err != nil {
		return fmt.Errorf("query aliases: %w", err)
	}
	defer rows.Close()

	newData := make(map[string]string)
	newEnabled := make(map[string]bool)
	for rows.Next() {
		var pk, alias string
		var enabledVal int
		if err := rows.Scan(&pk, &alias, &enabledVal); err != nil {
			logger.Printf("扫描别名失败: %v", err)
			continue
		}
		newData[pk] = alias
		newEnabled[pk] = enabledVal != 0
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows error: %w", err)
	}

	ac.mu.Lock()
	ac.data = newData
	ac.enabled = newEnabled
	ac.lastUpdate = time.Now()
	ac.mu.Unlock()

	logger.Printf("别名缓存已刷新，共 %d 条记录", len(newData))
	return nil
}

// NeedsRefresh 判断缓存是否已超过 TTL 需要刷新
func (ac *AliasCache) NeedsRefresh() bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return time.Since(ac.lastUpdate) > ac.ttl
}

// ================= TrafficBuffer：内存批量写入缓冲区 =================

// TrafficBuffer 线程安全的流量记录内存缓冲，满 maxSize 时触发批量写库。
type TrafficBuffer struct {
	mu      sync.Mutex
	entries []ProcessedLog
	maxSize int
}

// NewTrafficBuffer 创建指定容量的流量缓冲区
func NewTrafficBuffer(maxSize int) *TrafficBuffer {
	return &TrafficBuffer{
		entries: make([]ProcessedLog, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add 追加一条记录，返回是否已达到 maxSize（需要立即刷新）
func (tb *TrafficBuffer) Add(entry ProcessedLog) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.entries = append(tb.entries, entry)
	return len(tb.entries) >= tb.maxSize
}

// Flush 取走全部记录并重置缓冲区，无数据时返回 nil
func (tb *TrafficBuffer) Flush() []ProcessedLog {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	if len(tb.entries) == 0 {
		return nil
	}

	batch := make([]ProcessedLog, len(tb.entries))
	copy(batch, tb.entries)
	tb.entries = tb.entries[:0]
	return batch
}

// Size 返回当前缓冲区中的记录数
func (tb *TrafficBuffer) Size() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return len(tb.entries)
}

// ================= Metrics：原子计数监控指标 =================

// Metrics 使用原子操作记录关键运行指标，可暴露给 Prometheus
type Metrics struct {
	ProcessedCount int64
	FailedWrites   int64
	RedisErrors    int64
	CacheHits      int64
	CacheMisses    int64
}

func (m *Metrics) IncProcessed() {
	atomic.AddInt64(&m.ProcessedCount, 1)
}

func (m *Metrics) IncFailedWrites() {
	atomic.AddInt64(&m.FailedWrites, 1)
}

func (m *Metrics) IncRedisErrors() {
	atomic.AddInt64(&m.RedisErrors, 1)
}

func (m *Metrics) IncCacheHits() {
	atomic.AddInt64(&m.CacheHits, 1)
}

func (m *Metrics) IncCacheMisses() {
	atomic.AddInt64(&m.CacheMisses, 1)
}

// GetStats 返回所有指标的快照
func (m *Metrics) GetStats() map[string]int64 {
	return map[string]int64{
		"processed":     atomic.LoadInt64(&m.ProcessedCount),
		"failed_writes": atomic.LoadInt64(&m.FailedWrites),
		"redis_errors":  atomic.LoadInt64(&m.RedisErrors),
		"cache_hits":    atomic.LoadInt64(&m.CacheHits),
		"cache_misses":  atomic.LoadInt64(&m.CacheMisses),
	}
}

// ================= LatencyCache：Peer 延迟缓存 =================

// LatencyCache 存储每个 Peer 的最新 Ping 延迟字符串
type LatencyCache struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewLatencyCache 创建延迟缓存
func NewLatencyCache() *LatencyCache {
	return &LatencyCache{
		data: make(map[string]string),
	}
}

// Get 获取延迟字符串，不存在时返回空串
func (lc *LatencyCache) Get(pk string) string {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	return lc.data[pk]
}

// Set 更新 Peer 的延迟字符串
func (lc *LatencyCache) Set(pk, latency string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.data[pk] = latency
}

// Delete 删除 Peer 的延迟记录（Peer 离线时调用）
func (lc *LatencyCache) Delete(pk string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	delete(lc.data, pk)
}
