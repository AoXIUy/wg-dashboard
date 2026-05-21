package main

import (
	"sync"
	"time"
)

// ================= PeerRealtimeState：替代 Redis Hash wg:peer:state:{pk} =================

// PeerRealtimeState 存储单个 Peer 的实时状态
type PeerRealtimeState struct {
	RxRate   float64
	TxRate   float64
	IsOnline bool
	Endpoint string
	LastSeen int64
}

// PeerStateCache 线程安全的 Peer 实时状态缓存（替代 Redis Hash）
type PeerStateCache struct {
	mu   sync.RWMutex
	data map[string]PeerRealtimeState
}

// NewPeerStateCache 创建 Peer 状态缓存
func NewPeerStateCache() *PeerStateCache {
	return &PeerStateCache{
		data: make(map[string]PeerRealtimeState),
	}
}

// Get 获取指定 Peer 的实时状态
func (c *PeerStateCache) Get(pk string) (PeerRealtimeState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.data[pk]
	return s, ok
}

// Update 更新指定 Peer 的实时状态
func (c *PeerStateCache) Update(pk string, state PeerRealtimeState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[pk] = state
}

// GetAll 返回所有 Peer 状态的快照
func (c *PeerStateCache) GetAll() map[string]PeerRealtimeState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := make(map[string]PeerRealtimeState, len(c.data))
	for k, v := range c.data {
		snapshot[k] = v
	}
	return snapshot
}

// ================= TTLCache：通用 TTL 缓存（替代 Redis GET/SET + TTL） =================

// TTLCache 通用带 TTL 的内存缓存，替代 Redis 的 SET key value EX ttl
type TTLCache[T any] struct {
	mu       sync.RWMutex
	data     T
	valid    bool
	cachedAt time.Time
	ttl      time.Duration
}

// NewTTLCache 创建指定 TTL 的通用缓存
func NewTTLCache[T any](ttl time.Duration) *TTLCache[T] {
	return &TTLCache[T]{ttl: ttl}
}

// Get 获取缓存数据，过期或未设置时返回 false
func (c *TTLCache[T]) Get() (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.valid || time.Since(c.cachedAt) > c.ttl {
		var zero T
		return zero, false
	}
	return c.data, true
}

// Set 写入缓存数据并重置 TTL
func (c *TTLCache[T]) Set(data T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = data
	c.valid = true
	c.cachedAt = time.Now()
}

// ================= PeerBaseline 缓存 =================

// PeerBaselineCache 存储 Peer 流量基线（替代 Redis wg:cache:peer_baseline）
type PeerBaselineCache struct {
	mu   sync.RWMutex
	data map[string]PeerBaseline
}

// NewPeerBaselineCache 创建基线缓存
func NewPeerBaselineCache() *PeerBaselineCache {
	return &PeerBaselineCache{
		data: make(map[string]PeerBaseline),
	}
}

// Get 获取所有基线快照
func (c *PeerBaselineCache) Get() map[string]PeerBaseline {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := make(map[string]PeerBaseline, len(c.data))
	for k, v := range c.data {
		snapshot[k] = v
	}
	return snapshot
}

// Set 批量设置基线数据
func (c *PeerBaselineCache) Set(baselines map[string]PeerBaseline) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = baselines
}

// ================= 全局内存缓存实例 =================

var (
	// peerStateCache 替代 Redis Hash，存储所有 Peer 的实时状态
	peerStateCache *PeerStateCache

	// advancedReportCache 替代 Redis wg:cache:advanced_report（2 分钟 TTL）
	advancedReportCache *TTLCache[AdvancedReport]

	// baselineCache 替代 Redis wg:cache:peer_baseline
	baselineCache *PeerBaselineCache

	// geoCacheRedis 不再需要 Redis 缓存层，仅使用内存 geoCache（funcs.go 中已有）
)

// initStateCache 初始化所有内存状态缓存
func initStateCache() {
	peerStateCache = NewPeerStateCache()
	advancedReportCache = NewTTLCache[AdvancedReport](2 * time.Minute)
	baselineCache = NewPeerBaselineCache()
}
