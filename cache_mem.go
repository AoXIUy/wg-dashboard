package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// cacheEntry 表示单条带过期时间的缓存值
type cacheEntry struct {
	val       string
	hashVal   map[string]string
	isHash    bool
	expiresAt time.Time
}

func (e *cacheEntry) isExpired(now time.Time) bool {
	if e.expiresAt.IsZero() {
		return false
	}
	return now.After(e.expiresAt)
}

// MemoryCache 进程内高性能并发安全缓存引擎，完全替代外部 Redis
type MemoryCache struct {
	mu      sync.RWMutex
	items   map[string]*cacheEntry
	maxSize int
}

var globalCache *MemoryCache

func initMemoryCache(maxSize int) {
	if maxSize <= 0 {
		maxSize = 100000
	}
	globalCache = NewMemoryCache(maxSize)
}

// NewMemoryCache 创建指定最大容量的内存缓存
func NewMemoryCache(maxSize int) *MemoryCache {
	return &MemoryCache{
		items:   make(map[string]*cacheEntry),
		maxSize: maxSize,
	}
}

// StartCleaner 启动后台定期清理过期条目的协程
func (c *MemoryCache) StartCleaner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanExpired()
		}
	}
}

func (c *MemoryCache) cleanExpired() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, entry := range c.items {
		if entry.isExpired(now) {
			delete(c.items, k)
		}
	}
}

// Get 获取字符串缓存
func (c *MemoryCache) Get(key string) (string, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		return "", false
	}

	if entry.isExpired(time.Now()) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return "", false
	}

	return entry.val, true
}

// Set 设置字符串缓存及 TTL
func (c *MemoryCache) Set(key string, val string, ttl time.Duration) {
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 简单的容量控制：若超限则随机或按顺序清理若干条
	if len(c.items) >= c.maxSize {
		count := 0
		for k := range c.items {
			delete(c.items, k)
			count++
			if count > 100 {
				break
			}
		}
	}

	c.items[key] = &cacheEntry{
		val:       val,
		isHash:    false,
		expiresAt: exp,
	}
}

// HSet 设置 Hash 结构缓存（兼容原 Redis HSet）
func (c *MemoryCache) HSet(key string, fields map[string]interface{}, ttl time.Duration) {
	strFields := make(map[string]string, len(fields))
	for k, v := range fields {
		strFields[k] = fmt.Sprintf("%v", v)
	}

	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[key]
	if !ok || !entry.isHash || entry.isExpired(time.Now()) {
		c.items[key] = &cacheEntry{
			hashVal:   strFields,
			isHash:    true,
			expiresAt: exp,
		}
		return
	}

	// 合并已有 fields
	for k, v := range strFields {
		entry.hashVal[k] = v
	}
	if ttl > 0 {
		entry.expiresAt = exp
	}
}

// HGet 获取 Hash 中指定字段的值
func (c *MemoryCache) HGet(key string, field string) (string, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok || !entry.isHash {
		return "", false
	}

	if entry.isExpired(time.Now()) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return "", false
	}

	val, found := entry.hashVal[field]
	return val, found
}

// HGetAll 获取 Hash 中全部字段
func (c *MemoryCache) HGetAll(key string) (map[string]string, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok || !entry.isHash {
		return nil, false
	}

	if entry.isExpired(time.Now()) {
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		return nil, false
	}

	// 返回副本
	result := make(map[string]string, len(entry.hashVal))
	for k, v := range entry.hashVal {
		result[k] = v
	}
	return result, true
}

// Delete 删除指定缓存项
func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}
