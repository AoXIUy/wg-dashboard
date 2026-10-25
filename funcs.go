package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ================= 全局缓存 =================

type GeoCacheEntry struct {
	Lat       float64
	Lon       float64
	City      string
	Country   string
	Timestamp time.Time
}

var (
	geoCache   = make(map[string]GeoCacheEntry)
	geoCacheMu sync.RWMutex
)

// startGeoCacheCleaner 内存泄漏修复：每小时清理 geoCache 中超过 24h TTL 的过期条目。
// 防止 Peer 更换 IP 后旧条目无限积累导致内存增长。
func startGeoCacheCleaner(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			geoCacheMu.Lock()
			for ip, entry := range geoCache {
				if now.Sub(entry.Timestamp) >= 24*time.Hour {
					delete(geoCache, ip)
				}
			}
			geoCacheMu.Unlock()
		}
	}
}

// ================= 地图与高级分析接口 =================

func getMapData(c *gin.Context) {
	peers, _, _, err := collectPeersData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type PeerGeo struct {
		PublicKey  string   `json:"public_key"`
		Alias      string   `json:"alias"`
		Endpoint   string   `json:"endpoint"`
		IsOnline   bool     `json:"is_online"`
		Lat        float64  `json:"lat"`
		Lon        float64  `json:"lon"`
		City       string   `json:"city"`
		Country    string   `json:"country_code"`
		Source     string   `json:"source"`
		Latency    string   `json:"latency"`
		RxRate     float64  `json:"rx_rate"`
		TxRate     float64  `json:"tx_rate"`
		TotalRx    int64    `json:"total_rx"`
		TotalTx    int64    `json:"total_tx"`
		AllowedIPs []string `json:"allowed_ips"`
	}

	var data []PeerGeo

	for _, p := range peers {
		// 即使没有 Endpoint (未连接)，也应该在拓扑图中显示，作为离线节点
		// 地图模式下如果没有坐标则无法显示，但拓扑图应该显示所有 Peers

		// 尝试获取 IP 用于定位
		var ip net.IP
		host := ""
		if p.Endpoint != "" && p.Endpoint != "未连接" {
			h, _, err := net.SplitHostPort(p.Endpoint)
			if err == nil {
				host = strings.Trim(h, "[]")
				ip = net.ParseIP(host)
			}
		}

		var lat, lon float64
		var city, country string
		var source string = "none"

		if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			ipStr := ip.String()

			// 1. 查内存缓存
			geoCacheMu.RLock()
			entry, found := geoCache[ipStr]
			geoCacheMu.RUnlock()

			if found && time.Since(entry.Timestamp) < 24*time.Hour {
				// 命中内存缓存
				lat = entry.Lat
				lon = entry.Lon
				city = entry.City
				country = entry.Country
				source = "cache_mem"
			} else {
				// 2. 查全局内存引擎缓存
				cacheHit := false
				if val, found := globalCache.Get("wg:geo:" + ipStr); found {
					var entry GeoCacheEntry
					if json.Unmarshal([]byte(val), &entry) == nil {
						lat = entry.Lat
						lon = entry.Lon
						city = entry.City
						country = entry.Country
						source = "cache_mem"
						cacheHit = true

						geoCacheMu.Lock()
						geoCache[ipStr] = entry
						geoCacheMu.Unlock()
					}
				}

				// 3. 缓存未命中，使用 ipProvider (支持本地数据库 + 外部 API 回退)
				if !cacheHit && ipProvider != nil {
					if info, err := ipProvider.GetInfo(ip); err == nil {
						lat = info.Latitude
						lon = info.Longitude
						country = info.CountryCode
						city = info.City
						source = info.Source

						if lat != 0 || lon != 0 || city != "" {
							newEntry := GeoCacheEntry{
								Lat:       lat,
								Lon:       lon,
								City:      city,
								Country:   country,
								Timestamp: time.Now(),
							}

							geoCacheMu.Lock()
							geoCache[ipStr] = newEntry
							geoCacheMu.Unlock()

							if jsonBytes, err := json.Marshal(newEntry); err == nil {
								globalCache.Set("wg:geo:"+ipStr, string(jsonBytes), 24*time.Hour)
							}
						}
					}
				}
			}
		}

		data = append(data, PeerGeo{
			PublicKey:  p.PublicKey,
			Alias:      p.Alias,
			Endpoint:   p.Endpoint,
			IsOnline:   p.IsOnline,
			Lat:        lat,
			Lon:        lon,
			City:       city,
			Country:    country,
			Source:     source,
			Latency:    getPeerLatency(p.PublicKey),
			RxRate:     p.RxRate,
			TxRate:     p.TxRate,
			TotalRx:    p.ReceiveBytes,
			TotalTx:    p.TransmitBytes,
			AllowedIPs: p.AllowedIPs,
		})
	}

	c.JSON(http.StatusOK, data)
}

// ================= 内存级分析报告缓存（无 Redis 时的兜底保护）=================

var (
	memAnalysisCache   AdvancedReport
	memAnalysisCacheAt time.Time
	memAnalysisMu      sync.RWMutex
)

func getAdvancedAnalysis(c *gin.Context) {
	// 进程内存缓存（60 秒 TTL），确保高频请求时快速响应
	memAnalysisMu.RLock()
	if !memAnalysisCacheAt.IsZero() && time.Since(memAnalysisCacheAt) < 60*time.Second {
		report := memAnalysisCache
		memAnalysisMu.RUnlock()
		c.JSON(http.StatusOK, report)
		return
	}
	memAnalysisMu.RUnlock()

	report, err := analysisEngine.GetAdvancedReport()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	memAnalysisMu.Lock()
	memAnalysisCache = report
	memAnalysisCacheAt = time.Now()
	memAnalysisMu.Unlock()

	c.JSON(http.StatusOK, report)
}
