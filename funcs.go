package main

import (
	"context"
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

// startGeoCacheCleaner 每小时清理 geoCache 中超过 24h TTL 的过期条目
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
	cachedPeersMu.RLock()
	peers := make([]PeerData, len(cachedPeers))
	copy(peers, cachedPeers)
	cachedPeersMu.RUnlock()

	type PeerGeo struct {
		PublicKey  string   `json:"public_key"`
		Alias     string   `json:"alias"`
		Endpoint  string   `json:"endpoint"`
		IsOnline  bool     `json:"is_online"`
		Lat       float64  `json:"lat"`
		Lon       float64  `json:"lon"`
		City      string   `json:"city"`
		Country   string   `json:"country_code"`
		Source    string   `json:"source"`
		Latency   string   `json:"latency"`
		RxRate    float64  `json:"rx_rate"`
		TxRate    float64  `json:"tx_rate"`
		TotalRx   int64    `json:"total_rx"`
		TotalTx   int64    `json:"total_tx"`
		AllowedIPs []string `json:"allowed_ips"`
	}

	var data []PeerGeo

	for _, p := range peers {
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
				lat = entry.Lat
				lon = entry.Lon
				city = entry.City
				country = entry.Country
				source = "cache_mem"
			} else {
				// 2. 使用 ipProvider（仅内存缓存，移除 Redis 层）
				if ipProvider != nil {
					if info, err := ipProvider.GetInfo(ip); err == nil {
						lat = info.Latitude
						lon = info.Longitude
						country = info.CountryCode
						city = info.City
						source = info.Source

						// 写入内存缓存
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
						}
					}
				}
			}
		}

		data = append(data, PeerGeo{
			PublicKey:  p.PublicKey,
			Alias:     p.Alias,
			Endpoint:  p.Endpoint,
			IsOnline:  p.IsOnline,
			Lat:       lat,
			Lon:       lon,
			City:      city,
			Country:   country,
			Source:    source,
			Latency:   getPeerLatency(p.PublicKey),
			RxRate:    p.RxRate,
			TxRate:    p.TxRate,
			TotalRx:   p.ReceiveBytes,
			TotalTx:   p.TransmitBytes,
			AllowedIPs: p.AllowedIPs,
		})
	}

	c.JSON(http.StatusOK, data)
}

// ================= 高级分析 API =================

func getAdvancedAnalysis(c *gin.Context) {
	report, err := analysisEngine.GetAdvancedReport()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}
