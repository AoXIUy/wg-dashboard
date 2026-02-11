package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// ================= 地图与高级分析接口 =================

// 外部 API 响应结构 (ip-api.com)
type IPAPIResponse struct {
	Status      string  `json:"status"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

func fetchGeoFromAPI(ip string) (float64, float64, string, string, error) {
	// 使用 ip-api.com (免费版不支持 HTTPS，注意生产环境 mixed content 问题，但后端抓取没问题)
	// 备选: ipapi.co (HTTPS supported)
	url := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN", ip)
	
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return 0, 0, "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, "", "", fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, "", "", err
	}

	var result IPAPIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, 0, "", "", err
	}

	if result.Status != "success" {
		return 0, 0, "", "", fmt.Errorf("API returned error status")
	}

	return result.Lat, result.Lon, result.City, result.CountryCode, nil
}

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
			// 1. 尝试本地 GeoIP 数据库 (优先)
			localSuccess := false
			if geoCity != nil {
				if record, err := geoCity.City(ip); err == nil {
					lat = record.Location.Latitude
					lon = record.Location.Longitude
					country = record.Country.IsoCode
					if name, ok := record.City.Names["zh-CN"]; ok {
						city = name
					} else {
						city = record.City.Names["en"]
					}
					
					if lat != 0 && lon != 0 && city != "" {
						localSuccess = true
						source = "local"
					}
				}
			}

			// 2. 如果本地获取失败或不完整，尝试缓存或外部 API
			if !localSuccess {
				ipStr := ip.String()
				
				// 2.1 查内存缓存
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
					// 2.2 查 Redis 缓存
					redisHit := false
					if redisEnabled && rdb != nil {
						val, err := rdb.Get(context.Background(), "wg:geo:"+ipStr).Result()
						if err == nil {
							var redisEntry GeoCacheEntry
							if json.Unmarshal([]byte(val), &redisEntry) == nil {
								lat = redisEntry.Lat
								lon = redisEntry.Lon
								city = redisEntry.City
								country = redisEntry.Country
								source = "cache_redis"
								redisHit = true
								
								geoCacheMu.Lock()
								geoCache[ipStr] = redisEntry
								geoCacheMu.Unlock()
							}
						}
					}

					// 2.3 调用外部 API
					if !redisHit {
						l, ln, c, cc, err := fetchGeoFromAPI(ipStr)
						if err == nil {
							lat, lon, city, country = l, ln, c, cc
							source = "external"
							
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
							
							if redisEnabled && rdb != nil {
								if jsonBytes, err := json.Marshal(newEntry); err == nil {
									rdb.Set(context.Background(), "wg:geo:"+ipStr, jsonBytes, 24*time.Hour)
								}
							}
						} else {
							// 回退使用本地不完整数据
							if geoCity != nil {
								if record, err := geoCity.City(ip); err == nil {
									lat = record.Location.Latitude
									lon = record.Location.Longitude
									country = record.Country.IsoCode
									if name, ok := record.City.Names["zh-CN"]; ok {
										city = name
									} else {
										city = record.City.Names["en"]
									}
									source = "local_fallback"
								}
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
			RxRate:     p.RxRate,
			TxRate:     p.TxRate,
			TotalRx:    p.ReceiveBytes,
			TotalTx:    p.TransmitBytes,
			AllowedIPs: p.AllowedIPs,
		})
	}

	c.JSON(http.StatusOK, data)
}

func getAdvancedAnalysis(c *gin.Context) {
	report, err := analysisEngine.GetAdvancedReport()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}
