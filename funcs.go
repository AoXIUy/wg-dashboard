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
		PublicKey string  `json:"public_key"`
		Alias     string  `json:"alias"`
		Endpoint  string  `json:"endpoint"`
		IsOnline  bool    `json:"is_online"`
		Lat       float64 `json:"lat"`
		Lon       float64 `json:"lon"`
		City      string  `json:"city"`
		Country   string  `json:"country_code"`
		Source    string  `json:"source"` // "local", "external", "cache"
	}

	var data []PeerGeo

	for _, p := range peers {
		if p.Endpoint == "" || p.Endpoint == "未连接" {
			continue
		}

		host, _, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			host = p.Endpoint // fallback
		}
		
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		
		// 忽略内网 IP
		if ip.IsPrivate() || ip.IsLoopback() {
			continue
		}

		var lat, lon float64
		var city, country string
		var source string = "unknown"

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
				
				// 判定本地数据是否足够详细
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
				// 2.2 查 Redis 缓存 (如果启用了 Redis)
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
							
							// 同步回内存缓存
							geoCacheMu.Lock()
							geoCache[ipStr] = redisEntry
							geoCacheMu.Unlock()
						}
					}
				}

				// 2.3 调用外部 API (如无缓存)
				if !redisHit {
					// 只有当本地完全失败，或者经纬度为0时才调用
					// 为了避免阻塞，这里是同步调用，可能会慢。
					// 建议前端做懒加载，但这里后端出接口，暂且忍受一下延迟，或只对前N个并发。
					// 为防止卡死，设置了较短的 Timeout
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
						
						// 写入内存缓存
						geoCacheMu.Lock()
						geoCache[ipStr] = newEntry
						geoCacheMu.Unlock()
						
						// 写入 Redis 缓存
						if redisEnabled && rdb != nil {
							if jsonBytes, err := json.Marshal(newEntry); err == nil {
								rdb.Set(context.Background(), "wg:geo:"+ipStr, jsonBytes, 24*time.Hour)
							}
						}
					} else {
						// API 失败，如果有本地即使不完整的数据，也回退使用本地
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

		if lat != 0 || lon != 0 {
			data = append(data, PeerGeo{
				PublicKey: p.PublicKey,
				Alias:     p.Alias,
				Endpoint:  p.Endpoint,
				IsOnline:  p.IsOnline,
				Lat:       lat,
				Lon:       lon,
				City:      city,
				Country:   country,
				Source:    source,
			})
		}
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
