package ipapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// APIResponse 外部 API 响应结构 (ip-api.com)
type APIResponse struct {
	Status      string  `json:"status"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// GeoLite2Provider 使用 GeoLite2 数据库提供 IP 信息查询
type GeoLite2Provider struct {
	cityReader        *geoip2.Reader
	asnReader         *geoip2.Reader
	enableAPIFallback bool // 是否启用外部 API 回退
	rateLimiter       *apiRateLimiter
}

// NewGeoLite2Provider 创建一个新的 GeoLite2Provider
// cityPath 和 asnPath 可以为空，此时对应的功能将被禁用
// enableAPIFallback 控制当本地数据不完整时是否回退到外部 API
func NewGeoLite2Provider(cityPath, asnPath string, enableAPIFallback bool) (*GeoLite2Provider, error) {
	provider := &GeoLite2Provider{
		enableAPIFallback: enableAPIFallback,
		rateLimiter:       newAPIRateLimiter(40, time.Minute),
	}

	if cityPath != "" {
		cityReader, err := geoip2.Open(cityPath)
		if err != nil {
			return nil, fmt.Errorf("打开 GeoLite2 City 数据库失败: %w", err)
		}
		provider.cityReader = cityReader
	}

	if asnPath != "" {
		asnReader, err := geoip2.Open(asnPath)
		if err != nil {
			// 如果已经打开了 city reader，需要关闭
			if provider.cityReader != nil {
				provider.cityReader.Close()
			}
			return nil, fmt.Errorf("打开 GeoLite2 ASN 数据库失败: %w", err)
		}
		provider.asnReader = asnReader
	}

	return provider, nil
}

// isPrivateIP 检查是否为私有/特殊 IP 地址（包括回环、链路本地、私有地址段）
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"100.64.0.0/10", // CGNAT
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// GetInfo 实现 Provider 接口
// 优先使用本地数据库，如果数据不完整且启用了 API 回退，则使用外部 API
func (p *GeoLite2Provider) GetInfo(ip net.IP) (*Info, error) {
	if ip == nil {
		return nil, fmt.Errorf("IP 地址为空")
	}

	// FIX-低危6: 私有/特殊 IP 提前短路，避免无意义的查询和 API 调用
	if isPrivateIP(ip) {
		return &Info{Source: "private"}, nil
	}

	info := &Info{}
	localSuccess := false

	// 1. 尝试本地 GeoIP2 数据库
	if p.cityReader != nil {
		record, err := p.cityReader.City(ip)
		if err == nil {
			// 优先使用中文城市名，否则使用英文
			if name, ok := record.City.Names["zh-CN"]; ok && name != "" {
				info.City = name
			} else {
				info.City = record.City.Names["en"]
			}
			info.CountryCode = record.Country.IsoCode
			info.Latitude = record.Location.Latitude
			info.Longitude = record.Location.Longitude

			// FIX-低危7: 有 CountryCode 即视为本地成功，不触发完整回退
			// 减少对坐标和城市的强依赖，避免仅有国家级数据时过度调用外部 API
			if info.CountryCode != "" {
				localSuccess = true
				info.Source = "local"
			}
		}
	}

	// 查询 ASN 信息（无论本地查询是否成功都尝试）
	if p.asnReader != nil {
		record, err := p.asnReader.ASN(ip)
		if err == nil {
			info.ASN = record.AutonomousSystemOrganization
			info.ASNNumber = record.AutonomousSystemNumber
		}
	}

	// 2. 如果本地数据不完整且启用了 API 回退，尝试外部 API
	if !localSuccess && p.enableAPIFallback {
		apiLat, apiLon, apiCity, apiCountry, err := fetchFromAPI(ip.String(), p.rateLimiter)
		if err == nil {
			info.Latitude = apiLat
			info.Longitude = apiLon
			info.City = apiCity
			info.CountryCode = apiCountry
			info.Source = "external"
		} else {
			// API 调用失败，使用本地不完整数据作为回退
			if info.CountryCode != "" || info.City != "" {
				info.Source = "local_fallback"
			} else {
				info.Source = "none"
			}
		}
	} else if !localSuccess {
		// 未启用 API 回退，使用本地不完整数据
		if info.CountryCode != "" || info.City != "" {
			info.Source = "local_fallback"
		} else {
			info.Source = "none"
		}
	}

	return info, nil
}

// ================= GeoIP 外部 API 限速器 =================
// ip-api.com 免费版限制：45 次/分钟。此处设置保守上限 40 次/分钟。
// 注意：ip-api.com 免费版仅支持 HTTP，HTTPS 为付费专业版功能。
// FIX-中危3: 将限速器封装为结构体，消除全局状态，便于单元测试

// apiRateLimiter 封装了速率限制状态，支持实例级控制
type apiRateLimiter struct {
	mu          sync.Mutex
	limit       int64         // 每个窗口最大调用次数
	window      time.Duration // 窗口时长
	callCount   int64         // 当前窗口内已调用次数（受 mu 保护，而非原子操作）
	windowStart time.Time     // 当前窗口开始时间
	nowFn       func() time.Time // 可注入的时间函数，便于测试
}

// newAPIRateLimiter 创建一个新的限速器
func newAPIRateLimiter(limit int64, window time.Duration) *apiRateLimiter {
	return &apiRateLimiter{
		limit:       limit,
		window:      window,
		windowStart: time.Now(),
		nowFn:       time.Now,
	}
}

// allow 检查是否允许本次外部 API 调用
func (r *apiRateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowFn()
	if now.Sub(r.windowStart) >= r.window {
		// 重置窗口
		r.windowStart = now
		r.callCount = 0
	}
	if r.callCount >= r.limit {
		return false
	}
	r.callCount++
	return true
}

// FIX-中危4: 包级复用 HTTP 客户端，避免每次调用创建新实例耗尽连接池
var apiHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
}

// fetchFromAPI 从外部 API 获取地理位置信息
// 注意：ip-api.com 免费版不支持 HTTPS，此处使用 HTTP。
// 如需 HTTPS，请升级为付费版或更换支持免费 HTTPS 的服务商。
func fetchFromAPI(ip string, limiter *apiRateLimiter) (lat, lon float64, city, countryCode string, err error) {
	if !limiter.allow() {
		return 0, 0, "", "", fmt.Errorf("外部 GeoIP API 调用频率已达上限，本次跳过")
	}

	// FIX-中危5: ip-api.com 免费版不支持 HTTPS，改回 HTTP 避免静默失败
	url := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN&fields=status,countryCode,city,lat,lon", ip)

	resp, err := apiHTTPClient.Get(url)
	if err != nil {
		return 0, 0, "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, "", "", fmt.Errorf("API 请求失败，状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, "", "", err
	}

	var result APIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, 0, "", "", err
	}

	if result.Status != "success" {
		return 0, 0, "", "", fmt.Errorf("API 返回错误状态")
	}

	return result.Lat, result.Lon, result.City, result.CountryCode, nil
}

// Close 实现 Provider 接口，关闭所有数据库文件句柄
// FIX-高危2: 使用兼容 Go 1.13+ 的错误组合方式，替代 fmt.Errorf("%w; %w") 多包装
func (p *GeoLite2Provider) Close() error {
	var errs []error
	if p.cityReader != nil {
		if closeErr := p.cityReader.Close(); closeErr != nil {
			errs = append(errs, closeErr)
		}
	}
	if p.asnReader != nil {
		if closeErr := p.asnReader.Close(); closeErr != nil {
			errs = append(errs, closeErr)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return fmt.Errorf("关闭 GeoIP2 读取器时发生多个错误: %v; %v", errs[0], errs[1])
}
