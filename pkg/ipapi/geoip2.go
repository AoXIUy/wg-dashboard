package ipapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	cityReader       *geoip2.Reader
	asnReader        *geoip2.Reader
	enableAPIFallback bool // 是否启用外部 API 回退
}

// NewGeoLite2Provider 创建一个新的 GeoLite2Provider
// cityPath 和 asnPath 可以为空，此时对应的功能将被禁用
// enableAPIFallback 控制当本地数据不完整时是否回退到外部 API
func NewGeoLite2Provider(cityPath, asnPath string, enableAPIFallback bool) (*GeoLite2Provider, error) {
	provider := &GeoLite2Provider{
		enableAPIFallback: enableAPIFallback,
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

// GetInfo 实现 Provider 接口
// 优先使用本地数据库，如果数据不完整且启用了 API 回退，则使用外部 API
func (p *GeoLite2Provider) GetInfo(ip net.IP) (*Info, error) {
	if ip == nil {
		return nil, fmt.Errorf("IP 地址为空")
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

			// 检查本地数据是否完整（需要有坐标和城市信息）
			if info.Latitude != 0 && info.Longitude != 0 && info.City != "" {
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
		apiLat, apiLon, apiCity, apiCountry, err := fetchFromAPI(ip.String())
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

// fetchFromAPI 从外部 API 获取地理位置信息
func fetchFromAPI(ip string) (lat, lon float64, city, countryCode string, err error) {
	// 使用 ip-api.com (免费版，支持中文)
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

// Close 实现 Provider 接口
func (p *GeoLite2Provider) Close() error {
	var err error
	if p.cityReader != nil {
		if closeErr := p.cityReader.Close(); closeErr != nil {
			err = closeErr
		}
	}
	if p.asnReader != nil {
		if closeErr := p.asnReader.Close(); closeErr != nil {
			if err != nil {
				err = fmt.Errorf("%w; %w", err, closeErr)
			} else {
				err = closeErr
			}
		}
	}
	return err
}
