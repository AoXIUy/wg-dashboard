package ipapi

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoLite2Provider 使用 GeoLite2 数据库提供 IP 信息查询
type GeoLite2Provider struct {
	cityReader *geoip2.Reader
	asnReader  *geoip2.Reader
}

// NewGeoLite2Provider 创建一个新的 GeoLite2Provider
// cityPath 和 asnPath 可以为空，此时对应的功能将被禁用
func NewGeoLite2Provider(cityPath, asnPath string) (*GeoLite2Provider, error) {
	provider := &GeoLite2Provider{}

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
func (p *GeoLite2Provider) GetInfo(ip net.IP) (*Info, error) {
	if ip == nil {
		return nil, fmt.Errorf("IP 地址为空")
	}

	info := &Info{}

	// 查询城市信息
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
		}
		// 忽略查询错误，可能是私有 IP 或数据库中没有此 IP
	}

	// 查询 ASN 信息
	if p.asnReader != nil {
		record, err := p.asnReader.ASN(ip)
		if err == nil {
			info.ASN = record.AutonomousSystemOrganization
			info.ASNNumber = record.AutonomousSystemNumber
		}
		// 忽略查询错误
	}

	return info, nil
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
