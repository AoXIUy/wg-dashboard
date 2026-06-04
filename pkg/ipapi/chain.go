package ipapi

import (
	"fmt"
	"net"
)

// ChainProvider 按优先级依次尝试多个 Provider
// 策略：以城市信息是否非空作为"命中"判断依据
// - 若当前 Provider 返回城市非空 → 直接返回（胜出）
// - 否则继续尝试下一个，并将已获得的 CountryCode/ASN 合并补充
type ChainProvider struct {
	providers []Provider
}

// NewChainProvider 创建链式 Provider，按传入顺序决定优先级（第一个优先级最高）
func NewChainProvider(providers ...Provider) *ChainProvider {
	return &ChainProvider{providers: providers}
}

// GetInfo 实现 Provider 接口，按链顺序查询，城市非空即返回
func (c *ChainProvider) GetInfo(ip net.IP) (*Info, error) {
	if len(c.providers) == 0 {
		return nil, fmt.Errorf("ChainProvider: 没有可用的 Provider")
	}

	// merged 用于跨 provider 合并部分字段（如 ASN、CountryCode）
	merged := &Info{}

	for _, p := range c.providers {
		info, err := p.GetInfo(ip)
		if err != nil {
			// 单个 provider 失败不中断链，继续尝试后续
			continue
		}

		// 逐字段合并：优先保留已有值，用后续 provider 补充空缺
		if merged.CountryCode == "" && info.CountryCode != "" {
			merged.CountryCode = info.CountryCode
		}
		if merged.ASN == "" && info.ASN != "" {
			merged.ASN = info.ASN
		}
		if merged.ASNNumber == 0 && info.ASNNumber != 0 {
			merged.ASNNumber = info.ASNNumber
		}
		if merged.Latitude == 0 && info.Latitude != 0 {
			merged.Latitude = info.Latitude
		}
		if merged.Longitude == 0 && info.Longitude != 0 {
			merged.Longitude = info.Longitude
		}

		// 城市非空：胜出，合并已有字段后返回
		if info.City != "" {
			merged.City = info.City
			merged.Source = info.Source
			return merged, nil
		}
	}

	// 所有 provider 均无城市数据，返回已合并的部分结果
	if merged.Source == "" {
		if merged.CountryCode != "" {
			merged.Source = "partial"
		} else {
			merged.Source = "none"
		}
	}

	return merged, nil
}

// Close 实现 Provider 接口，关闭链中所有 Provider
func (c *ChainProvider) Close() error {
	var errs []error
	for _, p := range c.providers {
		if err := p.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("ChainProvider 关闭时发生 %d 个错误: %v", len(errs), errs)
}
