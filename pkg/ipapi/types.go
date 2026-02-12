package ipapi

import "net"

// Info 包含 IP 地址的地理位置和 ASN 信息
type Info struct {
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         string  `json:"asn"`
	ASNNumber   uint    `json:"asn_number"`
}

// Provider 定义了 IP 信息查询的统一接口
type Provider interface {
	// GetInfo 根据 IP 地址获取地理位置和 ASN 信息
	GetInfo(ip net.IP) (*Info, error)
	// Close 关闭 provider 并释放资源
	Close() error
}
