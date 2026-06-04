package ipapi

import (
	"fmt"
	"net"
	"strings"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// 中国省级行政区省会坐标表（用于 IPv6 无法从 xdb 获得精确坐标时的回退）
var provinceCoords = map[string][2]float64{
	"北京市":   {39.9042, 116.4074},
	"天津市":   {39.3434, 117.3616},
	"上海市":   {31.2304, 121.4737},
	"重庆市":   {29.5630, 106.5516},
	"河北省":   {38.0428, 114.5149},
	"山西省":   {37.8706, 112.5489},
	"辽宁省":   {41.8057, 123.4315},
	"吉林省":   {43.8868, 125.3245},
	"黑龙江省":  {45.7420, 126.6423},
	"江苏省":   {32.0603, 118.7969},
	"浙江省":   {30.2741, 120.1551},
	"安徽省":   {31.8612, 117.2272},
	"福建省":   {26.0745, 119.2965},
	"江西省":   {28.6765, 115.9095},
	"山东省":   {36.6512, 117.1201},
	"河南省":   {34.7657, 113.7534},
	"湖北省":   {30.5928, 114.3055},
	"湖南省":   {28.1127, 112.9823},
	"广东省":   {23.1291, 113.2644},
	"海南省":   {20.0442, 110.1999},
	"四川省":   {30.6598, 104.0633},
	"贵州省":   {26.5982, 106.7072},
	"云南省":   {25.0456, 102.7097},
	"陕西省":   {34.2655, 108.9541},
	"甘肃省":   {36.0611, 103.8343},
	"青海省":   {36.6171, 101.7782},
	"内蒙古自治区": {40.8175, 111.7654},
	"广西壮族自治区": {22.8150, 108.3275},
	"西藏自治区":  {29.6525, 91.1322},
	"宁夏回族自治区": {38.4681, 106.2731},
	"新疆维吾尔自治区": {43.7936, 87.6273},
	"香港特别行政区": {22.3193, 114.1694},
	"澳门特别行政区": {22.1987, 113.5439},
	"台湾省":   {25.0330, 121.5654},
}

// IP2RegionProvider 使用 ip2region v2 xdb 文件提供中国 IP 精准城市查询
type IP2RegionProvider struct {
	searcher *xdb.Searcher
}

// NewIP2RegionProvider 从 xdb 文件路径创建 Provider（全内存模式，< 1µs/查询）
func NewIP2RegionProvider(xdbPath string) (*IP2RegionProvider, error) {
	// 将 xdb 内容整体加载到内存，避免磁盘 I/O
	cBuff, err := xdb.LoadContentFromFile(xdbPath)
	if err != nil {
		return nil, fmt.Errorf("加载 ip2region xdb 失败: %w", err)
	}

	// 从内容解析 Header 并获取 Version
	header, err := xdb.LoadHeaderFromBuff(cBuff)
	if err != nil {
		return nil, fmt.Errorf("解析 xdb Header 失败: %w", err)
	}
	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, fmt.Errorf("解析 xdb Version 失败: %w", err)
	}

	searcher, err := xdb.NewWithBuffer(version, cBuff)
	if err != nil {
		return nil, fmt.Errorf("初始化 ip2region searcher 失败: %w", err)
	}

	return &IP2RegionProvider{searcher: searcher}, nil
}

// GetInfo 实现 Provider 接口，返回 ip2region 查询结果
// ip2region 返回格式：国家|区域|省份|城市|ISP
// 例如：中国|0|广东省|深圳市|电信
func (p *IP2RegionProvider) GetInfo(ip net.IP) (*Info, error) {
	if ip == nil {
		return nil, fmt.Errorf("IP 地址为空")
	}

	// 私有/特殊 IP 提前短路
	if isPrivateIP(ip) {
		return &Info{Source: "private"}, nil
	}

	region, err := p.searcher.Search(ip.String())
	if err != nil {
		return nil, fmt.Errorf("ip2region 查询失败: %w", err)
	}

	return parseIP2RegionResult(region), nil
}

// parseIP2RegionResult 解析 ip2region 返回的 "国家|区域|省份|城市|ISP" 字符串
func parseIP2RegionResult(region string) *Info {
	// region 格式：中国|0|广东省|深圳市|电信
	parts := strings.Split(region, "|")
	info := &Info{Source: "ip2region"}

	// 国家码映射（ip2region 返回中文国家名）
	if len(parts) > 0 {
		switch parts[0] {
		case "中国":
			info.CountryCode = "CN"
		case "美国":
			info.CountryCode = "US"
		case "日本":
			info.CountryCode = "JP"
		case "韩国":
			info.CountryCode = "KR"
		case "德国":
			info.CountryCode = "DE"
		case "英国":
			info.CountryCode = "GB"
		case "法国":
			info.CountryCode = "FR"
		case "俄罗斯":
			info.CountryCode = "RU"
		case "澳大利亚":
			info.CountryCode = "AU"
		case "加拿大":
			info.CountryCode = "CA"
		// 其他国家暂不映射，保持空值让后续 provider 补充
		default:
			if parts[0] != "0" && parts[0] != "" {
				// 保存中文国家名作为城市的补充描述
				info.CountryCode = ""
			}
		}
	}

	// 省份（parts[2]）
	province := ""
	if len(parts) > 2 && parts[2] != "0" && parts[2] != "" {
		province = parts[2]
	}

	// 城市（parts[3]）
	city := ""
	if len(parts) > 3 && parts[3] != "0" && parts[3] != "" {
		city = parts[3]
	}

	// 优先使用城市，无城市则用省份
	if city != "" {
		info.City = city
	} else if province != "" {
		info.City = province
	}

	// ASN/ISP（parts[4]）
	if len(parts) > 4 && parts[4] != "0" && parts[4] != "" {
		info.ASN = parts[4]
	}

	// 坐标：优先用城市匹配，否则用省份推断
	if info.CountryCode == "CN" {
		if coords, ok := provinceCoords[city]; ok {
			info.Latitude = coords[0]
			info.Longitude = coords[1]
		} else if coords, ok := provinceCoords[province]; ok {
			info.Latitude = coords[0]
			info.Longitude = coords[1]
		}
	}

	return info
}

// Close 实现 Provider 接口，释放 searcher 资源
func (p *IP2RegionProvider) Close() error {
	if p.searcher != nil {
		p.searcher.Close()
	}
	return nil
}
