package main

import (
	"context"
	"math"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type PingResponse struct {
	Address         string  `json:"address"`
	IsAlive         bool    `json:"is_alive"`
	MinRtt          float64 `json:"min_rtt"`
	AvgRtt          float64 `json:"avg_rtt"`
	MaxRtt          float64 `json:"max_rtt"`
	Jitter          float64 `json:"jitter"`
	PacketsSent     int     `json:"packets_sent"`
	PacketsReceived int     `json:"packets_received"`
	PacketLoss      float64 `json:"packet_loss"`
	City            string  `json:"city"`
	CountryCode     string  `json:"country_code"`
	Lat             float64 `json:"lat"`
	Lon             float64 `json:"lon"`
}

type TracerouteHop struct {
	Distance    int     `json:"distance"`
	Address     string  `json:"address"`
	MinRtt      float64 `json:"min_rtt"`
	AvgRtt      float64 `json:"avg_rtt"`
	MaxRtt      float64 `json:"max_rtt"`
	City        string  `json:"city"`
	CountryCode string  `json:"country_code"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

type TracerouteResponse struct {
	Target    string          `json:"target"`
	Hops      []TracerouteHop `json:"hops"`
	RawOutput string          `json:"raw_output,omitempty"`
	Error     string          `json:"error,omitempty"`
}

func pingHandler(c *gin.Context) {
	ipStr := c.Query("ipAddress")
	if ipStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ipAddress parameter"})
		return
	}
	countStr := c.Query("count")
	count := 4
	if cnt, err := strconv.Atoi(countStr); err == nil && cnt > 0 && cnt <= 20 {
		count = cnt
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(count+2)*time.Second)
	defer cancel()

	res, err := wgExecutor.Ping(ctx, ipStr, count)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ping failed: " + err.Error()})
		return
	}

	// 补充 GeoIP 信息
	if ipProvider != nil {
		info, err := ipProvider.GetInfo(ip)
		if err == nil && info != nil {
			res.City = info.City
			res.CountryCode = info.CountryCode
			res.Lat = info.Latitude
			res.Lon = info.Longitude
		}
	}

	c.JSON(http.StatusOK, res)
}

func parseLinuxPing(res *PingResponse, out string) {
	rePackets := regexp.MustCompile(`(\d+)\s+packets?\s+transmitted,\s+(\d+)\s+(?:packets?\s+)?received,\s+([\d\.]+)%\s+packet\s+loss`)
	matches := rePackets.FindStringSubmatch(out)
	if len(matches) == 4 {
		res.PacketsSent, _ = strconv.Atoi(matches[1])
		res.PacketsReceived, _ = strconv.Atoi(matches[2])
		res.PacketLoss, _ = strconv.ParseFloat(matches[3], 64)
	}

	reRtt := regexp.MustCompile(`(?:rtt|round-trip)\s+min/avg/max(?:/(?:mdev|stddev))?.*?=\s+([\d\.]+)/([\d\.]+)/([\d\.]+)(?:/([\d\.]+))?`)
	mRtt := reRtt.FindStringSubmatch(out)
	if len(mRtt) >= 4 {
		res.MinRtt, _ = strconv.ParseFloat(mRtt[1], 64)
		res.AvgRtt, _ = strconv.ParseFloat(mRtt[2], 64)
		res.MaxRtt, _ = strconv.ParseFloat(mRtt[3], 64)
		if len(mRtt) == 5 && mRtt[4] != "" {
			res.Jitter, _ = strconv.ParseFloat(mRtt[4], 64)
		} else if res.MaxRtt >= res.MinRtt {
			res.Jitter = math.Round((res.MaxRtt-res.MinRtt)*100) / 100
		}
	}
}

func parseWindowsPing(res *PingResponse, out string) {
	rePackets := regexp.MustCompile(`(?i)Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*\d+\s*\(([\d\.]+)%`)
	if !rePackets.MatchString(out) {
		rePackets = regexp.MustCompile(`已发送\s*=\s*(\d+).*?已接收\s*=\s*(\d+).*?\(([\d\.]+)%`)
	}
	matches := rePackets.FindStringSubmatch(out)
	if len(matches) == 4 {
		res.PacketsSent, _ = strconv.Atoi(matches[1])
		res.PacketsReceived, _ = strconv.Atoi(matches[2])
		res.PacketLoss, _ = strconv.ParseFloat(matches[3], 64)
	}

	reRttMin := regexp.MustCompile(`(?i)(?:Minimum|最短)\s*=\s*(\d+)ms`)
	reRttMax := regexp.MustCompile(`(?i)(?:Maximum|最长)\s*=\s*(\d+)ms`)
	reRttAvg := regexp.MustCompile(`(?i)(?:Average|平均)\s*=\s*(\d+)ms`)

	if m := reRttMin.FindStringSubmatch(out); len(m) == 2 {
		res.MinRtt, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := reRttMax.FindStringSubmatch(out); len(m) == 2 {
		res.MaxRtt, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := reRttAvg.FindStringSubmatch(out); len(m) == 2 {
		res.AvgRtt, _ = strconv.ParseFloat(m[1], 64)
	}
	if res.MaxRtt >= res.MinRtt {
		res.Jitter = math.Round((res.MaxRtt-res.MinRtt)*100) / 100
	}
}

func tracerouteHandler(c *gin.Context) {
	ipStr := c.Query("ipAddress")
	if ipStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing ipAddress parameter"})
		return
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	res, err := wgExecutor.Traceroute(ctx, ipStr, 30)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Traceroute failed: " + err.Error()})
		return
	}

	if ipProvider != nil {
		for i, hop := range res.Hops {
			if hop.Address != "*" && hop.Address != "" {
				parsedIP := net.ParseIP(hop.Address)
				if parsedIP != nil {
					info, err := ipProvider.GetInfo(parsedIP)
					if err == nil && info != nil {
						res.Hops[i].City = info.City
						res.Hops[i].CountryCode = info.CountryCode
						res.Hops[i].Lat = info.Latitude
						res.Hops[i].Lon = info.Longitude
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, res)
}

// reMsToken 匹配独立的 ms 单位 token （如 "1.23ms" 或数字后面紧跟的 "ms"）
var reMsValue = regexp.MustCompile(`^(\d+\.?\d*)ms$`)

// 以下包级预编译正则供 parseWindowsTracert 使用，避免循环内重复编译（性能修复）
var (
	reWindowsLineStart = regexp.MustCompile(`^\d+`)
	reWindowsIP        = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+`)
	reWindowsMs        = regexp.MustCompile(`([<]*\d+)\s*ms`)
)

func parseLinuxTraceroute(res *TracerouteResponse, out string) {
	lines := strings.Split(out, "\n")
	expectedDistance := 1

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "traceroute") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		distance, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		for expectedDistance < distance {
			res.Hops = append(res.Hops, TracerouteHop{
				Distance: expectedDistance,
				Address:  "*",
			})
			expectedDistance++
		}

		hop := TracerouteHop{
			Distance: distance,
		}

		// 全部是 * 的跳点：parts[1] == "*"
		if parts[1] == "*" {
			hop.Address = "*"
		} else {
			hop.Address = parts[1]
			var times []float64
			for _, p := range parts[2:] {
				// 跳过单独的 "ms" token 和 "*"
				if p == "ms" || p == "*" {
					continue
				}
				// 处理 "1.23ms" 格式（ms 紧贴数字）
				if m := reMsValue.FindStringSubmatch(p); len(m) == 2 {
					if t, e := strconv.ParseFloat(m[1], 64); e == nil {
						times = append(times, t)
					}
					continue
				}
				// 处理纯数字（"1.23 ms" 格式，数字与 ms 分离）
				if t, e := strconv.ParseFloat(p, 64); e == nil {
					times = append(times, t)
				}
			}
			if len(times) > 0 {
				min, max, sum := times[0], times[0], 0.0
				for _, t := range times {
					if t < min {
						min = t
					}
					if t > max {
						max = t
					}
					sum += t
				}
				hop.MinRtt = min
				hop.MaxRtt = max
				hop.AvgRtt = sum / float64(len(times))
			}
		}

		res.Hops = append(res.Hops, hop)
		expectedDistance = distance + 1
	}
}

func parseWindowsTracert(res *TracerouteResponse, out string) {
	lines := strings.Split(out, "\n")
	expectedDistance := 1

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 性能修复：使用包级预编译的正则，避免每行重复创建编译器
		if line == "" || !reWindowsLineStart.MatchString(line) {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		distance, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		for expectedDistance < distance {
			res.Hops = append(res.Hops, TracerouteHop{
				Distance: expectedDistance,
				Address:  "*",
			})
			expectedDistance++
		}

		hop := TracerouteHop{Distance: distance}
		var times []float64

		ips := reWindowsIP.FindAllString(line, -1)
		if len(ips) > 0 {
			hop.Address = ips[len(ips)-1]
		} else {
			hop.Address = "*"
		}

		msMatches := reWindowsMs.FindAllStringSubmatch(line, -1)
		for _, m := range msMatches {
			val := strings.TrimPrefix(m[1], "<")
			if t, err := strconv.ParseFloat(val, 64); err == nil {
				if strings.HasPrefix(m[1], "<") && t == 1 {
					t = 0.5
				}
				times = append(times, t)
			}
		}

		if len(times) > 0 {
			min, max, sum := times[0], times[0], 0.0
			for _, t := range times {
				if t < min {
					min = t
				}
				if t > max {
					max = t
				}
				sum += t
			}
			hop.MinRtt = min
			hop.MaxRtt = max
			hop.AvgRtt = sum / float64(len(times))
		}

		res.Hops = append(res.Hops, hop)
		expectedDistance = distance + 1
	}
}
