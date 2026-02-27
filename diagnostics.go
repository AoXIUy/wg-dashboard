package main

import (
	"context"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
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
	if c, err := strconv.Atoi(countStr); err == nil && c > 0 && c <= 20 {
		count = c
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid IP address"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(count+2)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", strconv.Itoa(count), ipStr)
	} else {
		// 检测 IPv6，Linux 需要 ping -6 才能正确 ping IPv6 地址
		if ip.To4() == nil {
			cmd = exec.CommandContext(ctx, "ping", "-6", "-c", strconv.Itoa(count), "-W", "1", ipStr)
		} else {
			cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", "1", ipStr)
		}
	}

	out, _ := cmd.CombinedOutput()
	outStr := string(out)

	res := PingResponse{
		Address: ipStr,
	}

	if runtime.GOOS == "windows" {
		parseWindowsPing(&res, outStr)
	} else {
		parseLinuxPing(&res, outStr)
	}

	if res.PacketsReceived > 0 {
		res.IsAlive = true
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

	reRtt := regexp.MustCompile(`(?:rtt|round-trip)\s+min/avg/max.*?=\s+([\d\.]+)/([\d\.]+)/([\d\.]+)`)
	mRtt := reRtt.FindStringSubmatch(out)
	if len(mRtt) == 4 {
		res.MinRtt, _ = strconv.ParseFloat(mRtt[1], 64)
		res.AvgRtt, _ = strconv.ParseFloat(mRtt[2], 64)
		res.MaxRtt, _ = strconv.ParseFloat(mRtt[3], 64)
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	var outStr string

	res := TracerouteResponse{
		Target: ipStr,
		Hops:   make([]TracerouteHop, 0),
	}

	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", "30", "-w", "1000", ipStr)
		out, _ := cmd.CombinedOutput()
		outStr = string(out)
		parseWindowsTracert(&res, outStr)
	} else {
		// 使用 nexttrace 进行路由追踪
		cmd = exec.CommandContext(ctx, "/usr/bin/nexttrace", ipStr)
		out, _ := cmd.CombinedOutput()
		outStr = string(out)

		res.RawOutput = outStr
		parseNextTraceLinux(&res, outStr)
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

func parseNextTraceLinux(res *TracerouteResponse, out string) {
	lines := strings.Split(out, "\n")
	var currentHop *TracerouteHop
	expectedDistance := 1

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "NextTrace") || strings.HasPrefix(trimmedLine, "[NextTrace") || strings.HasPrefix(trimmedLine, "IP Geo") || strings.HasPrefix(trimmedLine, "traceroute") || strings.HasPrefix(trimmedLine, "MapTrace") {
			continue
		}

		parts := strings.Fields(trimmedLine)
		if len(parts) == 0 {
			continue
		}

		// 如果行首是数字，说明这是一跳的开头
		distance, err := strconv.Atoi(parts[0])
		if err == nil {
			if currentHop != nil {
				res.Hops = append(res.Hops, *currentHop)
			}

			// 补齐中间可能缺失的跳点 (全*超时节点)
			for expectedDistance < distance {
				res.Hops = append(res.Hops, TracerouteHop{
					Distance: expectedDistance,
					Address:  "*",
				})
				expectedDistance++
			}

			currentHop = &TracerouteHop{
				Distance: distance,
				Address:  parts[1],
			}
			expectedDistance = distance + 1
		} else if currentHop != nil && strings.Contains(line, "ms") {
			// 这很可能是刚才那一跳的延迟时间行: "  0.94 ms / 0.70 ms / 1.30 ms"
			var times []float64
			for _, p := range parts {
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
				currentHop.MinRtt = min
				currentHop.MaxRtt = max
				currentHop.AvgRtt = sum / float64(len(times))
			}
		}
	}
	// 保存最后一跳记录
	if currentHop != nil {
		res.Hops = append(res.Hops, *currentHop)
	}
}

func parseWindowsTracert(res *TracerouteResponse, out string) {
	lines := strings.Split(out, "\n")
	expectedDistance := 1

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !regexp.MustCompile(`^\d+`).MatchString(line) {
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

		ipRegex := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+`)
		ips := ipRegex.FindAllString(line, -1)
		if len(ips) > 0 {
			hop.Address = ips[len(ips)-1]
		} else {
			hop.Address = "*"
		}

		msRegex := regexp.MustCompile(`([<]*\d+)\s*ms`)
		msMatches := msRegex.FindAllStringSubmatch(line, -1)
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
